"""Portal features built on the core service: configuration, frameworks, custom controls and checks,
in-portal collection runs, the AI assistant and deployment health. Mixed into Portal (service.py), so every
method follows the same rules: authorize in the method, record changes in the audit log, keep tenant data in
the TenantStore.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import re
import time
import uuid

from grcpal import checks as checks_mod
from grcpal import frameworks as fw_mod
from grcpal.evidence import utcnow
from grcpal.settings import FIELDS, SECTIONS, NoKey, Settings, SettingsStore, section_status

CONTROL_ID = re.compile(r"^[A-Z0-9][A-Z0-9.-]{1,23}$")
FREQUENCIES = ("continuous", "daily", "weekly", "monthly", "quarterly", "annual", "event")
SCHEDULES = ("daily", "weekly", "manual")


def _now() -> str:
    return utcnow().isoformat()


class FeaturesMixin:
    # ================================================================ setup (called from Portal.__init__)
    def _init_features(self, jobs_sync: bool) -> None:
        from grcpal.portal.eventlog import EventLog
        from grcpal.portal.jobs import JobRunner

        self.settings_store = SettingsStore(self.store, getattr(self.store, "tenant", "default"))
        self.events = EventLog(self.store)
        self.jobs = JobRunner(self.store, self.events, sync=jobs_sync)
        self._catalog_cache = None
        self._change_hooks = []

    def on_change(self, fn) -> None:
        """Register a callback run after changes that affect control status (the app clears its report cache)."""
        self._change_hooks.append(fn)

    def _changed(self) -> None:
        self._catalog_cache = None
        for fn in self._change_hooks:
            fn()

    # ================================================================ effective catalog
    @property
    def catalog(self):
        """The program catalog from files plus custom controls created in the portal."""
        if self._catalog_cache is None:
            custom = [self._as_control(r) for r in self.custom_controls() if r.get("status", "active") == "active"]
            repo_checks: dict[str, list] = {}
            for chk in self.base_catalog.checks:
                repo_checks.setdefault(chk.get("control"), []).append(chk)
            controls = []
            edits = {r["RowKey"]: r for r in self.store.list("controledits", "c")}
            known = self.frameworks if edits else {}
            for c in self.base_catalog.controls:
                if c["id"] in edits:
                    c = self._apply_edit(c, edits[c["id"]], known)
                extra = [{"artifact": k.get("title") or f"Check {k['RowKey']}", "via": f"check:{k['RowKey']}"}
                         for k in self._ui_checks_for(c["id"])
                         if f"check:{k['RowKey']}" not in {str(e["via"]) for e in c["evidence"]}]
                controls.append({**c, "evidence": c["evidence"] + extra} if extra else c)
            cat = dataclasses.replace(self.base_catalog, controls=controls + custom)
            cat._policies = self.base_catalog.policies
            cat._checks = self.base_catalog.checks
            self._catalog_cache = cat
        return self._catalog_cache

    # ================================================================ control definitions (library owner)
    EDITABLE = ("title", "description", "owner", "owner_emails", "mappings", "extra_evidence")

    @staticmethod
    def _base_fingerprint(c: dict) -> str:
        keys = ("title", "description", "owner", "criteria", "iso27001", "mappings", "evidence")
        return hashlib.sha256(json.dumps({k: c.get(k) for k in keys}, sort_keys=True, default=str).encode()).hexdigest()

    def _apply_edit(self, base: dict, row: dict, known: dict) -> dict:
        """The control as the library owner defined it: their fields on top of the starter catalog."""
        e = row.get("edit") or {}
        c = {**base, "mappings": dict(base.get("mappings") or {})}
        for k in ("title", "description", "owner"):
            if e.get(k) is not None:
                c[k] = e[k]
        if e.get("owner_emails") is not None:
            c["owner_emails"] = list(e["owner_emails"])
        for fid, ids in (e.get("mappings") or {}).items():
            fw = known.get(fid)
            if fw and fw.control_field:
                c[fw.control_field] = list(ids)
            c["mappings"][fid] = list(ids)
        if e.get("extra_evidence"):
            c["evidence"] = list(base["evidence"]) + [{"artifact": a, "via": "upload"} for a in e["extra_evidence"]]
        c["edited"] = {"version": row.get("version", 1), "by": row.get("updated_by", ""), "at": row.get("updated_at", ""),
                       "reason": row.get("reason", ""), "starter_changed": row.get("base_hash") != self._base_fingerprint(base)}
        return c

    def control_definition(self, control_id: str) -> dict:
        """Current definition values for the edit form."""
        c = self.catalog.control(control_id)
        if not c or c.get("custom"):
            raise self._invalid("Unknown control")
        base = self.base_catalog.control(control_id)
        manual = [e["artifact"] for e in c["evidence"] if e.get("via") == "upload"
                  and e not in (base.get("evidence") or [])]
        return {"title": c["title"].strip(), "description": (c.get("description") or "").strip(), "owner": c.get("owner", ""),
                "owner_emails": c.get("owner_emails") or [], "extra_evidence": manual,
                "mappings": {fid: fw_mod.requirements_of(c, fw) for fid, fw in self.frameworks_in_use.items()}}

    def uncovered_by_change(self, control_id: str, new_maps: dict) -> list[str]:
        """In-scope SOC 2 criteria that would be left with no control if this control's mappings change."""
        if "soc2" not in new_maps:
            return []
        cov = self.catalog.coverage()
        out = []
        for crit in self.catalog.in_scope_criteria:
            ctls = cov.get(crit, [])
            if ctls == [control_id] and crit not in new_maps["soc2"]:
                out.append(crit)
        return out

    def save_control_definition(self, actor, control_id: str, form: dict) -> dict:
        """Change a built-in control's owners, wording, evidence wanted and framework mappings.
        Library owner only; a reason is required; every version is kept for auditors."""
        self._library(actor)
        before = self.control_definition(control_id)
        reason = (form.get("reason") or "").strip()
        if len(reason) < 10:
            raise self._invalid("Say why you are changing this control (at least 10 characters); auditors will read it")
        title = (form.get("title") or "").strip()
        if len(title) < 3:
            raise self._invalid("Give the control a title")
        owner = (form.get("owner") or "").strip()
        if owner and owner not in self.base_catalog.roles:
            raise self._invalid(f"Owner role '{owner}' is not in roles.yaml")
        emails = sorted({x.strip().lower() for x in re.split(r"[,;\s]+", form.get("owner_emails", "")) if x.strip()})
        for x in emails:
            if not self._email_ok(x):
                raise self._invalid(f"'{x}' is not a valid email address")
        if not owner and not emails:
            raise self._invalid("A control needs an owner: a role, named people, or both")
        maps = {}
        for fid, fw in self.frameworks_in_use.items():
            ids = list(dict.fromkeys(x.strip() for x in re.split(r"[,\s]+", form.get(f"map_{fid}", "")) if x.strip()))
            unknown = [x for x in ids if x not in fw.requirements]
            if unknown:
                raise self._invalid(f"{fw.name}: unknown requirement(s) {', '.join(unknown[:5])}")
            maps[fid] = ids
        if not any(maps.values()):
            raise self._invalid("Map the control to at least one requirement")
        gaps = self.uncovered_by_change(control_id, maps)
        if gaps and form.get("confirm_uncovered") != "yes":
            raise self._invalid(f"This would leave {', '.join(gaps)} with no control. Map another control there first, "
                                "or tick the box to confirm you accept the gap.")
        after = {"title": title[:200], "description": (form.get("description") or "").strip()[:4000], "owner": owner,
                 "owner_emails": emails, "mappings": maps,
                 "extra_evidence": [x.strip()[:300] for x in (form.get("extra_evidence") or "").splitlines() if x.strip()][:30]}
        if after == before:
            return before
        for x in emails:
            self._ensure_contributor(actor, x)
        current = self.store.get("controledits", "c", control_id) or {}
        version = int(current.get("version", 0)) + 1
        now = _now()
        self.store.upsert("controledits", {"PartitionKey": "c", "RowKey": control_id, "edit": after, "version": version,
                                           "base_hash": self._base_fingerprint(self.base_catalog.control(control_id)),
                                           "updated_by": actor.email, "updated_at": now, "reason": reason[:1000]})
        self._history(actor, control_id, "edit", version, before, after, reason, gaps)
        self._changed()
        return after

    def reset_control_definition(self, actor, control_id: str, reason: str) -> None:
        self._library(actor)
        current = self.store.get("controledits", "c", control_id)
        if not current:
            raise self._invalid("This control already uses the starter definition")
        if len((reason or "").strip()) < 10:
            raise self._invalid("Say why you are resetting this control (at least 10 characters)")
        before = self.control_definition(control_id)
        self.store.delete("controledits", "c", control_id)
        self._changed()
        self._history(actor, control_id, "reset", int(current.get("version", 0)) + 1, before,
                      self.control_definition(control_id), reason.strip(), [])

    def _history(self, actor, control_id: str, action: str, version: int, before: dict, after: dict, reason: str,
                 gaps: list) -> None:
        now = _now()
        changed = sorted(k for k in after if before.get(k) != after.get(k))
        self.store.insert("controlhistory", {"PartitionKey": "h", "RowKey": f"{control_id}~{version:05d}",
                                             "control": control_id, "version": version, "action": action,
                                             "by": actor.email, "at": now, "reason": reason[:1000],
                                             "fields": ", ".join(changed), "before": before, "after": after})
        self.audit(actor, f"control.{action}", control_id, {"controls": [control_id], "version": version,
                                                            "fields": changed, "reason": reason[:300],
                                                            "accepted_gaps": gaps or None})

    def control_definition_history(self, control_id: str | None = None) -> list[dict]:
        rows = self.store.list("controlhistory", "h")
        if control_id:
            rows = [r for r in rows if r["control"] == control_id]
        return sorted(rows, key=lambda r: (r["control"], r["version"]), reverse=bool(control_id))

    @property
    def frameworks(self) -> dict:
        """Every framework GRC-pal knows (built in, files, custom), whether or not this client uses it."""
        return fw_mod.load(self.base_catalog, self.store.list("frameworks", "f"))

    @property
    def frameworks_in_use(self) -> dict:
        """Frameworks switched on for this client (GRCPAL_FRAMEWORKS). Empty setting means SOC 2 only."""
        known = self.frameworks
        chosen = [f for f in self.settings.list("GRCPAL_FRAMEWORKS") if f in known] or ["soc2"]
        return {f: known[f] for f in chosen}

    def program_view(self, requested: str = "") -> str:
        """The framework the portal shows: the only one in use, the one the person picked, or "all"."""
        in_use = self.frameworks_in_use
        if len(in_use) == 1:
            return next(iter(in_use))
        return requested if requested in in_use else "all"

    def set_framework_in_use(self, actor, framework_id: str, on: bool) -> list[str]:
        """Turn a framework on or off for this client. At least one stays on. Recorded in the audit log."""
        self._admin(actor)
        known = self.frameworks
        if framework_id not in known:
            raise self._invalid("Unknown framework")
        current = list(self.frameworks_in_use)
        if on and framework_id not in current:
            new = current + [framework_id]
        elif not on and framework_id in current:
            new = [f for f in current if f != framework_id]
            if not new:
                raise self._invalid("Keep at least one framework turned on")
        else:
            return current
        org = self.settings_store.row("organization").get("values") or {}
        form = {**{k: v for k, v in org.items()}, "GRCPAL_FRAMEWORKS": "\n".join(new)}
        _, errors = self.settings_store.save("organization", form, actor.email)
        if errors:
            raise self._invalid("; ".join(errors))
        self.audit(actor, "framework.on" if on else "framework.off", framework_id, {"in_use": new})
        self.events.info("config", f"Framework {'turned on' if on else 'turned off'}: {known[framework_id].name}",
                         actor=actor.email, framework=framework_id)
        return new

    # ================================================================ settings
    @property
    def settings(self) -> Settings:
        return self.settings_store.load()

    def settings_overview(self) -> list[dict]:
        s = self.settings
        return [{"section": sec, "status": section_status(self.settings_store, s, sec),
                 "row": self.settings_store.row(sec.id)} for sec in SECTIONS.values()]

    def save_settings(self, actor, section_id: str, form: dict) -> list[str]:
        self._admin(actor)
        if section_id not in SECTIONS:
            raise self._invalid("Unknown configuration section")
        try:
            changed, errors = self.settings_store.save(section_id, form, actor.email)
        except NoKey as exc:
            raise self._invalid(str(exc)) from exc
        if errors:
            raise self._invalid("; ".join(errors))
        if changed:
            safe = [k for k in changed if not FIELDS[k].secret]
            secrets = [k for k in changed if FIELDS[k].secret]
            self.audit(actor, "config.save", section_id, {"fields": safe, "secrets_changed": secrets})
            self.events.info("config", f"Configuration saved: {SECTIONS[section_id].title}", actor=actor.email,
                             section=section_id, fields=changed)
            self.apply_settings()
        return changed

    def test_settings(self, actor, section_id: str, form: dict | None = None) -> dict:
        """Run the connection test for a section. With form values, test them before saving
        (blank secret fields fall back to the saved secret)."""
        from grcpal.integrations import TestContext, validate

        self._admin(actor)
        if section_id not in SECTIONS:
            raise self._invalid("Unknown configuration section")
        s = self.settings
        if form:
            values, secrets = {}, {}
            for f in SECTIONS[section_id].fields:
                if f.secret:
                    if (form.get(f.key) or "").strip() and form.get(f.key) != "__clear__":
                        secrets[f.key] = form[f.key].strip()
                elif f.kind == "bool":
                    values[f.key] = "true" if form.get(f.key) in ("true", "on", "1") else "false"
                elif f.key in form:
                    values[f.key] = form.get(f.key, "").strip()
            try:
                s = s.overlay(values, secrets)
            except NoKey as exc:
                raise self._invalid(str(exc)) from exc
        started = time.perf_counter()
        result = validate(section_id, s, TestContext(self, actor))
        result["ms"] = int((time.perf_counter() - started) * 1000)
        if not form:
            self.settings_store.record_test(section_id, result)
        self.audit(actor, "config.test", section_id, {"ok": result["ok"], "summary": result["summary"]})
        (self.events.info if result["ok"] else self.events.warning)(
            "config", f"Connection test {'passed' if result['ok'] else 'failed'}: {SECTIONS[section_id].title}",
            actor=actor.email, section=section_id, summary=result["summary"],
            failed=[c["name"] for c in result["checks"] if not c["ok"]])
        return result

    def apply_settings(self) -> None:
        """Make saved settings take effect without a restart."""
        from grcpal.portal import mailer as mailer_mod

        if getattr(self, "_explicit_mailer", False):
            return
        try:
            new = mailer_mod.from_settings(self.settings)
        except Exception as exc:  # noqa: BLE001
            self.events.error("mail", "Email settings are incomplete; using the console outbox", error=str(exc))
            new = mailer_mod.ConsoleMailer("grc-pal@localhost")
        new.on_result = self._mail_result
        self.mailer = new
        self._changed()

    # ================================================================ frameworks (custom)
    def save_framework(self, actor, fid: str, name: str, version: str, description: str, requirements_text: str) -> dict:
        self._library(actor)
        fid = (fid or "").strip().lower()
        if not fw_mod.ID_RE.match(fid):
            raise self._invalid("Framework ID: 2-40 lowercase letters, digits or hyphens, e.g. hipaa-security")
        builtin = fw_mod.load(self.base_catalog, [])
        if fid in builtin:
            raise self._invalid(f"{fid} is provided by a file; edit that file in your program repository instead")
        reqs = fw_mod.parse_requirements(requirements_text)
        if not reqs:
            raise self._invalid("Add at least one requirement as: ID | title | group")
        if len({r["id"] for r in reqs}) != len(reqs):
            raise self._invalid("Requirement IDs must be unique")
        existing = self.store.get("frameworks", "f", fid)
        row = {"PartitionKey": "f", "RowKey": fid, "name": (name or fid).strip()[:120], "version": (version or "")[:40],
               "description": (description or "")[:1000], "requirements": reqs, "active": True,
               "updated_by": actor.email, "updated_at": _now(),
               "created_by": (existing or {}).get("created_by", actor.email), "created_at": (existing or {}).get("created_at", _now())}
        self.store.upsert("frameworks", row)
        self.audit(actor, "framework.update" if existing else "framework.create", fid, {"requirements": len(reqs)})
        return row

    # ================================================================ custom controls
    def custom_controls(self) -> list[dict]:
        return sorted(self.store.list("customcontrols", "c"), key=lambda r: r["RowKey"])

    def custom_control(self, cid: str) -> dict | None:
        return self.store.get("customcontrols", "c", cid)

    def _as_control(self, r: dict) -> dict:
        mappings = r.get("mappings") or {}
        evidence = list(r.get("evidence") or [])
        evidence += [{"artifact": k.get("title") or f"Check {k.get('id') or k['RowKey']}",
                      "via": f"check:{k.get('id') or k['RowKey']}"}
                     for k in self._ui_checks_for(r["RowKey"]) + [c for c in self.base_catalog.checks
                                                                   if c.get("control") == r["RowKey"]]]
        for name, url in [(x.get("name"), x.get("url")) for x in (r.get("links") or [])]:
            evidence.append({"artifact": f"Reference: {name}", "via": f"link:{url}"})
        return {"id": r["RowKey"], "title": r["title"], "description": r.get("description", ""),
                "criteria": [x for x in mappings.get("soc2", []) if x in self.base_catalog.criteria],
                "iso27001": mappings.get("iso27001", []), "mappings": mappings,
                "owner": r.get("owner") or "custom", "owner_emails": r.get("owner_emails") or [],
                "frequency": r.get("frequency", "annual"), "type": r.get("type", "manual"), "evidence": evidence,
                "links": r.get("links") or [], "custom": True}

    def save_custom_control(self, actor, form: dict, existing_id: str | None = None) -> dict:
        self._library(actor)
        cid = (existing_id or form.get("id") or "").strip().upper()
        if not CONTROL_ID.match(cid):
            raise self._invalid("Control ID: 2-24 capital letters, digits, dots or hyphens, e.g. CUS-01 or HIPAA-164.312")
        current = self.custom_control(cid)
        if not existing_id and (current or self.base_catalog.control(cid)):
            raise self._invalid(f"{cid} already exists")
        title = (form.get("title") or "").strip()
        if len(title) < 3:
            raise self._invalid("Give the control a title")
        freq = form.get("frequency") or "annual"
        if freq not in FREQUENCIES:
            raise self._invalid("Choose a frequency")
        frameworks = self.frameworks_in_use
        mappings: dict[str, list[str]] = {}
        for fid, ids in ((current or {}).get("mappings") or {}).items():
            if fid not in frameworks:  # keep mappings to frameworks that are switched off (not on the form)
                mappings[fid] = ids
        for fid, fw in frameworks.items():
            raw = form.get(f"map_{fid}", "")
            ids = [x.strip() for x in re.split(r"[,\s]+", raw) if x.strip()]
            unknown = [x for x in ids if x not in fw.requirements]
            if unknown:
                raise self._invalid(f"{fw.name}: unknown requirement(s) {', '.join(unknown[:5])}")
            if ids:
                mappings[fid] = ids
        if not any(mappings.get(f) for f in frameworks):
            raise self._invalid("Map the control to at least one requirement of a framework")
        owner = (form.get("owner") or "").strip()
        owner_emails = sorted({e.strip().lower() for e in re.split(r"[,;\s]+", form.get("owner_emails", "")) if e.strip()})
        for e in owner_emails:
            if not self._email_ok(e):
                raise self._invalid(f"'{e}' is not a valid email address")
        if owner and owner not in self.base_catalog.roles:
            raise self._invalid(f"Owner role '{owner}' is not in roles.yaml; leave it empty and list owner emails instead")
        links = []
        for line in (form.get("links") or "").splitlines():
            name, _, url = line.partition("|")
            url = (url or name).strip()
            if url:
                if not url.startswith(("https://", "http://")):
                    raise self._invalid(f"Links must start with https:// ({url[:60]})")
                links.append({"name": (name.strip() if "|" in line else url)[:120], "url": url[:1000]})
        evidence = [{"artifact": a.strip()[:300], "via": "upload"} for a in (form.get("evidence_wanted") or "").splitlines()
                    if a.strip()]
        row = {"PartitionKey": "c", "RowKey": cid, "title": title[:200], "description": (form.get("description") or "")[:4000],
               "owner": owner, "owner_emails": owner_emails, "frequency": freq, "type": "manual", "mappings": mappings,
               "evidence": evidence, "links": links, "status": "active",
               "created_by": (current or {}).get("created_by", actor.email),
               "created_at": (current or {}).get("created_at", _now()), "updated_by": actor.email, "updated_at": _now()}
        self.store.upsert("customcontrols", row)
        for e in owner_emails:
            self._ensure_contributor(actor, e)
        self.audit(actor, "control.update" if current else "control.create", cid,
                   {"controls": [cid], "mappings": mappings, "links": len(links)})
        self._changed()
        return row

    def retire_custom_control(self, actor, cid: str, reason: str) -> None:
        self._library(actor)
        row = self.custom_control(cid)
        if not row:
            raise self._invalid("Custom control not found")
        if len((reason or "").strip()) < 5:
            raise self._invalid("Give a reason (at least 5 characters)")
        self.store.update("customcontrols", "c", cid, {"status": "retired", "updated_by": actor.email, "updated_at": _now()})
        self.audit(actor, "control.retire", cid, {"controls": [cid], "reason": reason[:300]})
        self._changed()

    # ================================================================ checks
    def _ui_checks_for(self, control_id: str) -> list[dict]:
        return [k for k in self.store.list("checks", "k") if k.get("control") == control_id and k.get("active", True)]

    def checks_for(self, control_id: str) -> list[dict]:
        ui = [dict(k, id=k["RowKey"], source="portal") for k in self._ui_checks_for(control_id)]
        repo = [dict(c, source="repository", last_result=self._repo_check_state(c["id"])) for c in self.base_catalog.checks
                if c.get("control") == control_id]
        return ui + repo

    def all_checks(self) -> list[dict]:
        ui = [dict(k, id=k["RowKey"], source="portal") for k in self.store.list("checks", "k") if k.get("active", True)]
        repo = [dict(c, source="repository", last_result=self._repo_check_state(c["id"])) for c in self.base_catalog.checks]
        return ui + repo

    def _repo_check_state(self, check_id: str) -> dict:
        return self.settings_store.state(f"check:{check_id}", {}) or {}

    def check_summaries(self, control_id: str) -> list[dict]:
        out = []
        for k in self.checks_for(control_id):
            last = k.get("last_result") or {}
            out.append({"id": k["id"], "type": k["type"], "title": k.get("title", ""),
                        "target": (k.get("config") or k).get("url") or (k.get("config") or k).get("host") or k.get("run", ""),
                        "last_ok": last.get("ok"), "last_summary": last.get("summary"), "last_at": last.get("at"),
                        "failures": last.get("failures", [])})
        return out

    def save_check(self, actor, control_id: str, form: dict) -> dict:
        self._admin(actor)
        if not self.catalog.control(control_id):
            raise self._invalid("Unknown control")
        kind = form.get("type", "http")
        if kind not in ("http", "tls"):
            raise self._invalid("The portal can create HTTP and TLS checks. Command checks belong in catalog/checks.yaml.")
        check_id = (form.get("id") or "").strip()
        if not checks_mod.ID_RE.match(check_id):
            raise self._invalid("Check ID: 2-48 letters, digits, dots, dashes or underscores")
        if self.store.get("checks", "k", check_id) or any(c["id"] == check_id for c in self.base_catalog.checks):
            raise self._invalid(f"A check named {check_id} already exists")
        schedule = form.get("schedule", "daily")
        if schedule not in SCHEDULES:
            raise self._invalid("Schedule must be daily, weekly or manual")
        cfg: dict = {}
        headers, secret_headers = {}, {}
        if kind == "http":
            url = (form.get("url") or "").strip()
            if not url.startswith(("https://", "http://")):
                raise self._invalid("URL must start with https://")
            method = (form.get("method") or "GET").upper()
            if method not in checks_mod.METHODS:
                raise self._invalid(f"Method must be one of {', '.join(checks_mod.METHODS)}")
            cfg = {"method": method, "url": url[:2000], "body": (form.get("body") or "")[:8000],
                   "expect_status": (form.get("expect_status") or "200-399").strip()[:40],
                   "store_response": form.get("store_response") in ("on", "true", "1"),
                   "timeout": min(int(form.get("timeout") or 15), 60), "assertions": self._parse_assertions(form.get("assertions", ""))}
            for line in (form.get("headers") or "").splitlines():
                name, _, value = line.partition(":")
                if name.strip():
                    headers[name.strip()[:100]] = value.strip()[:2000]
            box = None
            for line in (form.get("secret_headers") or "").splitlines():
                name, _, value = line.partition(":")
                if name.strip() and value.strip():
                    from grcpal.settings import secret_box

                    try:
                        box = box or secret_box()
                    except NoKey as exc:
                        raise self._invalid(str(exc)) from exc
                    secret_headers[name.strip()[:100]] = {"enc": box.seal(value.strip(), f"{self.settings_store.tenant}|check:{check_id}:{name.strip()}")}
        else:
            host = (form.get("host") or "").strip().lower()
            if not re.match(r"^[a-z0-9.-]+$", host):
                raise self._invalid("Enter a host name such as app.example.com")
            cfg = {"host": host, "port": int(form.get("port") or 443), "min_days": int(form.get("min_days") or 21)}
        row = {"PartitionKey": "k", "RowKey": check_id, "control": control_id, "type": kind,
               "title": (form.get("title") or check_id)[:200], "severity": form.get("severity") if form.get("severity") in ("low", "medium", "high") else "medium",
               "schedule": schedule, "config": cfg, "headers": headers, "secrets": secret_headers, "active": True,
               "created_by": actor.email, "created_at": _now(), "last_result": {}}
        self.store.insert("checks", row)
        self.audit(actor, "check.create", check_id, {"controls": [control_id], "type": kind,
                                                    "target": cfg.get("url") or cfg.get("host"),
                                                    "secret_headers": sorted(secret_headers)})
        self._changed()
        return row

    @staticmethod
    def _parse_assertions(text: str) -> list[dict]:
        """One per line: kind | path | op | value, e.g. 'json_path | status.indicator | equals | none'."""
        out = []
        for line in (text or "").splitlines():
            parts = [p.strip() for p in line.split("|")]
            if not parts[0]:
                continue
            if parts[0] not in checks_mod.ASSERTION_KINDS:
                raise ValueError(f"unknown assertion kind {parts[0]}")
            if parts[0] in ("contains", "not_contains", "regex", "status", "max_ms"):
                out.append({"kind": parts[0], "value": parts[-1] if len(parts) > 1 else ""})
            else:
                out.append({"kind": parts[0], "path": parts[1] if len(parts) > 1 else "",
                            "op": parts[2] if len(parts) > 2 else "exists", "value": parts[3] if len(parts) > 3 else ""})
        return out

    def delete_check(self, actor, check_id: str) -> None:
        self._admin(actor)
        row = self.store.get("checks", "k", check_id)
        if not row:
            raise self._invalid("Only checks created in the portal can be removed here")
        self.store.update("checks", "k", check_id, {"active": False})
        self.audit(actor, "check.disable", check_id, {"controls": [row["control"]]})
        self._changed()

    def run_check(self, actor, check_id: str, allow_commands: bool = False) -> dict:
        if not actor.is_admin:
            raise self._forbidden("Only admins can run checks")
        row = self.store.get("checks", "k", check_id)
        repo = next((c for c in self.base_catalog.checks if c["id"] == check_id), None)
        if row is None and repo is None:
            raise self._invalid("Check not found")
        if row is not None:
            chk = {"id": check_id, "control": row["control"], "type": row["type"], "title": row["title"],
                   "severity": row.get("severity", "medium"), **row["config"]}
            headers = dict(row.get("headers") or {})
            if row.get("secrets"):
                from grcpal.settings import secret_box

                box = secret_box()
                for name, sealed in row["secrets"].items():
                    headers[name] = box.open(sealed["enc"], f"{self.settings_store.tenant}|check:{check_id}:{name}")
            secret_names = set(row.get("secrets") or {})
        else:
            chk, headers, secret_names = dict(repo), {k: os.path.expandvars(str(v)) for k, v in (repo.get("headers") or {}).items()}, \
                {k for k, v in (repo.get("headers") or {}).items() if "$" in str(v)}
        if chk["type"] == "http":
            result = checks_mod.run_http(chk, headers, secret_names)
        elif chk["type"] == "tls":
            result = checks_mod.run_tls(chk)
        else:
            if not allow_commands:
                raise self._invalid("Command checks run in the collection job or with 'grcpal checks run', not from the web page")
            result = checks_mod.run_command(chk, allow_commands=True)
        prefix = checks_mod.store_result(self.evidence, chk, result)
        state = {"ok": result.ok, "summary": result.summary, "at": result.at, "failures": result.failures[:20], "run": prefix}
        if row is not None:
            self.store.update("checks", "k", check_id, {"last_result": state})
        else:
            self.settings_store.set_state(f"check:{check_id}", state)
        self.audit(actor, "check.run", check_id, {"controls": [chk["control"]], "ok": result.ok, "run": prefix})
        (self.events.info if result.ok else self.events.warning)(
            "check", f"Check {check_id} {'passed' if result.ok else 'failed'}: {result.summary}", actor=actor.email,
            check=check_id, failures=result.failures[:10])
        self._changed()
        return state

    def run_due_checks(self, actor, allow_commands: bool = False, force: bool = False) -> list[dict]:
        out = []
        weekday = self.today.weekday()
        for chk in self.all_checks():
            sched = chk.get("schedule", "daily")
            if not force and (sched == "manual" or (sched == "weekly" and weekday != 0)):
                continue
            if chk["type"] == "command" and not allow_commands:
                continue
            try:
                out.append({"id": chk["id"], **self.run_check(actor, chk["id"], allow_commands)})
            except Exception as exc:  # noqa: BLE001
                out.append({"id": chk["id"], "ok": False, "summary": f"{type(exc).__name__}: {exc}"})
        return out

    # ================================================================ collection inside the portal
    def inbox_read(self, name: str) -> bytes | None:
        if "/" in name or ".." in name:
            return None
        local = self.evidence.root.parent / "inbox" / name
        if local.exists():
            return local.read_bytes()
        if self.evidence.account_url:
            try:
                from azure.identity import DefaultAzureCredential
                from azure.storage.blob import BlobServiceClient

                svc = BlobServiceClient(self.evidence.account_url, credential=DefaultAzureCredential())
                prefix = f"{self.evidence.namespace}/" if self.evidence.namespace else ""
                return svc.get_container_client("inbox").download_blob(prefix + name).readall()
            except Exception:  # noqa: BLE001
                return None
        return None

    def inbox_exists(self, name: str) -> bool:
        return self.inbox_read(name) is not None

    def run_collection(self, actor, names: list[str] | None = None, clients=None, sessions: dict | None = None) -> dict:
        """Run collectors (and due checks) as a background job with the saved configuration."""
        from grcpal import collectors

        self._admin(actor)
        if self.jobs.running("collect"):
            raise self._invalid("A collection run is already in progress")

        def work(job):
            from grcpal.clients import Clients

            settings = self.settings
            ctx = collectors.Context(clients=clients or Clients(settings), catalog=self.catalog, today=self.today,
                                     settings=settings, inbox=self.inbox_read)
            ctx._sessions.update(sessions or {})
            source_controls = self.catalog.sources("collector")
            todo = [n for n in (names or collectors.NAMES)
                    if collectors.platform_enabled(collectors.get(n), self.catalog, settings)
                    and (not hasattr(collectors.get(n), "enabled") or collectors.get(n).enabled())]
            summary = {"ok": [], "failed": [], "skipped": sorted(set(names or collectors.NAMES) - set(todo))}
            for i, name in enumerate(todo, 1):
                job.progress(i - 1, len(todo), f"Running {name}")
                mod = collectors.get(name)
                if name == "portal_audit":
                    ctx.portal_store = self.store
                run = self.evidence.new_run(name, sorted(source_controls.get(name, [])), {"description": mod.DESCRIPTION})
                try:
                    findings = mod.run(ctx, run) or []
                    run.finish(findings)
                    summary["ok"].append(name)
                    job.log(f"ok {name}: {len(findings)} findings")
                    self.events.info("collector", f"Collector {name} finished with {len(findings)} findings",
                                     actor=actor.email, collector=name, findings=len(findings))
                except Exception as exc:  # noqa: BLE001
                    run.finish([], status="error", error=f"{type(exc).__name__}: {exc}")
                    summary["failed"].append(name)
                    job.log(f"FAILED {name}: {type(exc).__name__}: {str(exc)[:200]}")
                    self.events.error("collector", f"Collector {name} failed", actor=actor.email, collector=name,
                                      error=f"{type(exc).__name__}: {exc}")
            job.progress(len(todo), len(todo), "Running checks")
            checks = self.run_due_checks(actor)
            summary["checks"] = {"ran": len(checks), "failed": sum(1 for c in checks if not c.get("ok"))}
            self.settings_store.set_state("last_collection", {"at": _now(), **summary})
            self._changed()
            return summary

        return self.jobs.submit("collect", "Collect evidence", actor.email, work)

    # ================================================================ AI assistant
    AI_EXTERNAL = ("anthropic", "openai_compatible")

    def ai_status(self) -> dict:
        s = self.settings
        provider = s.get("GRCPAL_AI_PROVIDER")
        ready = provider != "off" and (provider not in self.AI_EXTERNAL or s.flag("GRCPAL_AI_DATA_ACK"))
        usage = self.settings_store.state("ai_usage", {}) or {}
        today = self.today.isoformat()
        return {"provider": provider, "model": s.get("GRCPAL_AI_MODEL") or ("claude-sonnet-5-5" if provider == "anthropic" else provider),
                "ready": ready, "send_files": s.flag("GRCPAL_AI_SEND_FILES"), "redact": s.flag("GRCPAL_AI_REDACT_EMAILS"),
                "used_today": usage.get(today, 0), "daily_limit": s.number("GRCPAL_AI_DAILY_LIMIT")}

    def _ai_guard(self, actor, calls: int = 1):
        if not actor.is_admin:
            raise self._forbidden("Only admins can run AI reviews")
        st = self.ai_status()
        if st["provider"] == "off":
            raise self._invalid("The AI assistant is off. Turn it on under Configuration > AI assistant.")
        if not st["ready"]:
            raise self._invalid("Confirm data use under Configuration > AI assistant before sending evidence to an external provider.")
        if st["used_today"] + calls > st["daily_limit"]:
            raise self._invalid(f"Daily AI request limit reached ({st['daily_limit']}). Raise it in Configuration > AI assistant.")
        return st

    def _ai_count(self, n: int = 1) -> None:
        usage = self.settings_store.state("ai_usage", {}) or {}
        today = self.today.isoformat()
        usage = {today: usage.get(today, 0) + n}
        self.settings_store.set_state("ai_usage", usage)

    def ai_review(self, actor, control_id: str, status: dict | None, audit_id: str = "", provider=None) -> dict:
        from grcpal.ai import review as rv
        from grcpal.ai.providers import from_settings

        self._ai_guard(actor)
        settings = self.settings
        provider = provider or from_settings(settings)
        try:
            package, file_blocks, manifest = rv.build_package(self, control_id, status, settings)
        except rv.AIError as exc:
            raise self._invalid(str(exc)) from exc
        if file_blocks and not provider.supports_files:
            file_blocks = []
        prompt = rv.review_prompt(package, settings.flag("GRCPAL_AI_REDACT_EMAILS"))
        started = time.perf_counter()
        self._ai_count()
        try:
            completion = provider.complete(rv.SYSTEM_REVIEW, file_blocks + [{"type": "text", "text": prompt}],
                                           settings.number("GRCPAL_AI_MAX_TOKENS"))
            result = rv.normalize(rv.parse_json(completion.text))
            error = ""
        except Exception as exc:  # noqa: BLE001
            completion, result, error = None, None, f"{type(exc).__name__}: {exc}"[:500]
        ms = int((time.perf_counter() - started) * 1000)
        run = self.evidence.new_run("ai_review", [control_id], {"provider": provider.name, "model": provider.model,
                                                              "requested_by": actor.email, "audit": audit_id or None})
        run.add_bytes("prompt.txt", (rv.SYSTEM_REVIEW + "\n\n---\n\n" + prompt).encode())
        run.add("files_sent", manifest)
        run.add_bytes("response.txt", (completion.text if completion else error).encode())
        run.finish([], status="ok" if result else "error", error=error or None)
        row = {"PartitionKey": control_id, "RowKey": f"{utcnow():%Y%m%dT%H%M%S}-{uuid.uuid4().hex[:6]}",
               "control": control_id, "audit": audit_id, "provider": provider.name,
               "model": completion.model if completion else provider.model, "requested_by": actor.email, "at": _now(),
               "ms": ms, "input_tokens": completion.input_tokens if completion else 0,
               "output_tokens": completion.output_tokens if completion else 0,
               "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(), "evidence_run": run.prefix,
               "verdict": (result or {}).get("verdict", "error"), "result": result or {}, "error": error,
               "disposition": "pending", "disposition_by": "", "disposition_at": "", "disposition_note": ""}
        self.store.insert("aireviews", row)
        self.audit(actor, "ai.review", control_id, {"controls": [control_id], "verdict": row["verdict"],
                                                    "model": row["model"], "run": run.prefix, "audit": audit_id or None})
        (self.events.info if result else self.events.error)(
            "ai", f"AI review of {control_id}: {row['verdict']}", actor=actor.email, control=control_id,
            provider=provider.name, model=row["model"], ms=ms, input_tokens=row["input_tokens"],
            output_tokens=row["output_tokens"], error=error or None)
        return row

    def ai_reviews(self, control_id: str) -> list[dict]:
        return sorted(self.store.list("aireviews", control_id), key=lambda r: r["RowKey"], reverse=True)

    def ai_review_row(self, control_id: str, review_id: str) -> dict:
        row = self.store.get("aireviews", control_id, review_id)
        if not row:
            raise self._invalid("Review not found")
        return row

    def ai_disposition(self, actor, control_id: str, review_id: str, decision: str, note: str) -> dict:
        self._admin(actor)
        row = self.ai_review_row(control_id, review_id)
        if decision not in ("accepted", "dismissed"):
            raise self._invalid("Decision must be accept or dismiss")
        if row["disposition"] != "pending":
            raise self._invalid(f"This review was already {row['disposition']}")
        if decision == "dismissed" and len((note or "").strip()) < 10:
            raise self._invalid("Say why you dismiss the AI's findings (at least 10 characters)")
        row = self.store.update("aireviews", control_id, review_id, {
            "disposition": decision, "disposition_by": actor.email, "disposition_at": _now(), "disposition_note": (note or "")[:2000]})
        self.audit(actor, f"ai.review.{decision}", control_id, {"controls": [control_id], "review": review_id,
                                                               "note": (note or "")[:300]})
        return row

    def ai_audit_scope(self, framework_id: str) -> list[dict]:
        fw = self.frameworks.get(framework_id)
        if not fw:
            raise self._invalid("Unknown framework")
        out = []
        in_scope = set(self.catalog.in_scope_criteria) if framework_id == "soc2" else None
        for c in self.catalog.controls:
            reqs = fw_mod.requirements_of(c, fw)
            if not reqs or (in_scope is not None and not any(r in in_scope for r in reqs)):
                continue
            out.append({"control": c, "group": fw.requirements.get(reqs[0], {}).get("group") or "Requirements"})
        return out

    def start_ai_audit(self, actor, framework_id: str, status_fn, limit: int = 0, provider=None) -> dict:
        from grcpal.ai import review as rv
        from grcpal.ai.providers import from_settings

        scope = self.ai_audit_scope(framework_id)
        if limit:
            scope = scope[:limit]
        if not scope:
            raise self._invalid("No controls map to this framework yet")
        self._ai_guard(actor, calls=len(scope) + 1)
        if self.jobs.running("ai_audit"):
            raise self._invalid("A mock audit is already running")
        fw = self.frameworks[framework_id]
        audit_id = f"{utcnow():%Y%m%dT%H%M%S}-{uuid.uuid4().hex[:4]}"
        self.store.insert("aiaudits", {"PartitionKey": "a", "RowKey": audit_id, "framework": framework_id,
                                       "framework_name": fw.name, "status": "running", "requested_by": actor.email,
                                       "started_at": _now(), "finished_at": "", "controls": len(scope), "items": [],
                                       "summary": {}, "evidence_run": "", "model": "", "cycle": self.active_cycle()["RowKey"]})
        self.audit(actor, "ai.audit.start", audit_id, {"framework": framework_id, "control_count": len(scope)})

        def work(job):
            prov = provider or from_settings(self.settings)
            items, tokens = [], 0
            for i, entry in enumerate(scope, 1):
                ctl = entry["control"]
                job.progress(i - 1, len(scope) + 1, f"Reviewing {ctl['id']}")
                try:
                    row = self.ai_review(actor, ctl["id"], status_fn(ctl["id"]), audit_id=audit_id, provider=prov)
                    res = row["result"] or {}
                    items.append({"control": ctl["id"], "title": ctl["title"], "group": entry["group"],
                                  "verdict": row["verdict"], "confidence": res.get("confidence", ""),
                                  "summary": res.get("summary", row.get("error", ""))[:600],
                                  "gaps": len(res.get("gaps", [])),
                                  "high_gaps": sum(1 for g in res.get("gaps", []) if g.get("severity") == "high"),
                                  "review": row["RowKey"]})
                    tokens += row["input_tokens"] + row["output_tokens"]
                    job.log(f"{ctl['id']}: {row['verdict']}")
                except Exception as exc:  # noqa: BLE001
                    items.append({"control": ctl["id"], "title": ctl["title"], "group": entry["group"], "verdict": "error",
                                  "confidence": "", "summary": str(exc)[:300], "gaps": 0, "high_gaps": 0, "review": ""})
                    job.log(f"{ctl['id']}: error {str(exc)[:120]}")
                self.store.update("aiaudits", "a", audit_id, {"items": items})
            job.progress(len(scope), len(scope) + 1, "Writing the summary")
            settings = self.settings
            summary, error = {}, ""
            try:
                self._ai_count()
                comp = prov.complete(rv.SYSTEM_SUMMARY, [{"type": "text", "text": rv.summary_prompt(
                    [{k: x[k] for k in ("control", "title", "group", "verdict", "confidence", "summary", "gaps")} for x in items],
                    fw.name, settings.flag("GRCPAL_AI_REDACT_EMAILS"))}], settings.number("GRCPAL_AI_MAX_TOKENS"))
                summary = rv.parse_json(comp.text)
                tokens += comp.input_tokens + comp.output_tokens
            except Exception as exc:  # noqa: BLE001
                error = f"{type(exc).__name__}: {exc}"[:300]
            counts: dict[str, int] = {}
            for x in items:
                counts[x["verdict"]] = counts.get(x["verdict"], 0) + 1
            run = self.evidence.new_run("ai_audit", [x["control"] for x in items],
                                        {"framework": framework_id, "requested_by": actor.email, "model": prov.model})
            run.add("results", items)
            run.add("summary", {"summary": summary, "counts": counts, "tokens": tokens, "error": error})
            run.finish([], status="ok" if not error else "error", error=error or None)
            self.store.update("aiaudits", "a", audit_id, {"status": "done" if not error else "done_with_errors",
                                                          "finished_at": _now(), "summary": {**summary, "counts": counts,
                                                                                             "tokens": tokens, "error": error},
                                                          "evidence_run": run.prefix, "model": prov.model})
            self.audit(actor, "ai.audit.finish", audit_id, {"framework": framework_id, "counts": counts, "run": run.prefix})
            return {"audit": audit_id, "counts": counts}

        job = self.jobs.submit("ai_audit", f"AI mock audit: {fw.name}", actor.email, work, audit=audit_id)
        return {"audit": audit_id, "job": job["RowKey"]}

    def ai_audits(self) -> list[dict]:
        return sorted(self.store.list("aiaudits", "a"), key=lambda r: r["RowKey"], reverse=True)

    def ai_audit(self, audit_id: str) -> dict:
        row = self.store.get("aiaudits", "a", audit_id)
        if not row:
            raise self._invalid("Mock audit not found")
        return row

    # ================================================================ deployment health (setup wizard)
    def deployment_checks(self, request_host: str = "") -> list[dict]:
        from grcpal.portal.auth import auth_mode

        s, out = self.settings, []

        def add(name, ok, detail, hint=""):
            out.append({"name": name, "ok": ok, "detail": detail, "hint": hint})

        prod = os.getenv("GRCPAL_ENV", "").lower() == "production"
        mode = auth_mode()
        add("Sign-in", mode != "dev", f"mode: {mode}",
            "Development sign-in lets anyone act as anyone. On a VM use local accounts (GRCPAL_AUTH_MODE=local, the "
            "default); on Azure, deploy/azure/deploy.sh sets up Easy Auth.")
        if mode == "local":
            https = os.getenv("GRCPAL_PUBLIC_URL", "").startswith("https://")
            add("HTTPS", https, "on" if https else "off",
                "Without HTTPS, passwords cross the network in clear text. Put GRC-pal behind HTTPS (see the VM "
                "guide) and set GRCPAL_PUBLIC_URL to the https:// address.")
        add("Production mode", prod, "GRCPAL_ENV=production" if prod else "not set",
            "Set GRCPAL_ENV=production on shared instances; it blocks development shortcuts.")
        add("Form signing key", bool(os.getenv("GRCPAL_SECRET")), "set" if os.getenv("GRCPAL_SECRET") else "random per restart",
            "Set GRCPAL_SECRET (openssl rand -hex 32) so forms keep working across restarts and replicas.")
        add("Secret encryption key", bool(os.getenv("GRCPAL_ENCRYPTION_KEY")),
            "set" if os.getenv("GRCPAL_ENCRYPTION_KEY") else "local key file (development only)",
            "Set GRCPAL_ENCRYPTION_KEY (openssl rand -hex 32) as a secret. Keep a copy in a password manager: "
            "without it, saved credentials cannot be decrypted.")
        tables = bool(os.getenv("GRCPAL_TABLES_URL"))
        add("Portal data storage", tables, "Azure Table Storage" if tables else "SQLite file",
            "SQLite is fine on one server with a persistent disk. In containers, use Azure Table Storage "
            "(GRCPAL_TABLES_URL) or data is lost on restart.")
        blob = bool(self.evidence.account_url)
        add("Evidence storage", blob, "Azure Blob (write-once)" if blob else f"local folder {self.evidence.root}",
            "Auditors rely on write-once storage. deploy.sh creates a container with time-based retention; lock it "
            "after the first clean week.")
        url = os.getenv("GRCPAL_PUBLIC_URL", "")
        add("Public URL", bool(url) and (not request_host or request_host in url), url or "not set",
            "Set GRCPAL_PUBLIC_URL to the address people use, so email links work.")
        admins = len(self.active_emails("admin"))
        add("Admins", admins >= 2, f"{admins} active admin(s)",
            "Have at least two admins so evidence uploaded by one can be reviewed by the other (segregation of duties).")
        add("Email", s.get("GRCPAL_MAIL_BACKEND") in ("smtp", "graph"), s.get("GRCPAL_MAIL_BACKEND"),
            "Choose SMTP or Microsoft Graph in the Email step so reminders reach people.")
        last = self.settings_store.state("last_collection", {}) or {}
        add("First collection run", bool(last), last.get("at", "never"),
            "Run a collection from the last step once your integrations pass their tests.")
        return out
