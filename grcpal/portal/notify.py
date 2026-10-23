"""Email content. Each builder returns a plain dict; render() turns it into a Message.

Content is escaped by Jinja autoescape in the HTML part. Emails carry only what the recipient
may already see in the portal (their control, their assignment) plus a deep link; evidence
files are never attached.
"""
from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from grcpal.portal.mailer import Message

_env = Environment(loader=FileSystemLoader(str(Path(__file__).parent / "templates" / "email")),
                   autoescape=select_autoescape(["html"]), trim_blocks=False, keep_trailing_newline=True)


def render(content: dict, to: str, org: str, kind: str) -> Message:
    m = {"fields": [], "sections": [], "note": "", "note_by": "", **content}
    text = _env.get_template("message.txt").render(m=m, org=org)
    html = _env.get_template("message.html").render(m=m, org=org)
    return Message(to=to, subject=m["subject"], text=text, html=html, kind=kind)


def _short(a: dict) -> str:
    return a["label"].splitlines()[0][:120]


def assigned(p, a: dict, actor) -> dict:
    return {"subject": f"Evidence request: {_short(a)} (due {a['due']})",
            "title": "You have a new evidence request",
            "intro": f"{actor.name} asked you to provide evidence in GRC-pal.",
            "fields": [("Request", _short(a)), ("Controls", ", ".join(a["controls"])), ("Due", a["due"]),
                       ("Cycle", p.cycle_name(a["cycle"]))],
            "sections": [("Instructions", a["instructions"].splitlines() or ["See the request in GRC-pal."]),
                         ("Evidence we are looking for", p.evidence_wanted(a["controls"]))],
            "button": ("Open the request", p.link(f"/assignments/{a['RowKey']}"))}


def uploaded(p, u: dict, a: dict | None, actor) -> dict:
    where = p.link(f"/assignments/{a['RowKey']}") if a else p.link(f"/controls/{u['controls'][0]}")
    return {"subject": f"Evidence submitted: {u['filename']} for {', '.join(u['controls'])}",
            "title": "New evidence was submitted",
            "intro": f"{actor.name} uploaded {u['filename']}. It is waiting for review.",
            "fields": [("Request", _short(a) if a else "Direct upload on the control"),
                       ("Controls", ", ".join(u["controls"])), ("File", u["filename"]),
                       ("Their note", u["comment"] or "(none)")],
            "button": ("Review or comment", where)}


def commented(p, c: dict, actor) -> dict:
    target = p.link(f"/assignments/{c['assignment']}") if c["assignment"] else p.link(f"/controls/{c['controls'][0]}")
    about = f" on {c['upload_name']}" if c.get("upload_name") else ""
    return {"subject": f"New comment{about} ({', '.join(c['controls'])})",
            "title": f"{actor.name} commented{about}",
            "intro": "A new comment was added to evidence you are involved with.",
            "sections": [("Comment", c["body"].splitlines())],
            "button": ("Reply in GRC-pal", target)}


def reviewed(p, u: dict, actor) -> dict:
    approved = u["status"] == "approved"
    where = p.link(f"/assignments/{u['assignment']}") if u["assignment"] else p.link(f"/controls/{u['controls'][0]}")
    return {"subject": f"Evidence {'approved' if approved else 'returned'}: {u['filename']}",
            "title": "Your evidence was approved" if approved else "Your evidence needs changes",
            "intro": f"{actor.name} reviewed {u['filename']}.",
            "fields": [("Decision", "Approved" if approved else "Returned for changes"),
                       ("Controls", ", ".join(u["controls"]))],
            "sections": [("Reviewer note", (u["review_note"] or "(none)").splitlines())],
            "button": ("Open in GRC-pal", where)}


def reminder(p, ctl: dict, assignments: list[dict], note: str, actor, status: str | None) -> dict:
    current = p.uploads(control=ctl["id"])
    prev = p.previous_cycle()
    last = p.uploads(control=ctl["id"], cycle=prev["RowKey"]) if prev else []
    instructions = [line for a in assignments for line in a["instructions"].splitlines() if line.strip()]
    due = min((a["due"] for a in assignments), default="")
    fields = [("Control", f"{ctl['id']} · {ctl['title']}"), ("Cycle", p.cycle_name(p.active_cycle()["RowKey"]))]
    if due:
        fields.append(("Due", due))
    if status:
        fields.append(("Current status", status))
    sections = [("What this control does", [ctl["description"]]),
                ("Evidence we are looking for", p.evidence_wanted([ctl["id"]]) + instructions),
                ("Submitted this cycle", [f"{u['filename']} · {u['status']} · {u['uploaded_at'][:10]}" for u in current]
                 or ["Nothing submitted yet."])]
    if prev:
        sections.append((f"Last cycle ({prev['name']})",
                         [f"{u['filename']} · {u['status']} · {u['uploaded_at'][:10]}" for u in last]
                         or ["No evidence was uploaded in the portal last cycle."]))
    return {"subject": f"Reminder: evidence for {ctl['id']} {ctl['title']}",
            "title": f"Please review the evidence for {ctl['id']}",
            "intro": "Please check what has been submitted for this control, upload what is missing, "
                     "and leave a comment if something is unclear or not applicable.",
            "fields": fields, "sections": sections, "note": note.strip(), "note_by": actor.name,
            "button": ("Open the control", p.link(f"/controls/{ctl['id']}"))}


def policy_reminder(p, policy: dict, actor) -> dict:
    return {"subject": f"Please read and acknowledge: {policy['title']} v{policy['version']}",
            "title": f"Acknowledge the {policy['title']}",
            "intro": "Please read the current version of this policy and confirm you have read it. It takes a few minutes.",
            "fields": [("Policy", policy["title"]), ("Version", policy["version"]),
                       ("Effective", policy["effective"] or "now")],
            "button": ("Read and acknowledge", p.link(f"/policies/{policy['id']}"))}


def doc_approval(p, kind: str, number: str, title: str, did: str, v: dict, note: str, actor) -> dict:
    """Approval workflow emails: request, reminder, approved, denied, closed (withdrawn, reassigned or approved
    directly). Only the document's number, title and version and a link; never the file or its text."""
    name = f"{number} {title}".strip() + f" v{v['label']}" + (f" ({v['variant']})" if v.get("variant") else "")
    review = p.link(f"/library/{did}/review/{v['RowKey']}")
    fields = [("Document", name), ("Uploaded by", v.get("uploaded_by", "")), ("Change", v.get("change", "") or "-")]
    if kind in ("request", "reminder"):
        intro = (f"{actor.name} asks you to approve this document." if kind == "request" else
                 "This document is still waiting for your approval.")
        return {"subject": f"{'Reminder: ' if kind == 'reminder' else ''}Approval needed: {name}",
                "title": "A document is waiting for your approval",
                "intro": intro + " Please sign in, read it and approve it or send it back with a reason.",
                "fields": fields, "sections": [("Note from the sender", (note or "(none)").splitlines())],
                "button": ("Review and approve", review)}
    if kind == "approved":
        return {"subject": f"Approved: {name}", "title": "Your document was approved",
                "intro": f"{actor.name} approved it. It is now the published version.",
                "fields": fields, "sections": [("Approver note", (note or "(none)").splitlines())],
                "button": ("Open the document", p.link(f"/library/{did}"))}
    if kind == "denied":
        return {"subject": f"Not approved: {name}", "title": "Your document needs changes",
                "intro": f"{actor.name} did not approve it. It is back to draft.",
                "fields": fields, "sections": [("Reason", note.splitlines())],
                "button": ("Open the document", p.link(f"/library/{did}"))}
    return {"subject": f"No longer needed: approval of {name}", "title": "You do not need to approve this document",
            "intro": "The approval request was closed. There is nothing for you to do.",
            "fields": fields, "sections": [("Why", (note or "(none)").splitlines())],
            "button": ("Open GRC-pal", p.link("/work"))}


def config_changed(p, section, changed: list[str], cleared: list[str], endpoints: dict, actor) -> dict:
    """Security notice to every admin when a Configuration section is saved. Field names only; secret values are
    never included. Changed endpoints are shown in full so a redirect of traffic is easy to spot."""
    from grcpal.settings import FIELDS

    labels = [FIELDS[k].label + (" (secret)" if FIELDS[k].secret else "") for k in changed]
    sections = [("Changed", labels)]
    if endpoints:
        sections.append(("Server addresses", [f"{FIELDS[k].label}: {old or '(default)'} -> {new or '(default)'}"
                                              for k, (old, new) in endpoints.items()]))
    if cleared:
        sections.append(("Secrets cleared because the address changed",
                         [FIELDS[k].label for k in cleared] + ["Enter them again if this change was intended."]))
    return {"subject": f"Configuration changed: {section.title}",
            "title": "GRC-pal configuration was changed",
            "intro": f"{actor.name} ({actor.email}) saved the {section.title} settings. If you did not expect this, "
                     "check the audit log and the account that made the change.",
            "fields": [("Section", section.title), ("Changed by", actor.email)],
            "sections": sections,
            "button": ("Review the configuration", p.link(f"/settings/{section.id}"))}
