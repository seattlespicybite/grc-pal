"""AI providers behind one interface, so GRC-pal is not tied to one vendor.

  anthropic          Claude through the Messages API (images and PDFs supported)
  openai_compatible  any OpenAI-style /chat/completions endpoint: Ollama, vLLM, LM Studio, Azure OpenAI, OpenAI
  demo               offline, rule-based reviewer for trials and tests; sends nothing anywhere

Adding a provider: subclass Provider, implement complete(), register it in from_settings().
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass

import requests

RETRY = {408, 429, 500, 502, 503, 504, 529}


@dataclass
class Completion:
    text: str
    model: str
    input_tokens: int = 0
    output_tokens: int = 0
    id: str = ""


class ProviderError(RuntimeError):
    pass


class Provider:
    name = "base"
    supports_files = False

    def __init__(self, model: str):
        self.model = model

    def complete(self, system: str, blocks: list[dict], max_tokens: int = 4000) -> Completion:  # pragma: no cover
        raise NotImplementedError

    @staticmethod
    def _post(url: str, headers: dict, body: dict, timeout: int = 180) -> dict:
        for attempt in range(4):
            r = requests.post(url, headers=headers, json=body, timeout=timeout)
            if r.status_code in RETRY and attempt < 3:
                time.sleep(min(float(r.headers.get("retry-after", 2 ** (attempt + 1))), 30))
                continue
            if r.status_code >= 400:
                raise ProviderError(f"HTTP {r.status_code}: {r.text[:300]}")
            return r.json()
        raise ProviderError("provider kept returning errors")


class AnthropicProvider(Provider):
    name = "anthropic"
    supports_files = True

    def __init__(self, model: str, api_key: str, base_url: str = ""):
        super().__init__(model or "claude-sonnet-5-5")
        if not api_key:
            raise ProviderError("The Claude API needs an API key")
        self.api_key, self.base_url = api_key, (base_url or "https://api.anthropic.com").rstrip("/")

    def complete(self, system, blocks, max_tokens=4000):
        data = self._post(f"{self.base_url}/v1/messages",
                          {"x-api-key": self.api_key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
                          {"model": self.model, "max_tokens": max_tokens, "system": system,
                           "messages": [{"role": "user", "content": blocks}]})
        text = "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")
        usage = data.get("usage") or {}
        if data.get("stop_reason") == "refusal":
            raise ProviderError("the model declined to answer")
        return Completion(text, data.get("model", self.model), usage.get("input_tokens", 0),
                          usage.get("output_tokens", 0), data.get("id", ""))


class OpenAICompatibleProvider(Provider):
    name = "openai_compatible"
    supports_files = True   # images; PDFs are summarized as "not sent" notes

    def __init__(self, model: str, api_key: str, base_url: str):
        super().__init__(model)
        if not base_url or not model:
            raise ProviderError("An OpenAI-compatible provider needs the endpoint URL and the model name")
        self.api_key, self.base_url = api_key, base_url.rstrip("/")

    def complete(self, system, blocks, max_tokens=4000):
        content = []
        for b in blocks:
            if b["type"] == "text":
                content.append({"type": "text", "text": b["text"]})
            elif b["type"] == "image":
                src = b["source"]
                content.append({"type": "image_url", "image_url": {"url": f"data:{src['media_type']};base64,{src['data']}"}})
            else:
                content.append({"type": "text", "text": "[A PDF was attached but this provider does not accept PDFs; "
                                                         "it was not sent.]"})
        headers = {"content-type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
            if ".openai.azure.com" in self.base_url:
                headers["api-key"] = self.api_key
        data = self._post(f"{self.base_url}/chat/completions", headers,
                          {"model": self.model, "max_tokens": max_tokens,
                           "messages": [{"role": "system", "content": system}, {"role": "user", "content": content}]})
        choice = (data.get("choices") or [{}])[0]
        usage = data.get("usage") or {}
        return Completion(choice.get("message", {}).get("content") or "", data.get("model", self.model),
                          usage.get("prompt_tokens", 0), usage.get("completion_tokens", 0), data.get("id", ""))


class DemoProvider(Provider):
    """Deterministic rules over the evidence package. Good enough to show the workflow; not an assessment."""
    name = "demo"
    supports_files = False

    def __init__(self):
        super().__init__("grc-pal-demo-rules")

    def complete(self, system, blocks, max_tokens=4000):
        text = "\n".join(b.get("text", "") for b in blocks if b["type"] == "text")
        start, end = text.find("<evidence>"), text.rfind("</evidence>")
        try:
            pkg = json.loads(text[start + len("<evidence>"):end]) if start >= 0 else {}
        except json.JSONDecodeError:
            pkg = {}
        if "Reply with exactly: OK" in text:
            return Completion("OK", self.model, 10, 1)
        if pkg.get("kind") == "audit_summary":
            return Completion(json.dumps(_demo_summary(pkg)), self.model, len(text) // 4, 300)
        return Completion(json.dumps(_demo_review(pkg)), self.model, len(text) // 4, 400)


def _demo_review(pkg: dict) -> dict:
    ev = pkg.get("evidence_status") or []
    uploads = pkg.get("uploads_this_cycle") or []
    approved = [u for u in uploads if u.get("status") == "approved"]
    bad = [e for e in ev if e.get("status") in ("stale", "error", "not_started")]
    findings = [e for e in ev if e.get("status") == "findings"]
    ok = [e for e in ev if e.get("status") == "ok"]
    gaps = [{"title": f"No current evidence from {e['via']}", "severity": "high" if e["status"] != "stale" else "medium",
             "detail": f"{e['artifact']} is {e['status']}.", "requirement": ""} for e in bad]
    gaps += [{"title": f"Open findings in {e['via']}", "severity": "medium",
              "detail": f"{e.get('findings', 0)} findings reported; remediation or an approved exception is needed.",
              "requirement": ""} for e in findings]
    if pkg.get("override"):
        verdict, conf = "partially_effective", "low"
        gaps.append({"title": "Status accepted by admin override", "severity": "medium",
                     "detail": "An auditor will test the justification and the evidence it references.", "requirement": ""})
    elif not ok and not approved:
        verdict, conf = "insufficient_evidence", "medium"
    elif bad:
        verdict, conf = "partially_effective", "medium"
    elif findings:
        verdict, conf = "partially_effective", "medium"
    else:
        verdict, conf = "effective", "medium"
    ctl = pkg.get("control") or {}
    return {
        "verdict": verdict, "confidence": conf,
        "summary": f"Demo reviewer: {len(ok)} automated source(s) current, {len(approved)} approved upload(s), "
                   f"{len(gaps)} gap(s). This is a rule-based demonstration, not an AI assessment.",
        "design_assessment": f"The control describes: {ctl.get('description', '')[:300]}",
        "operating_assessment": "Operating effectiveness is inferred from evidence freshness and review status only.",
        "evidence_reviewed": [{"item": f"{e['artifact']} ({e['via']})", "observation": e["status"]} for e in ev]
        + [{"item": u["filename"], "observation": f"upload {u['status']}"} for u in uploads],
        "gaps": gaps,
        "recommendations": (["Collect or upload current evidence for the sources marked not started or stale."] if bad else [])
        + (["Close or formally accept the open findings."] if findings else [])
        + ["Keep the population and the sample selection for the auditor."],
        "auditor_questions": ["How is the population for this control produced, and how do you know it is complete?"],
        "sample_requests": [f"Full population for {ctl.get('id', 'this control')} for the audit period"],
    }


def _demo_summary(pkg: dict) -> dict:
    results = pkg.get("results") or []
    counts: dict[str, int] = {}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    total = len(results) or 1
    effective = counts.get("effective", 0) / total
    readiness = "ready" if effective > .9 else "nearly_ready" if effective > .6 else "not_ready"
    weak = [r for r in results if r["verdict"] in ("not_effective", "insufficient_evidence")]
    return {"overall_readiness": readiness,
            "summary": f"Demo mock audit of {len(results)} controls: " + ", ".join(f"{v} {k.replace('_', ' ')}"
                                                                                for k, v in sorted(counts.items())),
            "by_group": [{"group": g, "assessment": f"{n} control(s) reviewed, "
                                                     f"{sum(1 for r in results if r.get('group', 'Controls') == g and r['verdict'] == 'effective')} effective"}
                         for g, n in sorted(_group_counts(results).items())],
            "top_risks": [f"{r['control']}: {r['summary'][:140]}" for r in weak[:8]],
            "likely_exceptions": [r["control"] for r in weak],
            "next_steps": ["Fix the controls with insufficient evidence first; they would be exceptions in a Type 2 report.",
                           "Rerun the mock audit after the next collection cycle."]}


def _group_counts(results: list[dict]) -> dict[str, int]:
    out: dict[str, int] = {}
    for r in results:
        out[r.get("group", "Controls")] = out.get(r.get("group", "Controls"), 0) + 1
    return out


def from_settings(settings) -> Provider:
    kind = settings.get("GRCPAL_AI_PROVIDER")
    if kind == "anthropic":
        return AnthropicProvider(settings.get("GRCPAL_AI_MODEL"), settings.secret("GRCPAL_AI_API_KEY"),
                                 settings.get("GRCPAL_AI_BASE_URL"))
    if kind == "openai_compatible":
        return OpenAICompatibleProvider(settings.get("GRCPAL_AI_MODEL"), settings.secret("GRCPAL_AI_API_KEY"),
                                        settings.get("GRCPAL_AI_BASE_URL"))
    if kind == "demo":
        return DemoProvider()
    raise ProviderError("The AI assistant is turned off. An admin can turn it on under Configuration > AI assistant.")
