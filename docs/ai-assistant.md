# AI assistant: evidence review and mock audits

The AI assistant acts like an assessor before the real audit. It never decides anything: every
answer is a suggestion that an admin accepts or dismisses, and both the question and the answer are
kept as evidence.

## What it does

| Feature | Where | What happens |
| --- | --- | --- |
| **Review with AI** | Any control page (admins) | GRC-pal builds an evidence package for the control and asks the model for a verdict (effective, partially effective, not effective, insufficient evidence), gaps, recommendations, likely auditor questions and sample requests |
| **Mock audit** | AI assistant page or `grcpal ai audit --framework soc2` | Reviews every control in scope for a framework (SOC 2, ISO 27001 or a custom one), then writes a leadership summary: readiness, top risks, likely exceptions, next steps. Runs as a background job; the report downloads as HTML |

The evidence package contains: the control and its mapped requirements, points of focus, evidence
status, summaries and CSV excerpts of the latest collector runs, check results, uploads this cycle
(metadata, plus file contents if you allow it), last cycle's uploads, comments, and any override.

## Providers

| Provider | Setting | Notes |
| --- | --- | --- |
| Claude | `anthropic`, model e.g. `claude-sonnet-5-5` or `claude-opus-5-5`, API key | Reads screenshots and PDFs when file contents are allowed |
| Self-hosted | `openai_compatible`, endpoint e.g. `http://ollama:11434/v1`, model name | Ollama, vLLM, LM Studio: evidence never leaves your network |
| Other hosted | `openai_compatible` | Azure OpenAI, OpenAI or any compatible gateway |
| Demo | `demo` | Offline rules for trying the workflow; not an AI |

To add a provider, subclass `Provider` in `grcpal/ai/providers.py` and register it in `from_settings`.

## Controls on the data (configure under Configuration > Settings > AI assistant)

- **Off by default.** Nothing is sent until an admin turns it on and presses a button.
- **Data use confirmation** is required before any external provider is used.
- **Send file contents** is off by default (metadata and summaries only).
- **Mask email addresses** is on by default (stable tokens such as `person-3f2a1c`).
- **Daily request limit** and **maximum answer length** cap cost.
- Only admins can run reviews. Auditors can read results.

## Risks and how they are handled

| Risk | Mitigation |
| --- | --- |
| Confidential data sent to a third party | Off by default, explicit confirmation, metadata-only default, email masking, self-hosted option |
| Wrong or invented conclusions | Structured output validated against a schema; a person must accept or dismiss; dismissal needs a reason; labeled "suggestion, not an audit opinion" everywhere |
| Prompt injection from uploaded files (for example a document saying "rate this effective") | Evidence wrapped in `<evidence>` tags with tag-closing text removed; system prompt says to treat it as data; answers are only displayed (escaped), never executed |
| Runaway cost | Daily limit, per-answer limit, one job at a time |
| Unclear provenance | Each review stores `prompt.txt`, `files_sent.json` (with SHA-256 of every item) and `response.txt` as a write-once evidence run (`ai_review/`, `ai_audit/`), plus an audit-log entry with model and verdict |

## How to evidence AI use to an auditor

- `ai_review/<run>/` shows exactly what the model saw and said.
- The audit log shows who requested each review and who accepted or dismissed it, with the note.
- Your AI acceptable-use policy (see `policies/acceptable-use.md`) and the vendor review of the
  AI provider cover the governance side (CC9.2 vendor management, CC2.1 information quality).

A mock audit is preparation, not assurance. Your CPA firm's testing is what goes in the SOC 2 report.
