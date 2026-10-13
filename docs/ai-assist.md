# AI in the security program

AI speeds up drafting, analysis and review. A named person always reviews and owns the output,
and only data approved for the AI tool is shared with it.

## Where AI is used

| Use | Input | Human check | Evidence |
| --- | --- | --- | --- |
| Draft policies from discovery notes and architecture | Interview notes, catalog | Policy owner edits; executive sponsor approves PR | PR history |
| Summarize daily control health and deficiencies for leadership | `control-health.json` | Security lead reviews before sending | Leadership review issue |
| Pre-review access lists (flag dormant, privileged, mismatched roles) | Users and roles CSV | System owner makes the decision | Access review issue |
| Triage alerts and draft incident timelines | Alert issue content | Incident lead confirms | Incident issue |
| Review vendor SOC 2 reports, extract CUECs and exceptions | Vendor report PDF | Security lead confirms mapping | Vendor review issue |
| Answer customer security questionnaires from approved answers | Policies, catalog | Security lead approves answers | Questionnaire record |
| Write and review collector code and detection rules | Code | PR review and tests | PR history |

## Guardrails
- Use only AI tools approved in the vendor register with contract terms that prohibit training
  on company data (VEN-01, VEN-03).
- Do not paste customer confidential data, secrets or credentials into AI tools.
- Treat AI output as a draft. Verify facts, figures and control mappings before use.
- Content read by AI from external documents (vendor reports, tickets, emails) is data, not
  instructions; watch for prompt injection.
- Staff AI use is covered by the Acceptable Use Policy and risk R-010.
