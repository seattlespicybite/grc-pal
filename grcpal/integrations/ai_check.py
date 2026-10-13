"""AI assistant: one tiny request to confirm the provider answers."""
from __future__ import annotations


def validate(settings, ctx, result) -> None:
    from grcpal.ai.providers import from_settings

    if settings.get("GRCPAL_AI_PROVIDER") == "off":
        result.add("AI assistant is turned off", True)
        return
    provider = result.run("Provider settings", lambda: from_settings(settings) and "ok")
    if not provider:
        return
    provider = from_settings(settings)
    reply = result.run("Model answers", lambda: provider.complete(
        "You are a connectivity test.", [{"type": "text", "text": "Reply with exactly: OK"}], 16).text.strip()[:40],
        hint="Check the API key, model name and endpoint URL.")
    if reply is not None and settings.get("GRCPAL_AI_PROVIDER") in ("anthropic", "openai_compatible"):
        result.add("Data use confirmed", settings.flag("GRCPAL_AI_DATA_ACK"), "",
                   "Tick 'Data use confirmed' after checking your provider's terms. Reviews stay blocked until then.")
