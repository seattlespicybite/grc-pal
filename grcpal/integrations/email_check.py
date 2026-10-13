"""Email: send a real test message to the person running the test."""
from __future__ import annotations

from grcpal.portal import mailer


def validate(settings, ctx, result) -> None:
    backend = settings.get("GRCPAL_MAIL_BACKEND")
    if backend == "off":
        result.add("Email is turned off", True, hint="Reminders and notifications will not be sent.")
        return
    m = result.run("Email settings complete", lambda: mailer.from_settings(settings, sync=True) and "ok")
    if not m:
        return
    m = mailer.from_settings(settings, sync=True)
    to = ctx.actor.email if ctx.actor else settings.get("GRCPAL_MAIL_FROM")
    errors = []
    m.on_result = lambda msg, err: errors.append(err) if err else None
    m.send(mailer.Message(to=to, subject="GRC-pal test email", kind="test",
                          text="This is a test from the GRC-pal Configuration page. Email works."))
    result.add(f"Send a test email to {to}", not errors, "sent" if not errors else str(errors[0])[:300],
               "Check the server, port, encryption and sign-in. For Graph, run the Exchange command that lets "
               "the identity send as this mailbox.")
    if backend == "console":
        result.add("Console mode", True, "Not really sent: see Email outbox. Choose SMTP or Graph for production.")
