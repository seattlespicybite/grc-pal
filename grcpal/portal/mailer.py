"""Outbound email: console (local), SMTP, or Microsoft Graph.

GRCPAL_MAIL_BACKEND = console | smtp | graph | off   (default console)
GRCPAL_MAIL_FROM    = sender address, e.g. grc@example.com

smtp:  GRCPAL_SMTP_HOST, GRCPAL_SMTP_PORT (587), GRCPAL_SMTP_USER, GRCPAL_SMTP_PASSWORD,
       GRCPAL_SMTP_TLS = starttls | ssl | none (starttls)
graph: sends as GRCPAL_MAIL_FROM (a shared mailbox) with the app's managed identity, which needs
       the Graph application permission Mail.Send, scoped to that one mailbox with Exchange
       RBAC for Applications (see docs/deploy-azure.md). No secrets are stored.

Each recipient gets their own message (no exposed recipient lists). Sending happens on a small
background pool so a slow mail server never blocks a page; results are logged and failures
are written to the audit log by the caller's callback.
"""
from __future__ import annotations

import collections
import os
import smtplib
import ssl
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from email.message import EmailMessage
from typing import Callable

from grcpal.portal.observability import event


@dataclass
class Message:
    to: str
    subject: str
    text: str
    html: str = ""
    kind: str = "notice"
    meta: dict = field(default_factory=dict)


class Mailer:
    name = "base"

    def __init__(self, sender: str, sync: bool = False) -> None:
        self.sender = sender
        self.sync = sync
        self._pool = None if sync else ThreadPoolExecutor(max_workers=2, thread_name_prefix="mail")
        self.on_result: Callable[[Message, Exception | None], None] | None = None

    def deliver(self, msg: Message) -> None:  # pragma: no cover - overridden
        raise NotImplementedError

    def _run(self, msg: Message) -> None:
        error = None
        try:
            self.deliver(msg)
            event("mail sent", backend=self.name, to=msg.to, kind=msg.kind)
        except Exception as exc:  # noqa: BLE001 - never crash the app over email
            error = exc
            event("mail failed", 40, backend=self.name, to=msg.to, kind=msg.kind, error=f"{type(exc).__name__}: {exc}")
        if self.on_result:
            try:
                self.on_result(msg, error)
            except Exception:  # noqa: BLE001
                pass

    def send(self, msg: Message) -> Future | None:
        msg.subject = " ".join(msg.subject.split())[:200]  # no header injection, no runaway subjects
        if self._pool is None:
            self._run(msg)
            return None
        return self._pool.submit(self._run, msg)


class ConsoleMailer(Mailer):
    """Logs messages and keeps the last 200 in memory (shown on /dev/outbox in dev mode)."""
    name = "console"

    def __init__(self, sender: str, sync: bool = False) -> None:
        super().__init__(sender, sync)
        self.outbox: collections.deque[Message] = collections.deque(maxlen=200)

    def deliver(self, msg: Message) -> None:
        self.outbox.appendleft(msg)


class NullMailer(Mailer):
    name = "off"

    def deliver(self, msg: Message) -> None:
        return None


class SmtpMailer(Mailer):
    name = "smtp"

    def __init__(self, sender: str, host: str, port: int, user: str = "", password: str = "",
                 tls: str = "starttls", sync: bool = False) -> None:
        super().__init__(sender, sync)
        self.host, self.port, self.user, self.password, self.tls = host, port, user, password, tls

    def deliver(self, msg: Message) -> None:
        em = EmailMessage()
        em["From"], em["To"], em["Subject"] = self.sender, msg.to, msg.subject
        em["Auto-Submitted"] = "auto-generated"
        em.set_content(msg.text)
        if msg.html:
            em.add_alternative(msg.html, subtype="html")
        context = ssl.create_default_context()
        if self.tls == "ssl":
            server = smtplib.SMTP_SSL(self.host, self.port, context=context, timeout=20)
        else:
            server = smtplib.SMTP(self.host, self.port, timeout=20)
        with server:
            if self.tls == "starttls":
                server.starttls(context=context)
            if self.user:
                server.login(self.user, self.password)
            server.send_message(em)


class GraphMailer(Mailer):
    name = "graph"

    def __init__(self, sender: str, sync: bool = False) -> None:
        super().__init__(sender, sync)
        self._credential = None

    def _token(self) -> str:
        if self._credential is None:
            from azure.identity import DefaultAzureCredential

            self._credential = DefaultAzureCredential()
        return self._credential.get_token("https://graph.microsoft.com/.default").token

    def deliver(self, msg: Message) -> None:
        import requests

        body = {"message": {"subject": msg.subject,
                            "body": {"contentType": "HTML" if msg.html else "Text", "content": msg.html or msg.text},
                            "toRecipients": [{"emailAddress": {"address": msg.to}}]},
                "saveToSentItems": False}
        r = requests.post(f"https://graph.microsoft.com/v1.0/users/{self.sender}/sendMail", json=body, timeout=20,
                          headers={"Authorization": f"Bearer {self._token()}"})
        if r.status_code != 202:
            raise RuntimeError(f"Graph sendMail returned {r.status_code}: {r.text[:300]}")


def from_settings(settings, sync: bool | None = None) -> Mailer:
    """Build the mailer from Configuration > Email (saved values, then environment variables)."""
    get = settings.get
    backend = get("GRCPAL_MAIL_BACKEND", "console").lower()
    sender = get("GRCPAL_MAIL_FROM") or "grc-pal@localhost"
    sync = os.getenv("GRCPAL_MAIL_SYNC", "") == "1" if sync is None else sync
    if backend == "smtp":
        host = get("GRCPAL_SMTP_HOST")
        if not host:
            raise RuntimeError("SMTP needs a server name (GRCPAL_SMTP_HOST)")
        return SmtpMailer(sender, host, int(get("GRCPAL_SMTP_PORT") or 587), get("GRCPAL_SMTP_USER"),
                          settings.secret("GRCPAL_SMTP_PASSWORD") if hasattr(settings, "secret") else get("GRCPAL_SMTP_PASSWORD"),
                          get("GRCPAL_SMTP_TLS") or "starttls", sync)
    if backend == "graph":
        if "@" not in sender:
            raise RuntimeError("Microsoft Graph needs the sender mailbox address (GRCPAL_MAIL_FROM)")
        return GraphMailer(sender, sync)
    if backend == "off":
        return NullMailer(sender, sync)
    if backend != "console":
        raise RuntimeError("GRCPAL_MAIL_BACKEND must be console, smtp, graph or off")
    return ConsoleMailer(sender, sync)


def from_env(sync: bool | None = None) -> Mailer:
    from grcpal.settings import Settings

    return from_settings(Settings(), sync)
