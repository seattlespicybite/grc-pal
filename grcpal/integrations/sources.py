"""HR feed, public endpoints and documentation links."""
from __future__ import annotations

import socket
from pathlib import Path

from grcpal.checks import safe_request


def validate(settings, ctx, result) -> None:
    path = settings.get("GRCPAL_HR_LEAVERS_CSV")
    if path:
        found = Path(path).exists()
        if not found and ctx.portal is not None and path.startswith("inbox/"):
            found = ctx.portal.inbox_exists(path.split("/", 1)[1])
        result.add("HR leavers export", found, path if found else f"{path} not found yet",
                   "Ask HR to upload the export to the inbox container (columns email,termination_date).")
    for host in settings.list("GRCPAL_TLS_TARGETS"):
        result.run(f"Resolve {host}", lambda h=host: socket.getaddrinfo(h, 443)[0][4][0],
                   "Check the spelling; only public host names are tested.")
    for name, url in settings.doc_links():
        def probe(u=url):
            r = safe_request("HEAD", u, timeout=10)
            if r.status >= 400 and r.status not in (401, 403):
                raise RuntimeError(f"HTTP {r.status}")
            return f"HTTP {r.status}" + (" (sign-in required, which is expected for internal sites)"
                                         if r.status in (401, 403) else "")
        result.run(f"Reach {name}", probe, "Check the link. Internal-only addresses are blocked on purpose.")
