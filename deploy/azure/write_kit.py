"""Write the recovery kit for an Azure instance (used by deploy.sh --kit-out). Standard library only.

The two keys come in through environment variables (never the command line, which other users of the machine
can read): GRCPAL_BACKUP_KEY (base64, as stored in the Container Apps secret) and GRCPAL_ENCRYPTION_KEY.
The file format is the same as `grcpal backup kit` (grcpal/backup.py make_kit), so restore accepts it.
"""
import base64
import datetime as dt
import hashlib
import json
import os
import sys


def key_id(key: bytes, label: bytes) -> str:
    return hashlib.sha256(label + b"\0" + key).hexdigest()[:16]


def kit_text(backup_key_b64: str, settings_key: str, instance: str) -> str:
    key = base64.b64decode(backup_key_b64, validate=True)
    kit = {"format": "grcpal-recovery-kit-1", "instance": instance,
           "created": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
           "backup_key": base64.b64encode(key).decode(), "backup_key_id": key_id(key, b"grcpal-backup-key-id"),
           "settings_key": settings_key or "",
           "settings_key_id": key_id(settings_key.encode(), b"grcpal-settings-key-id") if settings_key else None,
           "readme": ["Keep this file in a password manager or safe, NOT next to the backups.",
                      "backup_key opens .grcbak backup files.",
                      "settings_key is GRCPAL_ENCRYPTION_KEY: it opens the integration credentials saved in the "
                      "portal. Set it on the new machine before starting GRC-pal after a restore.",
                      "Restore: grcpal backup restore FILE.grcbak --kit THIS-FILE"]}
    return json.dumps(kit, indent=2) + "\n"


def main(path: str, instance: str) -> None:
    text = kit_text(os.environ["GRCPAL_BACKUP_KEY"], os.environ.get("GRCPAL_ENCRYPTION_KEY", ""), instance)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)  # never overwrite, readable by you only
    with os.fdopen(fd, "w") as fh:
        fh.write(text)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "")
