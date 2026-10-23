#!/usr/bin/env bash
# GRC-pal installer for a VM on your network: Debian 13 (trixie) minimal + Docker + Caddy (HTTPS).
#
#   sudo ./install.sh --hostname grc.internal.example.com --version 0.3.0
#   sudo ./install.sh --hostname grc.internal.example.com --bundle grcpal-0.3.0.grcupdate      # no internet
#   sudo ./install.sh --hostname grc.internal.example.com --version 0.3.0 \
#        --restore grcpal-acme-20261001T020000Z-scheduled.grcbak --kit recovery-kit.json      # rebuild
#
# What it does (safe to run again; it never deletes data):
#   * installs docker.io, caddy, nftables, unattended-upgrades from Debian (security updates install
#     automatically) and nothing else;
#   * Docker does not manage the firewall; GRC-pal runs on the host network bound to 127.0.0.1 only;
#   * firewall: only SSH, HTTP (redirects to HTTPS) and HTTPS are reachable;
#   * all data in /var/lib/grcpal (data, backups, updates, state); settings in /etc/grcpal;
#   * systemd runs the portal, the jobs (collection, tasks, reminders, hourly backup check), the monthly
#     update check and the updater that acts on approvals from the Updates page.
# Details: docs/deploy-vm.md
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="seattlespicybite/grc-pal"
HOSTNAME_ARG="" VERSION="" BUNDLE="" TLS="internal" CERT="" KEY="" RESTORE="" KIT="" SSH_PORT="22"
FORCE=0 FIREWALL=1

die() { echo "install: $*" >&2; exit 1; }
say() { echo "==> $*"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --hostname) HOSTNAME_ARG="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --bundle) BUNDLE="$2"; shift 2 ;;
    --tls) TLS="$2"; shift 2 ;;
    --cert) CERT="$2"; shift 2 ;;
    --key) KEY="$2"; shift 2 ;;
    --restore) RESTORE="$2"; shift 2 ;;
    --kit) KIT="$2"; shift 2 ;;
    --repo) REPO="$2"; shift 2 ;;
    --ssh-port) SSH_PORT="$2"; shift 2 ;;
    --no-firewall) FIREWALL=0; shift ;;
    --force) FORCE=1; shift ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) die "unknown option $1 (see --help)" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "run as root (sudo)"
[[ -n "$HOSTNAME_ARG" ]] || die "--hostname is required (the name people type, e.g. grc.internal.example.com)"
[[ "$HOSTNAME_ARG" =~ ^[A-Za-z0-9.-]{1,253}$ ]] || die "--hostname may only contain letters, digits, dots and hyphens"
[[ -n "$VERSION" || -n "$BUNDLE" ]] || die "give --version X.Y.Z (download) or --bundle FILE.grcupdate (offline)"
[[ -z "$VERSION" || "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "--version must look like 0.3.0"
[[ "$TLS" == "internal" || "$TLS" == "files" ]] || die "--tls is internal or files"
[[ "$TLS" != "files" || ( -f "$CERT" && -f "$KEY" ) ]] || die "--tls files needs --cert FILE and --key FILE"
[[ -z "$RESTORE" || ( -f "$RESTORE" && -f "$KIT" ) ]] || die "--restore needs the backup file and --kit FILE"
[[ "$SSH_PORT" =~ ^[0-9]{1,5}$ ]] || die "--ssh-port must be a number"

# shellcheck disable=SC1091
. /etc/os-release
if [[ "${ID:-}" != "debian" || "${VERSION_ID:-}" != "13" ]]; then
  [[ $FORCE -eq 1 ]] || die "this installer is tested on Debian 13 only (found ${PRETTY_NAME:-unknown}); --force to try anyway"
fi

ROOT=/var/lib/grcpal ETC=/etc/grcpal APP_UID=10001

say "Installing packages from Debian (docker.io, caddy, nftables, unattended-upgrades)"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q --no-install-recommends docker.io caddy nftables unattended-upgrades python3 \
  python3-cryptography ca-certificates curl

say "Automatic security updates for the operating system"
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

say "Docker: no firewall management, journald logs, no privilege escalation in containers"
mkdir -p /etc/docker
cat > /etc/docker/daemon.json <<'EOF'
{
  "iptables": false,
  "ip6tables": false,
  "log-driver": "journald",
  "no-new-privileges": true
}
EOF
systemctl restart docker

say "Folders"
install -d -m 0755 "$ROOT"
install -d -m 0700 -o $APP_UID -g $APP_UID "$ROOT/data" "$ROOT/requests"
install -d -m 0750 -o $APP_UID -g $APP_UID "$ROOT/backups"
install -d -m 0755 "$ROOT/state"
install -d -m 0700 "$ROOT/updates" "$ROOT/rollback"
install -d -m 0755 "$ETC"

if [[ ! -f "$ETC/secrets.env" ]]; then
  say "Creating the app's secrets (/etc/grcpal/secrets.env, readable by root only)"
  umask 077
  python3 - > "$ETC/secrets.env" <<'EOF'
import secrets
print(f"GRCPAL_SECRET={secrets.token_hex(32)}")
print(f"GRCPAL_ENCRYPTION_KEY={secrets.token_hex(32)}")
EOF
  umask 022
fi
chmod 0600 "$ETC/secrets.env"

cat > "$ETC/grcpal.env" <<EOF
# GRC-pal settings for this VM (no secrets here; those are in secrets.env).
GRCPAL_ENV=production
GRCPAL_AUTH_MODE=local
# Caddy is the one proxy in front; only the address it adds to X-Forwarded-For is believed.
GRCPAL_TRUSTED_PROXY_HOPS=1
GRCPAL_PUBLIC_URL=https://$HOSTNAME_ARG
GRCPAL_SQLITE=/data/grcpal.db
GRCPAL_EVIDENCE_DIR=/data/evidence
GRCPAL_BACKUP_DIR=/backups
GRCPAL_BACKUP_DIR_HOST=$ROOT/backups
GRCPAL_UPDATE_STATE=/state
GRCPAL_UPDATE_REQUESTS=/requests
EOF

if [[ -s "$HERE/update-signing.pub" ]]; then
  install -m 0644 "$HERE/update-signing.pub" "$ETC/update-signing.pub"
else
  echo "WARNING: deploy/vm/update-signing.pub is empty, so update files cannot be checked yet (docs/deploy-vm.md)." >&2
fi

say "Updater and the 'grcpal' command"
install -m 0755 "$HERE/grcpal-update" /usr/local/sbin/grcpal-update
cat > /usr/local/bin/grcpal <<'EOF'
#!/bin/sh
# Run a GRC-pal command inside the running portal, e.g.: sudo grcpal create-admin you@example.com
exec /usr/local/sbin/grcpal-update exec "$@"
EOF
chmod 0755 /usr/local/bin/grcpal

if [[ -f "$ROOT/state/image.env" ]]; then
  say "GRC-pal is already installed ($(grep GRCPAL_VERSION "$ROOT/state/image.env")); keeping that version. Use the Updates page to update."
elif [[ -n "$BUNDLE" ]]; then
  say "Loading GRC-pal from $BUNDLE"
  [[ -s "$ETC/update-signing.pub" ]] || die "cannot check $BUNDLE without $ETC/update-signing.pub"
  python3 - "$BUNDLE" "$ETC/update-signing.pub" "$ROOT/updates/install" <<'EOF'
import base64, hashlib, json, re, sys, tarfile
from pathlib import Path
from cryptography.hazmat.primitives import serialization
bundle, keyfile, out = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3])
pems = re.findall(r"-----BEGIN PUBLIC KEY-----.+?-----END PUBLIC KEY-----", keyfile.read_text(), re.S)
with tarfile.open(bundle, "r:") as tar:
    if sorted(tar.getnames()) != ["image.tar", "manifest.json", "manifest.sig"]:
        sys.exit("unexpected contents in the update file")
    data = tar.extractfile("manifest.json").read(1 << 20)
    sig = base64.b64decode(tar.extractfile("manifest.sig").read(4096))
    for pem in pems:
        try:
            serialization.load_pem_public_key(pem.encode()).verify(sig, data)
            break
        except Exception:
            continue
    else:
        sys.exit("the update file is not signed by the GRC-pal release key")
    m = json.loads(data)
    out.mkdir(parents=True, exist_ok=True)
    h = hashlib.sha256()
    with tar.extractfile("image.tar") as src, (out / "image.tar").open("wb") as dst:
        while block := src.read(1 << 20):
            h.update(block)
            dst.write(block)
    if h.hexdigest() != m["image_sha256"]:
        sys.exit("the image does not match its signed checksum")
    (out / "manifest.json").write_bytes(data)
    print(m["version"])
EOF
  docker load -i "$ROOT/updates/install/image.tar"
  IMG_REF=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["image_ref"])' "$ROOT/updates/install/manifest.json")
  IMG_ID=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["image_id"])' "$ROOT/updates/install/manifest.json")
  VERSION=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["version"])' "$ROOT/updates/install/manifest.json")
  [[ "$(docker image inspect -f '{{.Id}}' "$IMG_REF")" == "$IMG_ID" ]] || die "loaded image ID does not match the signed manifest"
  rm -rf "$ROOT/updates/install"
  printf 'GRCPAL_IMAGE=%s\nGRCPAL_VERSION=%s\n' "$IMG_ID" "$VERSION" > "$ROOT/state/image.env"
else
  say "Downloading GRC-pal $VERSION"
  docker pull "ghcr.io/$REPO:$VERSION"
  IMG_ID=$(docker image inspect -f '{{.Id}}' "ghcr.io/$REPO:$VERSION")
  echo "Image $IMG_ID (compare with the release page; verify provenance: gh attestation verify oci://ghcr.io/$REPO:$VERSION --owner ${REPO%%/*})"
  printf 'GRCPAL_IMAGE=%s\nGRCPAL_VERSION=%s\n' "$IMG_ID" "$VERSION" > "$ROOT/state/image.env"
fi
chmod 0644 "$ROOT/state/image.env"

if [[ -n "$RESTORE" ]]; then
  say "Restoring $(basename "$RESTORE")"
  [[ -z "$(ls -A "$ROOT/data")" ]] || die "$ROOT/data is not empty; restore only goes into a new installation"
  install -m 0640 -o $APP_UID -g $APP_UID "$RESTORE" "$ROOT/backups/"
  install -d -m 0700 -o $APP_UID -g $APP_UID "$ROOT/data/keys"
  python3 - "$KIT" "$ROOT/data/keys/backup.key" "$ETC/secrets.env" <<'EOF'
import json, os, re, sys
from pathlib import Path
kit, keyfile, secrets_env = json.loads(Path(sys.argv[1]).read_text()), Path(sys.argv[2]), Path(sys.argv[3])
if kit.get("format") != "grcpal-recovery-kit-1":
    sys.exit("not a GRC-pal recovery kit")
fd = os.open(keyfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w") as f:
    f.write(kit["backup_key"] + "\n")
os.chown(keyfile, 10001, 10001)
if kit.get("settings_key"):  # the app key the backup's saved credentials were encrypted with
    text = secrets_env.read_text()
    text = re.sub(r"(?m)^GRCPAL_ENCRYPTION_KEY=.*$", "GRCPAL_ENCRYPTION_KEY=" + kit["settings_key"], text)
    secrets_env.write_text(text)
EOF
  /usr/local/sbin/grcpal-update run backup restore "/backups/$(basename "$RESTORE")"
fi

say "HTTPS (Caddy) for https://$HOSTNAME_ARG"
if [[ "$TLS" == "files" ]]; then
  install -d -m 0750 -o root -g caddy "$ETC/tls"
  install -m 0640 -o root -g caddy "$CERT" "$ETC/tls/cert.pem"
  install -m 0640 -o root -g caddy "$KEY" "$ETC/tls/key.pem"
  TLS_LINE="tls $ETC/tls/cert.pem $ETC/tls/key.pem"
else
  TLS_LINE="tls internal"
fi
cat > /etc/caddy/Caddyfile <<EOF
# GRC-pal: HTTPS in front of the portal (which listens on 127.0.0.1:8000 only).
$HOSTNAME_ARG {
	$TLS_LINE
	encode zstd gzip
	request_body {
		max_size 60MB
	}
	reverse_proxy 127.0.0.1:8000
}
EOF
systemctl restart caddy

if [[ $FIREWALL -eq 1 ]]; then
  say "Firewall: only SSH ($SSH_PORT), HTTP and HTTPS are reachable"
  cat > /etc/nftables.conf <<EOF
#!/usr/sbin/nft -f
# GRC-pal VM firewall (installed by install.sh). Docker does not manage the firewall here.
flush ruleset
table inet filter {
	chain input {
		type filter hook input priority 0; policy drop;
		iif lo accept
		ct state established,related accept
		ct state invalid drop
		meta l4proto { icmp, ipv6-icmp } accept
		tcp dport { $SSH_PORT, 80, 443 } accept
	}
	chain forward {
		type filter hook forward priority 0; policy drop;
	}
	chain output {
		type filter hook output priority 0; policy accept;
	}
}
EOF
  systemctl enable --now nftables
  nft -f /etc/nftables.conf
fi

if [[ -d /etc/ssh/sshd_config.d ]]; then
  echo "PermitRootLogin no" > /etc/ssh/sshd_config.d/50-grcpal.conf
  systemctl reload ssh 2>/dev/null || true
fi

say "Services and timers"
install -m 0644 "$HERE"/systemd/* /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now grcpal.service grcpal-requests.path grcpal-update-check.timer \
  grcpal-backup.timer grcpal-collect.timer grcpal-tasks.timer grcpal-remind.timer

say "Waiting for GRC-pal to answer"
for _ in $(seq 1 60); do
  if curl -fsS http://127.0.0.1:8000/healthz >/dev/null 2>&1; then
    cat <<EOF

GRC-pal $(grep GRCPAL_VERSION "$ROOT/state/image.env" | cut -d= -f2) is running at https://$HOSTNAME_ARG

Next steps:
  1. First admin (skip after a restore):   sudo grcpal create-admin you@example.com --name "Your Name"
  2. Sign in, open Administration > Backups and download the recovery kit; keep it in a password manager.
  3. Backups go to $ROOT/backups every night; copy that folder to other storage (docs/deploy-vm.md).
EOF
    [[ "$TLS" == "internal" ]] && echo "  4. HTTPS uses Caddy's own certificate authority: distribute /var/lib/caddy/.local/share/caddy/pki/authorities/local/root.crt to staff devices (Intune or GPO), or reinstall with --tls files."
    exit 0
  fi
  sleep 3
done
die "GRC-pal did not answer; see: journalctl -u grcpal -n 100"
