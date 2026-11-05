#!/usr/bin/env bash
# Write the recovery kit of an existing GRC-pal instance on Azure, for example when deploy.sh was interrupted
# before its "Recovery kit" step or was run without --kit-out.
#
#   ./deploy/azure/kit.sh --name acme --out recovery-kit.json
#
# The kit holds the backup key and the app key: download it, keep it in a password manager away from the
# backups, then delete this copy. The keys pass through environment variables only (never the command line)
# and the file is created readable by you only; an existing file is never overwritten.
set -euo pipefail
NAME="" ; OUT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --name) NAME="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "Unknown option $1 (see --help)"; exit 1 ;;
  esac
done
[[ "$NAME" =~ ^[a-z0-9][a-z0-9-]{1,19}$ ]] || { echo "--name is required (the name used with deploy.sh)"; exit 1; }
[ -n "$OUT" ] || { echo "--out FILE is required"; exit 1; }
[ ! -e "$OUT" ] || { echo "$OUT already exists; choose a new file name"; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
RG="rg-grcpal-$NAME" ; APP="grcpal-$NAME"
FQDN=$(az containerapp show -g "$RG" -n "$APP" --query properties.configuration.ingress.fqdn -o tsv 2>/dev/null) || {
  echo "no container app $APP in $RG"; exit 1; }
GRCPAL_BACKUP_KEY=$(az containerapp secret show -g "$RG" -n "$APP" --secret-name backup-key --query value -o tsv)
GRCPAL_ENCRYPTION_KEY=$(az containerapp secret show -g "$RG" -n "$APP" --secret-name encryption-key --query value -o tsv)
[ -n "$GRCPAL_BACKUP_KEY" ] && [ -n "$GRCPAL_ENCRYPTION_KEY" ] || {
  echo "could not read the keys (you need Contributor on $RG)"; exit 1; }
export GRCPAL_BACKUP_KEY GRCPAL_ENCRYPTION_KEY
python3 -I "$HERE/write_kit.py" "$OUT" "https://$FQDN"
echo "wrote $OUT: download it, keep it in a password manager away from the backups, then delete this copy"
