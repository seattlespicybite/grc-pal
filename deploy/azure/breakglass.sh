#!/usr/bin/env bash
# Break-glass sign-in for a GRC-pal instance on Azure Container Apps.
#
#   ./deploy/azure/breakglass.sh --name acme set-password --email breakglass@acme.com
#   ./deploy/azure/breakglass.sh --name acme arm [--hours 4]
#   ./deploy/azure/breakglass.sh --name acme disarm
#   ./deploy/azure/breakglass.sh --name acme status
#
# When: sign-in with Microsoft to GRC-pal is broken while Azure and Entra ID work (an expired sign-in secret,
# a wrong app assignment, every GRC-pal admin disabled or locked out). For an Entra ID outage use your Entra
# emergency access accounts instead: GRC-pal also needs Entra ID to read its own storage.
#
# Normally password sign-in does not exist on the internet: Easy Auth sends everyone to Microsoft first.
# arm opens it for a few hours:
#   1. a new revision starts with GRCPAL_AUTH_MODE=local and a closing time (GRCPAL_BREAK_GLASS_UNTIL);
#   2. once it answers /healthz, traffic moves to it;
#   3. only then is Easy Auth turned off.
# The order matters: while Easy Auth is on, the app believes the identity header Azure adds. With Easy Auth off
# and the app still trusting that header, anyone could send it. disarm therefore turns Easy Auth on FIRST.
#
# While armed: only the break-glass account (created with set-password, always with two-step sign-in) can sign
# in; each sign-in is a security event and is emailed to every admin; sign-in closes by itself at the closing
# time (at most 24 hours) even if nobody runs disarm, and update.sh refuses to run until disarm. Arming and
# disarming change the sign-in settings, which triggers the "security change" alert set up by deploy.sh.
# Needs: Azure CLI signed in with Contributor on the container app, curl, python3.
set -euo pipefail

NAME="" ; ACTION="" ; EMAIL="" ; HOURS="4" ; YES=""
while [ $# -gt 0 ]; do
  case "$1" in
    --name) NAME="$2"; shift 2 ;;
    --email) EMAIL="$2"; shift 2 ;;
    --hours) HOURS="$2"; shift 2 ;;
    --yes) YES="1"; shift ;;
    arm|disarm|status|set-password) ACTION="$1"; shift ;;
    -h|--help) sed -n '2,25p' "$0"; exit 0 ;;
    *) echo "Unknown option $1 (see --help)"; exit 1 ;;
  esac
done
[[ "$NAME" =~ ^[a-z0-9][a-z0-9-]{1,19}$ ]] || { echo "--name is required (the instance name used with deploy.sh)"; exit 1; }
[ -n "$ACTION" ] || { echo "Say what to do: set-password, arm, disarm or status (see --help)"; exit 1; }
[[ "$HOURS" =~ ^[0-9]{1,2}$ ]] && [ "$HOURS" -ge 1 ] && [ "$HOURS" -le 24 ] || { echo "--hours must be 1 to 24"; exit 1; }
command -v az >/dev/null || { echo "Install the Azure CLI first: https://aka.ms/azcli"; exit 1; }

RG="rg-grcpal-$NAME"
APP=$(echo "grcpal-$NAME" | cut -c1-32)
step() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
die() { echo "breakglass: $*" >&2; exit 1; }
py() { python3 -c "$@"; }

APP_ID=$(az containerapp show -g "$RG" -n "$APP" --query id -o tsv 2>/dev/null) || die "no container app $APP in $RG"
tag() { az tag list --resource-id "$APP_ID" --query "properties.tags.\"$1\"" -o tsv 2>/dev/null || true; }
set_tags() { az tag update --resource-id "$APP_ID" --operation Merge --tags "$@" -o none; }
mode() { az containerapp show -g "$RG" -n "$APP" --query "properties.template.containers[0].env[?name=='GRCPAL_AUTH_MODE'].value | [0]" -o tsv; }
traffic_rev() {
  az containerapp ingress traffic show -g "$RG" -n "$APP" -o json | py '
import json, sys
rows = json.load(sys.stdin)
named = [r for r in rows if r.get("weight", 0) > 0 and r.get("revisionName")]
print(named[0]["revisionName"] if named else "")'
}
new_revision() {  # new_revision SUFFIX ENV-ARGS...: start a revision (no traffic yet), wait for /healthz
  local suffix="$1"; shift
  local old; old=$(traffic_rev)
  [ -n "$old" ] || old=$(az containerapp show -g "$RG" -n "$APP" --query properties.latestReadyRevisionName -o tsv)
  az containerapp revision set-mode -g "$RG" -n "$APP" --mode multiple -o none 2>/dev/null || true
  az containerapp ingress traffic set -g "$RG" -n "$APP" --revision-weight "$old=100" -o none
  az containerapp update -g "$RG" -n "$APP" --revision-suffix "$suffix" "$@" -o none
  NEW_REV="$APP--$suffix"
  local fqdn; fqdn=$(az containerapp revision show -g "$RG" -n "$APP" --revision "$NEW_REV" --query properties.fqdn -o tsv)
  for _ in $(seq 1 40); do
    if curl -fsS --max-time 10 "https://$fqdn/healthz" >/dev/null 2>&1; then return 0; fi
    sleep 15
  done
  return 1
}

case "$ACTION" in
status)
  echo "sign-in mode:        $(mode)"
  echo "Easy Auth enabled:   $(az containerapp auth show -g "$RG" -n "$APP" --query platform.enabled -o tsv)"
  echo "break-glass until:   $(tag grcpal-breakglass-until)"
  echo "serving revision:    $(traffic_rev)"
  ;;

set-password)
  [[ "$EMAIL" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] || die "--email must be the break-glass account's email address"
  step "Setting the break-glass password and two-step sign-in for $EMAIL"
  echo "You will type the password and a code from your authenticator app; nothing is passed on the command line."
  FQDN=$(az containerapp show -g "$RG" -n "$APP" --query properties.configuration.ingress.fqdn -o tsv)
  curl -fsS --max-time 60 "https://$FQDN/healthz" >/dev/null 2>&1 || true  # wake a replica (minReplicas 0)
  az containerapp exec -g "$RG" -n "$APP" --command "grcpal create-admin ${EMAIL,,} --two-step"
  echo "Keep the password and the authenticator entry together, offline, known only to the people who may use them."
  ;;

arm)
  [ "$(mode)" = "easyauth" ] || die "password sign-in is already open (mode $(mode)); see status, or run disarm"
  if [ -z "$YES" ]; then
    echo "This opens password sign-in to $APP on the internet for $HOURS hour(s), for the break-glass account only."
    read -r -p "Type the instance name ($NAME) to continue: " answer
    [ "$answer" = "$NAME" ] || die "not confirmed; nothing was changed"
  fi
  UNTIL=$(py 'import datetime as d, sys; print((d.datetime.now(d.timezone.utc) + d.timedelta(hours=int(sys.argv[1]))).strftime("%Y-%m-%dT%H:%M:%SZ"))' "$HOURS")
  FROM=$(traffic_rev)
  step "1/3 Starting a revision with password sign-in (closes at $UNTIL)"
  new_revision "bg-$(date +%H%M%S)" --set-env-vars GRCPAL_AUTH_MODE=local "GRCPAL_BREAK_GLASS_UNTIL=$UNTIL" \
    || die "the break-glass revision did not answer /healthz. Nothing is exposed (Easy Auth is still on). Run disarm to put the settings back."
  step "2/3 Moving traffic to it"
  az containerapp ingress traffic set -g "$RG" -n "$APP" --revision-weight "$NEW_REV=100" -o none
  step "3/3 Turning Easy Auth off"
  az containerapp auth update -g "$RG" -n "$APP" --enabled false -o none
  set_tags grcpal-breakglass-until="$UNTIL" grcpal-breakglass-from="$FROM"
  FQDN=$(az containerapp show -g "$RG" -n "$APP" --query properties.configuration.ingress.fqdn -o tsv)
  echo
  echo "Armed until $UNTIL. Sign in at https://$FQDN/login with the break-glass account (password + code)."
  echo "Every admin gets an email at each sign-in. When done: ./deploy/azure/breakglass.sh --name $NAME disarm"
  ;;

disarm)
  step "1/3 Turning Easy Auth on"
  az containerapp auth update -g "$RG" -n "$APP" --enabled true -o none
  if [ "$(mode)" != "easyauth" ]; then
    step "2/3 Starting a revision with Microsoft sign-in again"
    new_revision "bgoff-$(date +%H%M%S)" --set-env-vars GRCPAL_AUTH_MODE=easyauth --remove-env-vars GRCPAL_BREAK_GLASS_UNTIL \
      || die "Easy Auth is back on, so password sign-in is closed, but the restored revision did not answer /healthz. Run disarm again."
    az containerapp ingress traffic set -g "$RG" -n "$APP" --revision-weight "$NEW_REV=100" -o none
  else
    step "2/3 Sign-in mode is already Microsoft (easyauth)"
    NEW_REV=$(traffic_rev)
  fi
  step "3/3 Stopping break-glass revisions"
  for r in $(az containerapp revision list -g "$RG" -n "$APP" --query "[?properties.active].name" -o tsv); do
    case "$r" in *--bg-*) [ "$r" = "$NEW_REV" ] || az containerapp revision deactivate -g "$RG" -n "$APP" --revision "$r" -o none ;; esac
  done
  set_tags grcpal-breakglass-until="" grcpal-breakglass-from=""
  echo
  echo "Disarmed: everyone signs in with Microsoft again. Record why break-glass was used (see docs/deploy-azure.md)."
  ;;
esac
