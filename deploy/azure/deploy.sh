#!/usr/bin/env bash
# One-command GRC-pal deployment to Azure (one instance per organization).
#
#   ./deploy/azure/deploy.sh --name acme --admins you@acme.com [options]
#
# Options:
#   --name NAME            instance name, also the resource group suffix and GRC-pal tenant ID (required)
#   --admins EMAILS        comma-separated emails that become admins at first sign-in (required)
#   --location REGION      Azure region (default eastus2)
#   --image IMAGE          container image (default: the version already running, else this checkout's
#                          version, e.g. ghcr.io/seattlespicybite/grc-pal:0.3.0). Change versions with
#                          update.sh, which checks the new version before it gets traffic.
#   --restore-from FILE    rebuild a NEW instance from a backup file (.grcbak); needs --kit
#   --kit FILE             recovery kit (backup key and app key) that belongs to that backup
#   --github-repo O/R      your program repository; creates a keyless identity for its collectors
#   --mail-from ADDRESS    shared mailbox that sends notifications through Microsoft Graph
#   --require-assignment   only users assigned to the enterprise app may sign in (defense in depth)
#   --alert-email ADDRESS  email for alerts: missed backups and security-relevant changes (recommended)
#   --what-if              preview the Azure changes without deploying
#
# Needs: Azure CLI (az login), Owner or User Access Administrator on the subscription (role
# assignments), and Application Administrator in Entra ID (app registration). Safe to re-run;
# re-running rotates the sign-in client secret.
set -euo pipefail

NAME="" ; ADMINS="" ; LOCATION="eastus2" ; IMAGE="" ; RESTORE_FROM="" ; KIT=""
GITHUB_REPO="" ; MAIL_FROM="" ; ALERT_EMAIL="" ; REQUIRE_ASSIGNMENT="false" ; WHAT_IF=""
while [ $# -gt 0 ]; do
  case "$1" in
    --name) NAME="$2"; shift 2 ;;
    --admins) ADMINS="$2"; shift 2 ;;
    --location) LOCATION="$2"; shift 2 ;;
    --image) IMAGE="$2"; shift 2 ;;
    --restore-from) RESTORE_FROM="$2"; shift 2 ;;
    --kit) KIT="$2"; shift 2 ;;
    --github-repo) GITHUB_REPO="$2"; shift 2 ;;
    --mail-from) MAIL_FROM="$2"; shift 2 ;;
    --alert-email) ALERT_EMAIL="$2"; shift 2 ;;
    --require-assignment) REQUIRE_ASSIGNMENT="true"; shift ;;
    --what-if) WHAT_IF="1"; shift ;;
    -h|--help) sed -n '2,23p' "$0"; exit 0 ;;
    *) echo "Unknown option $1 (see --help)"; exit 1 ;;
  esac
done
[[ "$NAME" =~ ^[a-z0-9][a-z0-9-]{1,19}$ ]] || { echo "--name must be 2-20 lowercase letters, digits or hyphens"; exit 1; }
[ -n "$ADMINS" ] || { echo "--admins is required (your work email)"; exit 1; }
command -v az >/dev/null || { echo "Install the Azure CLI first: https://aka.ms/azcli"; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
if [ -n "$RESTORE_FROM" ]; then
  [ -f "$RESTORE_FROM" ] && [ -f "$KIT" ] || { echo "--restore-from needs the backup file and --kit FILE"; exit 1; }
  [[ "$(basename "$RESTORE_FROM")" =~ ^grcpal-[a-z0-9][a-z0-9-]{0,39}-[0-9]{8}T[0-9]{6}Z-(scheduled|manual|pre-update)\.grcbak$ ]] || {
    echo "Keep the backup's original file name (grcpal-<org>-<time>-<kind>.grcbak)"; exit 1; }
fi
RG="rg-grcpal-$NAME"
step() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }

step "Checking Azure sign-in"
az account show --query "{subscription:name, tenant:tenantId}" -o table
TENANT_ID=$(az account show --query tenantId -o tsv)

step "Resource group $RG in $LOCATION"
az group create -n "$RG" -l "$LOCATION" --tags app=grc-pal instance="$NAME" -o none

step "Entra app registration for sign-in"
DISPLAY="GRC-pal ($NAME)"
APP_ID=$(az ad app list --display-name "$DISPLAY" --query "[0].appId" -o tsv)
if [ -z "$APP_ID" ]; then
  APP_ID=$(az ad app create --display-name "$DISPLAY" --sign-in-audience AzureADMyOrg \
           --enable-id-token-issuance true --query appId -o tsv)
  az ad sp create --id "$APP_ID" -o none
  echo "created app $APP_ID"
else
  echo "reusing app $APP_ID"
fi
SP_ID=$(az ad sp show --id "$APP_ID" --query id -o tsv)
az ad sp update --id "$SP_ID" --set appRoleAssignmentRequired="$REQUIRE_ASSIGNMENT" -o none
CLIENT_SECRET=$(az ad app credential reset --id "$APP_ID" --display-name "container-apps-auth" --years 1 \
                --query password -o tsv --only-show-errors)
# Keep the encryption key stable across re-runs: saved credentials are encrypted with it.
APP="grcpal-$NAME"
ENCRYPTION_KEY=""
if az containerapp show -g "$RG" -n "$APP" -o none 2>/dev/null; then
  ENCRYPTION_KEY=$(az containerapp secret show -g "$RG" -n "$APP" --secret-name encryption-key --query value -o tsv 2>/dev/null || true)
fi
if [ -z "$ENCRYPTION_KEY" ]; then
  ENCRYPTION_KEY=$(openssl rand -hex 32)
  echo "generated a new encryption key; store a copy in your password manager:"
  echo "  GRCPAL_ENCRYPTION_KEY=$ENCRYPTION_KEY"
else
  echo "reusing the existing encryption key"
fi
# Backup key: stable across re-runs (existing backups need it); from the recovery kit when restoring.
BACKUP_KEY=""
if az containerapp show -g "$RG" -n "$APP" -o none 2>/dev/null; then
  BACKUP_KEY=$(az containerapp secret show -g "$RG" -n "$APP" --secret-name backup-key --query value -o tsv 2>/dev/null || true)
  [ -n "$RESTORE_FROM" ] && { echo "--restore-from only builds a new instance; $APP already exists"; exit 1; }
fi
if [ -n "$RESTORE_FROM" ]; then
  BACKUP_KEY=$(python3 -c 'import json,sys; k=json.load(open(sys.argv[1])); assert k["format"]=="grcpal-recovery-kit-1"; print(k["backup_key"])' "$KIT")
  KIT_APP_KEY=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("settings_key") or "")' "$KIT")
  [ -n "$KIT_APP_KEY" ] && ENCRYPTION_KEY="$KIT_APP_KEY" && echo "using the app key from the recovery kit"
fi
if [ -z "$BACKUP_KEY" ]; then
  BACKUP_KEY=$(openssl rand -base64 32)
  echo "generated a new backup key (download the recovery kit from Administration > Backups after sign-in)"
fi
# Image: never change versions here by accident; update.sh does that with its checks.
if [ -z "$IMAGE" ]; then
  IMAGE=$(az containerapp show -g "$RG" -n "$APP" --query "properties.template.containers[0].image" -o tsv 2>/dev/null || true)
fi
if [ -z "$IMAGE" ]; then
  VERSION=$(python3 -c 'import re,sys; print(re.search(r"__version__ = \"([0-9.]+)\"", open(sys.argv[1]).read()).group(1))' "$HERE/../../grcpal/__init__.py")
  IMAGE="ghcr.io/seattlespicybite/grc-pal:$VERSION"
fi
echo "image: $IMAGE"
GRCPAL_SECRET=$(openssl rand -hex 32)

PARAMS=(instanceName="$NAME" image="$IMAGE" entraClientId="$APP_ID" entraClientSecret="$CLIENT_SECRET"
        grcpalSecret="$GRCPAL_SECRET" encryptionKey="$ENCRYPTION_KEY" backupKey="$BACKUP_KEY" bootstrapAdmins="$ADMINS"
        githubRepo="$GITHUB_REPO")
[ -n "$MAIL_FROM" ] && PARAMS+=(mailBackend=graph mailFrom="$MAIL_FROM")
[ -n "$ALERT_EMAIL" ] && PARAMS+=(alertEmail="$ALERT_EMAIL")

if [ -n "$WHAT_IF" ]; then
  step "Preview (what-if)"
  az deployment group what-if -g "$RG" -f "$HERE/main.bicep" -p "${PARAMS[@]}"
  exit 0
fi

step "Deploying storage, identities, logs and the portal (3-6 minutes)"
OUT=$(az deployment group create -g "$RG" -n "grcpal-$(date +%Y%m%d%H%M%S)" -f "$HERE/main.bicep" \
      -p "${PARAMS[@]}" --query properties.outputs -o json)
get() { echo "$OUT" | python3 -c "import json,sys; print(json.load(sys.stdin)['$1']['value'])"; }
URL=$(get portalUrl) ; REDIRECT=$(get redirectUri)

step "Registering the sign-in redirect"
az ad app update --id "$APP_ID" --web-redirect-uris "$REDIRECT" -o none

if [ -n "$GITHUB_REPO" ]; then
  step "GitHub repository variables for collectors ($GITHUB_REPO)"
  VARS=(AZURE_CLIENT_ID="$(get collectorClientId)" AZURE_TENANT_ID="$TENANT_ID" GRCPAL_TENANT="$NAME"
        GRCPAL_EVIDENCE_ACCOUNT_URL="$(get evidenceAccountUrl)" GRCPAL_TABLES_URL="$(get tablesUrl)")
  VARS+=(AZURE_UPDATER_CLIENT_ID="$(get updaterClientId)" GRCPAL_INSTANCE="$NAME" AZURE_SUBSCRIPTION_ID="$(az account show --query id -o tsv)")
  if command -v gh >/dev/null && gh auth status >/dev/null 2>&1; then
    for kv in "${VARS[@]}"; do gh variable set "${kv%%=*}" --body "${kv#*=}" --repo "$GITHUB_REPO"; done
    echo "set ${#VARS[@]} variables with the GitHub CLI"
  else
    echo "Set these in GitHub > $GITHUB_REPO > Settings > Secrets and variables > Actions > Variables:"
    printf '  %s\n' "${VARS[@]}"
  fi
  echo "Monthly updates: create the environment 'grcpal-update' in GitHub > $GITHUB_REPO > Settings > Environments"
  echo "(add yourself as a required reviewer to approve every update). Details: docs/deploy-azure.md, 'Updates'."
  echo "Then grant read access for collectors: ./deploy/azure/grant-permissions.ps1 -PrincipalId $(get collectorPrincipalId) -Scope /subscriptions/$(az account show --query id -o tsv)"
fi

if [ -n "$MAIL_FROM" ]; then
  step "One manual step for email: let the portal send as $MAIL_FROM only"
  cat <<EOF
Run in Exchange Online PowerShell (Connect-ExchangeOnline) as an Exchange administrator.
This uses RBAC for Applications, so do NOT grant tenant-wide Mail.Send in Entra ID.

  New-ServicePrincipal -AppId $(get portalIdentityClientId) -ObjectId $(get portalIdentityPrincipalId) -DisplayName "GRC-pal $NAME"
  New-ManagementScope -Name "GRC-pal $NAME sender" -RecipientRestrictionFilter "PrimarySmtpAddress -eq '$MAIL_FROM'"
  New-ManagementRoleAssignment -App $(get portalIdentityClientId) -Role "Application Mail.Send" -CustomResourceScope "GRC-pal $NAME sender"
EOF
fi

if [ -n "$RESTORE_FROM" ]; then
  step "Restoring $(basename "$RESTORE_FROM") into the new instance"
  SA=$(get storageAccount)
  ME=$(az ad signed-in-user show --query id -o tsv)
  SCOPE="$(az storage account show -g "$RG" -n "$SA" --query id -o tsv)/blobServices/default/containers/backups"
  az role assignment create --assignee-object-id "$ME" --assignee-principal-type User \
     --role "Storage Blob Data Contributor" --scope "$SCOPE" -o none 2>/dev/null || true
  for i in $(seq 1 20); do   # role assignments take a minute or two to apply
    az storage blob upload --auth-mode login --account-name "$SA" -c backups -f "$RESTORE_FROM" \
       -n "$(basename "$RESTORE_FROM")" -o none 2>/dev/null && break
    [ "$i" = 20 ] && { echo "Could not upload the backup (permission not active yet). Re-run with the same options."; exit 1; }
    sleep 15
  done
  JOB=$(echo "job-$NAME-backup" | cut -c1-32)
  EX=$(az containerapp job start -g "$RG" -n "$JOB" --image "$IMAGE" --container-name backup \
       --command grcpal --args backup restore "$(basename "$RESTORE_FROM")" --query name -o tsv)
  echo "restore running as job execution $EX"
  for i in $(seq 1 120); do
    ST=$(az containerapp job execution show -g "$RG" -n "$JOB" --job-execution-name "$EX" --query properties.status -o tsv)
    case "$ST" in Succeeded) echo "restore finished"; break ;; Failed|Stopped|Degraded)
      echo "The restore did not finish ($ST). Logs: az containerapp job logs show -g $RG -n $JOB --execution $EX --container backup"; exit 1 ;; esac
    sleep 15
  done
  az role assignment delete --assignee "$ME" --role "Storage Blob Data Contributor" --scope "$SCOPE" -o none 2>/dev/null || true
fi

step "Done"
cat <<EOF
Portal:        $URL
Sign in as:    $ADMINS
Storage:       $(get storageAccount)
Next steps:
  1. Open the portal, sign in, and add people under Users and roles (or assign work; assignees get access automatically).
  2. After a week of clean runs, lock evidence and backup retention (cannot be undone):
       for c in evidence backups; do
         ETAG=\$(az storage container immutability-policy show -g $RG --account-name $(get storageAccount) -c \$c --query etag -o tsv)
         az storage container immutability-policy lock -g $RG --account-name $(get storageAccount) -c \$c --if-match "\$ETAG"
       done
  3. The sign-in client secret expires in one year. Re-run this script to rotate it.
  4. Restrict sign-in to your staff on compliant devices: docs/deploy-azure.md, Step 3b (Conditional Access).
EOF
