#!/usr/bin/env bash
# Update a GRC-pal instance on Azure Container Apps without risking its data.
#
#   ./deploy/azure/update.sh --name acme --status              what is running, what is available
#   ./deploy/azure/update.sh --name acme                       install the latest release (asks first)
#   ./deploy/azure/update.sh --name acme --version 0.3.1       install a specific release
#   ./deploy/azure/update.sh --name acme --auto                patch releases only (opt-in; not used by the workflow)
#   ./deploy/azure/update.sh --name acme --rollback            go back to the previous version
#
# How an update is applied (users keep working on the current version until step 6):
#   1. the image is pinned by digest and its build provenance is checked (gh attestation verify);
#   2. a backup is taken and checked, with the CURRENT version (backup job, "backup pre-update");
#   3. TRIAL: the NEW version copies every table into a scratch database, runs its migrations there and
#      self-tests the copy ("update trial"); a failure stops the update with nothing changed;
#   4. the new version starts as a new revision with NO traffic; it applies its (additive) migrations,
#      which the current version can still read;
#   5. HEALTH GATE: the new revision must answer /healthz and pass its self-test on the live data
#      (data model, audit chains, no table lost rows; "update selftest-saved");
#   6. traffic moves to the new revision; the jobs switch to the new image; the old revision stays ready
#      (label "previous") for --rollback. On any failure before this, traffic never moved.
# Every result is written to the instance's audit log (update.applied, update.trial_failed, ...).
#
# Rules: nothing installs unless a person runs this script or the workflow with --version (the weekly
# workflow run only reports what is available). --auto (patch releases only) exists for operators who
# choose automatic patching; GRC-pal's own workflow does not use it. Major releases also need --major (read the
# release notes first: they may need the backup-and-restore path).
# Needs: Azure CLI signed in with rights on the container app and its jobs (the monthly workflow uses the
# updater identity deploy.sh created), curl, python3, and the GitHub CLI for the provenance check.
set -euo pipefail
NAME="" ; VERSION="" ; AUTO="" ; ROLLBACK="" ; STATUS="" ; YES="" ; MAJOR="" ; NO_PROVENANCE=""
REPO="seattlespicybite/grc-pal"
while [ $# -gt 0 ]; do
  case "$1" in
    --name) NAME="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --auto) AUTO="1"; YES="1"; shift ;;
    --rollback) ROLLBACK="1"; shift ;;
    --status) STATUS="1"; shift ;;
    --yes) YES="1"; shift ;;
    --major) MAJOR="1"; shift ;;
    --repo) REPO="$2"; shift 2 ;;
    --no-provenance-check) NO_PROVENANCE="1"; shift ;;
    -h|--help) sed -n '2,28p' "$0"; exit 0 ;;
    *) echo "Unknown option $1 (see --help)"; exit 1 ;;
  esac
done
[[ "$NAME" =~ ^[a-z0-9][a-z0-9-]{1,19}$ ]] || { echo "--name is required (the instance name used with deploy.sh)"; exit 1; }
[ -z "$VERSION" ] || [[ "$VERSION" =~ ^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}$ ]] || { echo "--version must look like 0.3.1"; exit 1; }
command -v az >/dev/null || { echo "Install the Azure CLI first: https://aka.ms/azcli"; exit 1; }

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
RG="rg-grcpal-$NAME"
APP=$(echo "grcpal-$NAME" | cut -c1-32)
JOBS=(collect remind tasks backup)
job_name() { echo "job-$NAME-$1" | cut -c1-32; }
step() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
progress() {  # progress PERCENT MESSAGE: numbered steps so a person watching the run sees how far it got
  step "[$1%] $2"
}
die() { echo "update: $*" >&2; exit 1; }
py() { python3 -c "$@"; }

# ---------------------------------------------------------------- facts about the instance
APP_ID=$(az containerapp show -g "$RG" -n "$APP" --query id -o tsv 2>/dev/null) || die "no container app $APP in $RG"
tag() { az tag list --resource-id "$APP_ID" --query "properties.tags.\"$1\"" -o tsv 2>/dev/null || true; }
set_tags() { az tag update --resource-id "$APP_ID" --operation Merge --tags "$@" -o none; }
CUR_IMAGE=$(az containerapp show -g "$RG" -n "$APP" --query "properties.template.containers[0].image" -o tsv)
CUR_VERSION=$(tag grcpal-version)
if [ -z "$CUR_VERSION" ] && [[ "$CUR_IMAGE" =~ :([0-9]+\.[0-9]+\.[0-9]+)$ ]]; then CUR_VERSION="${BASH_REMATCH[1]}"; fi
traffic_rev() {  # the revision that serves users now
  az containerapp ingress traffic show -g "$RG" -n "$APP" -o json | py '
import json, sys
rows = json.load(sys.stdin)
named = [r for r in rows if r.get("weight", 0) > 0 and r.get("revisionName")]
print(named[0]["revisionName"] if named else "")'
}
label_rev() {
  az containerapp ingress traffic show -g "$RG" -n "$APP" -o json | py '
import json, sys
print(next((r["revisionName"] for r in json.load(sys.stdin) if r.get("label") == sys.argv[1]), ""))' "$1"
}
latest_release() {
  curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | py 'import json,sys; print(json.load(sys.stdin)["tag_name"].lstrip("v"))'
}
newer_releases() {  # every release newer than the running one, with "do I need it?" (same rules as the portal)
  curl -fsSL "https://api.github.com/repos/$REPO/releases?per_page=30" | PYTHONPATH="$ROOT" py '
import json, sys
from grcpal import update
try:
    rows = update.newer_releases(json.load(sys.stdin), sys.argv[1])
except update.UpdateError:
    rows = None
if rows is None:
    print("- (the running version is unknown)")
elif not rows:
    print("- none: this is the newest release")
for r in rows or []:
    print("- %s (%s): %s %s" % (r["version"], r["kind"], r["advice"]["text"], r["url"]))' "$CUR_VERSION"
}
kind_of() {
  py '
import sys
def t(v): return tuple(int(x) for x in v.split("."))
c, n = sys.argv[1], sys.argv[2]
if not c: print("unknown"); raise SystemExit
c, n = t(c), t(n)
print("same" if n == c else "older" if n < c else "major" if n[0] != c[0] else "minor" if n[1] != c[1] else "patch")' "$1" "$2"
}

# ---------------------------------------------------------------- run a grcpal command as a job execution
# Job arguments never start with "--": the Azure CLI would read them as its own options.
run_job() {  # run_job IMAGE ARGS... ; prints the execution name; returns non-zero if it did not succeed
  local img="$1"; shift
  local j; j=$(job_name backup)
  local ex st
  ex=$(az containerapp job start -g "$RG" -n "$j" --image "$img" --container-name backup \
       --command grcpal --args "$@" --query name -o tsv)
  for _ in $(seq 1 240); do
    st=$(az containerapp job execution show -g "$RG" -n "$j" --job-execution-name "$ex" --query properties.status -o tsv)
    case "$st" in
      Succeeded) echo "$ex"; return 0 ;;
      Failed|Stopped|Degraded)
        echo "job execution $ex ended $st. Logs: az containerapp job logs show -g $RG -n $j --execution $ex --container backup" >&2
        return 1 ;;
    esac
    sleep 15
  done
  echo "job execution $ex did not finish within an hour" >&2
  return 1
}
record() {  # record IMAGE EVENT JSON (best effort: never stops a rollback)
  run_job "$1" update record "$2" "$3" >/dev/null || echo "note: could not write $2 to the audit log" >&2
}

# ---------------------------------------------------------------- status
if [ -n "$STATUS" ]; then
  LATEST=$(latest_release || echo "?")
  echo "instance:      $NAME ($APP in $RG)"
  echo "running:       ${CUR_VERSION:-unknown} ($CUR_IMAGE)"
  echo "serving:       $(traffic_rev)    previous: $(label_rev previous)"
  echo "latest:        $LATEST ($(kind_of "$CUR_VERSION" "$LATEST" 2>/dev/null || echo ?))"
  echo
  echo "Newer releases (install one: run the workflow with its version):"
  newer_releases || echo "- (could not read the release list from GitHub)"
  exit 0
fi

# ---------------------------------------------------------------- rollback
if [ -n "$ROLLBACK" ]; then
  PREV=$(label_rev previous)
  [ -n "$PREV" ] || die "no revision is labelled 'previous'; nothing to roll back to"
  NOW=$(traffic_rev)
  PREV_IMAGE=$(az containerapp revision show -g "$RG" -n "$APP" --revision "$PREV" --query "properties.template.containers[0].image" -o tsv)
  PREV_VERSION=$(tag grcpal-previous-version)
  step "Rolling back: traffic to $PREV (${PREV_VERSION:-previous version})"
  [ -n "$YES" ] || { read -r -p "Continue? [y/N] " a; [[ "$a" =~ ^[yY]$ ]] || exit 1; }
  az containerapp revision activate -g "$RG" -n "$APP" --revision "$PREV" -o none 2>/dev/null || true
  az containerapp ingress traffic set -g "$RG" -n "$APP" --revision-weight "$PREV=100" -o none
  for j in "${JOBS[@]}"; do az containerapp job update -g "$RG" -n "$(job_name "$j")" --image "$PREV_IMAGE" -o none; done
  set_tags grcpal-version="${PREV_VERSION:-unknown}" grcpal-previous-version="${CUR_VERSION:-unknown}"
  record "$PREV_IMAGE" update.rolled_back "{\"from\": \"${CUR_VERSION}\", \"to\": \"${PREV_VERSION}\", \"revision\": \"$PREV\", \"by\": \"update.sh\"}"
  echo "Back on $PREV. The newer revision $NOW is kept (no traffic) for investigation."
  echo "Data note: updates only add to the data model, so the previous version reads today's data. If the release"
  echo "notes say otherwise (major release), restore the pre-update backup into a new instance instead."
  exit 0
fi

# ---------------------------------------------------------------- choose the version
[ -n "$VERSION" ] || VERSION=$(latest_release) || die "could not read the latest release from GitHub"
KIND=$(kind_of "$CUR_VERSION" "$VERSION")
echo "running ${CUR_VERSION:-unknown}, target $VERSION ($KIND)"
case "$KIND" in
  same|older) echo "Nothing to do."; exit 0 ;;
  unknown) [ -n "$AUTO" ] && { echo "The running version is unknown; run update.sh by hand once."; exit 0; } ;;
  minor) [ -n "$AUTO" ] && { echo "$VERSION is a feature release: waiting for approval (run the workflow with version $VERSION)."; exit 0; } ;;
  major)
    [ -n "$AUTO" ] && { echo "$VERSION is a major release: waiting for approval."; exit 0; }
    [ -n "$MAJOR" ] || die "$VERSION is a major release. Read its release notes, then re-run with --major." ;;
esac

progress 10 "Pinning the image and checking where it was built"
TOKEN=$(curl -fsSL "https://ghcr.io/token?scope=repository:${REPO}:pull" | py 'import json,sys; print(json.load(sys.stdin)["token"])')
DIGEST=$(curl -fsSI -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json" \
  "https://ghcr.io/v2/${REPO}/manifests/${VERSION}" | tr -d '\r' | awk -F': ' 'tolower($1)=="docker-content-digest" {print $2}')
[[ "$DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]] || die "image ghcr.io/$REPO:$VERSION not found"
NEW_IMAGE="ghcr.io/$REPO@$DIGEST"
if [ -z "$NO_PROVENANCE" ]; then
  command -v gh >/dev/null || die "the GitHub CLI is needed to check the image's build provenance (or --no-provenance-check)"
  gh attestation verify "oci://$NEW_IMAGE" --owner "${REPO%%/*}" >/dev/null || die "the image's build provenance did not verify; not installing"
  echo "provenance verified: built by $REPO's release workflow"
fi
echo "image $NEW_IMAGE"
[ -n "$YES" ] || { read -r -p "Install $VERSION ($KIND)? [y/N] " a; [[ "$a" =~ ^[yY]$ ]] || exit 1; }
DETAIL="\"from\": \"${CUR_VERSION}\", \"to\": \"$VERSION\", \"kind\": \"$KIND\", \"image\": \"$NEW_IMAGE\", \"by\": \"update.sh\""

progress 25 "Backup before the update (current version)"
run_job "$CUR_IMAGE" backup pre-update >/dev/null || die "the pre-update backup failed; nothing was changed"

progress 45 "Trial: $VERSION migrates and checks a copy of the tables"
if ! run_job "$NEW_IMAGE" update trial >/dev/null; then
  record "$CUR_IMAGE" update.trial_failed "{$DETAIL}"
  die "$VERSION failed its trial on a copy of the data; nothing was changed"
fi

progress 65 "Starting $VERSION as a new revision with no traffic"
az containerapp revision set-mode -g "$RG" -n "$APP" --mode multiple -o none 2>/dev/null || true
OLD_REV=$(traffic_rev)
[ -n "$OLD_REV" ] || OLD_REV=$(az containerapp show -g "$RG" -n "$APP" --query properties.latestReadyRevisionName -o tsv)
az containerapp ingress traffic set -g "$RG" -n "$APP" --revision-weight "$OLD_REV=100" -o none
SUFFIX="v${VERSION//./-}-$(date +%H%M%S)"
az containerapp update -g "$RG" -n "$APP" --image "$NEW_IMAGE" --revision-suffix "$SUFFIX" -o none
NEW_REV="$APP--$SUFFIX"
FQDN=$(az containerapp revision show -g "$RG" -n "$APP" --revision "$NEW_REV" --query properties.fqdn -o tsv)

fail_back() {
  echo "update: $1; traffic stays on $OLD_REV" >&2
  az containerapp ingress traffic set -g "$RG" -n "$APP" --revision-weight "$OLD_REV=100" -o none || true
  az containerapp revision deactivate -g "$RG" -n "$APP" --revision "$NEW_REV" -o none || true
  record "$CUR_IMAGE" update.rolled_back "{$DETAIL, \"reason\": \"$1\"}"
  exit 1
}

progress 80 "Health gate: the new revision must answer and pass its self-test"
ok=""
for _ in $(seq 1 40); do
  if curl -fsS --max-time 10 "https://$FQDN/healthz" >/dev/null 2>&1; then ok=1; break; fi
  sleep 15
done
[ -n "$ok" ] || fail_back "the new revision did not answer /healthz within 10 minutes"
run_job "$NEW_IMAGE" update selftest-saved >/dev/null || fail_back "the self-test on the live data failed"

progress 95 "Moving traffic to $VERSION"
az containerapp ingress traffic set -g "$RG" -n "$APP" --revision-weight "$NEW_REV=100" -o none
az containerapp revision label add -g "$RG" -n "$APP" --label previous --revision "$OLD_REV" --yes -o none
for j in "${JOBS[@]}"; do az containerapp job update -g "$RG" -n "$(job_name "$j")" --image "$NEW_IMAGE" -o none; done
set_tags grcpal-version="$VERSION" grcpal-previous-version="${CUR_VERSION:-unknown}"
# keep only the serving and the previous revision active
for r in $(az containerapp revision list -g "$RG" -n "$APP" --query "[?properties.active].name" -o tsv); do
  [ "$r" = "$NEW_REV" ] || [ "$r" = "$OLD_REV" ] || az containerapp revision deactivate -g "$RG" -n "$APP" --revision "$r" -o none
done
record "$NEW_IMAGE" update.applied "{$DETAIL, \"revision\": \"$NEW_REV\"}"
progress 100 "Updated to $VERSION"
echo "Updated to $VERSION. Roll back with: ./deploy/azure/update.sh --name $NAME --rollback"
