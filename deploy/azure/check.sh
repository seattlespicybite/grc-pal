#!/usr/bin/env bash
# Check a GRC-pal instance on Azure after deploying or updating (also run at the end of deploy.sh).
#
#   ./deploy/azure/check.sh --name acme          # report only
#   ./deploy/azure/check.sh --name acme --fix    # also register a missing sign-in redirect address
#
# Checks: the revision serving traffic is healthy, Microsoft sign-in is enforced, the sign-in redirect address
# and client secret are in place, who may sign in, and from the internet: /healthz answers while a forged
# identity header, /dev/login and /login are refused. Reads configuration only; no secrets. Exit 1 on any FAIL.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
exec python3 -I "$HERE/check.py" "$@"
