#!/usr/bin/env bash
# deploy_shield.sh is deprecated: shield deployment is fully integrated into setup.sh.
cd "$(dirname "$(readlink -f "$0")")"
exec ./setup.sh --upgrade --yes "$@"
