#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
cluster="${1:-ovn}"
image="${IMAGE:-ovn-light:dev}"
context="kind-${cluster}"
python3 scripts/local-kind-budget.py limit "$cluster"
if [[ "${GITHUB_ACTIONS:-}" != true || "${RUNNER_ENVIRONMENT:-}" != github-hosted ]]; then
  export GOMAXPROCS=2
  export GOFLAGS="${GOFLAGS:-} -p=2"
fi
kubectl --context "$context" get namespace ovn-kubernetes >/dev/null
make image IMAGE="$image"
kind load docker-image --name "$cluster" "$image"
BUILD_ID="$(docker image inspect --format '{{.Id}}' "$image")" IMAGE="$image" exec scripts/deploy.sh "$context"
