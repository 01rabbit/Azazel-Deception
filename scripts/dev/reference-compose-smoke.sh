#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/runtime/compose/reference-linux.compose.yaml"
PROJECT="az06-smoke-${GITHUB_RUN_ID:-$$}"

cleanup() {
  docker compose -p "$PROJECT" -f "$COMPOSE_FILE" down --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

command -v docker >/dev/null 2>&1 || { echo "docker is required" >&2; exit 2; }
docker info >/dev/null
docker compose version >/dev/null

case "$(uname -m)" in
  arm64|aarch64) expected_arch="arm64" ;;
  x86_64|amd64) expected_arch="amd64" ;;
  *) echo "unsupported host architecture: $(uname -m)" >&2; exit 2 ;;
esac

echo "[az06] host architecture: $expected_arch"
echo "[az06] validating Compose configuration"
docker compose -p "$PROJECT" -f "$COMPOSE_FILE" config --quiet

echo "[az06] pulling native image and starting isolated reference runtime"
docker compose -p "$PROJECT" -f "$COMPOSE_FILE" pull
docker compose -p "$PROJECT" -f "$COMPOSE_FILE" up -d --remove-orphans

cid="$(docker compose -p "$PROJECT" -f "$COMPOSE_FILE" ps -q intranet-web)"
if [[ -z "$cid" ]]; then
  echo "reference container did not start" >&2
  exit 1
fi

image_ref="$(docker inspect "$cid" --format '{{.Config.Image}}')"
image_arch="$(docker image inspect "$image_ref" --format '{{.Architecture}}')"
if [[ "$image_arch" != "$expected_arch" ]]; then
  echo "image architecture mismatch: expected=$expected_arch actual=$image_arch" >&2
  exit 1
fi

published="$(docker port "$cid" 2>/dev/null || true)"
if [[ -n "$published" ]]; then
  echo "reference container unexpectedly publishes host ports: $published" >&2
  exit 1
fi

network_name="${PROJECT}_decoy_internal"
internal="$(docker network inspect "$network_name" --format '{{.Internal}}')"
if [[ "$internal" != "true" ]]; then
  echo "decoy network is not internal" >&2
  exit 1
fi

readonly="$(docker inspect "$cid" --format '{{.HostConfig.ReadonlyRootfs}}')"
[[ "$readonly" == "true" ]] || { echo "rootfs is not read-only" >&2; exit 1; }

docker inspect "$cid" --format '{{json .HostConfig.CapDrop}}' | grep -q 'ALL' || {
  echo "ALL capabilities are not dropped" >&2
  exit 1
}

docker inspect "$cid" --format '{{json .HostConfig.SecurityOpt}}' | grep -qi 'no-new-privileges' || {
  echo "no-new-privileges is missing" >&2
  exit 1
}

pids_limit="$(docker inspect "$cid" --format '{{.HostConfig.PidsLimit}}')"
memory_limit="$(docker inspect "$cid" --format '{{.HostConfig.Memory}}')"
nano_cpus="$(docker inspect "$cid" --format '{{.HostConfig.NanoCpus}}')"
[[ "$pids_limit" -gt 0 ]] || { echo "PID limit missing" >&2; exit 1; }
[[ "$memory_limit" -gt 0 ]] || { echo "memory limit missing" >&2; exit 1; }
[[ "$nano_cpus" -gt 0 ]] || { echo "CPU limit missing" >&2; exit 1; }

docker compose -p "$PROJECT" -f "$COMPOSE_FILE" exec -T intranet-web nginx -t >/dev/null

echo "[az06] reference Compose smoke passed"
echo "[az06] native image architecture=$image_arch internal_network=true published_ports=none"
