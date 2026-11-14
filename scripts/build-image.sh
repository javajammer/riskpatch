#!/usr/bin/env bash
# Build the RiskPatch container image for one or more CPU architectures.
#
#   scripts/build-image.sh                          # host architecture, loads into local Docker
#   scripts/build-image.sh --platform linux/arm64   # cross-build arm64, loads into local Docker
#   scripts/build-image.sh --push ghcr.io/you/riskpatch:0.2.0 --platform linux/amd64,linux/arm64
#
# Multi-platform builds cannot be loaded into the local daemon; they need --push to a registry.
# Cross-building needs QEMU binfmt handlers on the build host (see README, "Cross-architecture builds").
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${VERSION:-0.2.0}"
IMAGE="${IMAGE:-riskpatch}"
PLATFORM=""
PUSH_TAG=""

while [ $# -gt 0 ]; do
  case "$1" in
    --platform) PLATFORM="$2"; shift 2 ;;
    --push) PUSH_TAG="$2"; shift 2 ;;
    --tag) IMAGE="$2"; shift 2 ;;
    -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if ! docker buildx version >/dev/null 2>&1; then
  echo "docker buildx is required (Docker Engine 20.10+ includes it)." >&2
  exit 1
fi

if [ -z "$PLATFORM" ]; then
  PLATFORM="linux/$(docker version -f '{{.Server.Arch}}' 2>/dev/null | sed 's/x86_64/amd64/;s/aarch64/arm64/')"
fi

ARGS=(buildx build "$ROOT" --file "$ROOT/Dockerfile" --platform "$PLATFORM" --tag "$IMAGE:$VERSION")
if [ -n "$PUSH_TAG" ]; then
  ARGS+=(--tag "$PUSH_TAG" --push)
elif [[ "$PLATFORM" == *,* ]]; then
  echo "multi-platform builds need --push <registry/image:tag>; the local daemon cannot hold several architectures." >&2
  exit 2
else
  ARGS+=(--load)
fi

echo "building $IMAGE:$VERSION for $PLATFORM"
docker "${ARGS[@]}"

if [ -z "$PUSH_TAG" ]; then
  docker image inspect "$IMAGE:$VERSION" --format 'loaded: {{.RepoTags}} arch={{.Architecture}}'
fi
