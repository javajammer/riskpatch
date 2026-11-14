#!/usr/bin/env bash
# Build the RiskPatch collector as static Linux binaries, one per CPU architecture.
#
#   scripts/build-collector.sh              # amd64 and arm64
#   scripts/build-collector.sh arm64        # only arm64
#   scripts/build-collector.sh --no-test    # skip go test
#
# Output: collector/bin/linux-<arch>/riskpatch-collector plus a SHA256SUMS file per directory.
# Requires Go 1.18 or newer on the build host. No cgo, no runtime dependencies.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COLLECTOR="$ROOT/collector"
OUT_ROOT="${OUT_ROOT:-$COLLECTOR/bin}"
RUN_TESTS=1
ARCHES=()

for arg in "$@"; do
  case "$arg" in
    amd64|arm64) ARCHES+=("$arg") ;;
    --no-test) RUN_TESTS=0 ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done
if [ ${#ARCHES[@]} -eq 0 ]; then
  ARCHES=(amd64 arm64)
fi

if ! command -v go >/dev/null 2>&1; then
  echo "go is not installed. Install Go 1.18+ (https://go.dev/dl/) and retry." >&2
  exit 1
fi

GO_VERSION="$(go env GOVERSION)"
VERSION="${VERSION:-$(sed -n 's/^\tversion = "\(.*\)"$/\1/p' "$COLLECTOR/cmd/riskpatch-collector/main.go")}"
COMMIT="$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
LDFLAGS="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}"

echo "build host : $(uname -m) · $GO_VERSION"
echo "collector  : $VERSION ($COMMIT)"
echo "targets    : ${ARCHES[*]}"

cd "$COLLECTOR"
if [ "$RUN_TESTS" -eq 1 ]; then
  echo "== go test ./..."
  go test ./...
fi

for arch in "${ARCHES[@]}"; do
  out_dir="$OUT_ROOT/linux-$arch"
  out="$out_dir/riskpatch-collector"
  mkdir -p "$out_dir"
  echo "== linux/$arch -> ${out#$ROOT/}"
  GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go build -trimpath -ldflags "$LDFLAGS" -o "$out" ./cmd/riskpatch-collector
  (cd "$out_dir" && sha256sum riskpatch-collector > SHA256SUMS)
  if command -v file >/dev/null 2>&1; then
    file "$out" | sed 's/^/   /'
  fi
done

echo "== done"
for arch in "${ARCHES[@]}"; do
  (cd "$OUT_ROOT/linux-$arch" && sha256sum -c SHA256SUMS)
done
