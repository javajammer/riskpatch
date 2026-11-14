#!/usr/bin/env bash
# Create or verify the RiskPatch database.
#
#   scripts/setup-db.sh              # existing database: apply pending migrations, check indexes, collect statistics
#   scripts/setup-db.sh --recreate   # keep a copy of the current database in the backups volume, then build a new one
#
# Indexes come from the migrations (src/riskpatch/migrations/), so a new database gets all of them automatically.
# Statistics (ANALYZE) are not created by migrations; this script collects them so the query planner does not guess.
set -euo pipefail

cd "$(dirname "$0")/.."
DB=/data/db/stackwatch.sqlite3
RUN="docker compose run --rm --no-deps api"

if [ "${1:-}" = "--recreate" ]; then
  echo "This copies the current database to the backups volume and then starts an empty database."
  read -r -p "Type RECREATE to continue: " answer
  if [ "$answer" != "RECREATE" ]; then
    echo "cancelled"
    exit 1
  fi
  docker compose stop api worker
  STAMP="$(date +%Y%m%d-%H%M%S)"
  $RUN sh -c "if [ -f $DB ]; then cp $DB /data/backups/riskpatch-before-recreate-$STAMP.sqlite3 && rm -f $DB $DB-wal $DB-shm && echo 'previous database saved to backups volume'; else echo 'no existing database'; fi"
elif [ -n "${1:-}" ]; then
  echo "unknown option: $1 (use --recreate or no option)" >&2
  exit 2
fi

echo "== migrations"
$RUN riskpatch migrate
echo "== indexes"
$RUN riskpatch db check
echo "== statistics"
$RUN riskpatch db analyze
echo "== start services"
docker compose up -d api worker
echo "done: $(curl -s http://127.0.0.1:8080/api/v1/ready || echo 'api not answering yet')"
