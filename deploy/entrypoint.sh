#!/bin/sh
set -eu
if [ "$(id -u)" = "0" ]; then
  mkdir -p /data/reports /data/cache /data/db /data/backups
  chown -R app:app /data/reports /data/cache /data/db /data/backups
  exec setpriv --reuid=app --regid=app --init-groups -- "$@"
fi
exec "$@"
