from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from riskpatch.inventory import load_inventory
from riskpatch.pipeline import run_once, webhook_url
from riskpatch.service import paths, serve
from riskpatch.tui import run_tui


def _chown_tree(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    for root, dirs, files in os.walk(path):
        os.chown(root, 1000, 1000)
        for name in dirs + files:
            os.chown(Path(root) / name, 1000, 1000)


def drop_root() -> None:
    if os.geteuid() != 0:
        return
    from riskpatch.service import paths

    _inventory, reports, cache = paths()
    from riskpatch.config import get_settings

    for path in (reports, cache, get_settings().db_path.parent):
        _chown_tree(path)
    os.setgid(1000)
    os.setuid(1000)


def server_command(args: argparse.Namespace) -> None:
    from riskpatch import auth, db
    from riskpatch.config import get_settings

    settings = get_settings()
    if args.command == "api":
        import uvicorn

        workers = max(1, args.workers)
        if workers == 1:
            from riskpatch.api import create_app

            uvicorn.run(create_app(settings), host=args.host, port=args.port, proxy_headers=True, log_level="info", access_log=False)
            return
        # Several processes use several CPU cores. Migrate and create bootstrap accounts once here so the
        # workers' startup finds nothing to do and never races each other on the same schema change.
        conn = db.connect(settings.db_path)
        db.migrate(conn)
        auth.ensure_bootstrap(conn, os.environ.get("RISKPATCH_BOOTSTRAP_TOKEN", "").strip())
        auth.ensure_bootstrap_admin(conn, os.environ.get("RISKPATCH_BOOTSTRAP_ADMIN_USER", "").strip(), os.environ.get("RISKPATCH_BOOTSTRAP_ADMIN_PASSWORD", ""))
        conn.close()
        uvicorn.run("riskpatch.api:create_app", factory=True, workers=workers, host=args.host, port=args.port,
                    proxy_headers=True, log_level="info", access_log=False)
        return
    if args.command == "worker":
        from riskpatch.scheduler import worker

        worker()
        return
    if args.command == "restore":
        db.restore(args.source, settings.db_path)
        print(f"restored {args.source} -> {settings.db_path}")
        return
    conn = db.connect(settings.db_path)
    version = db.migrate(conn)
    if args.command == "migrate":
        print(f"schema version {version}")
    elif args.command == "backup":
        db.backup(conn, args.dest)
        print(args.dest)
    elif args.command == "prune":
        from riskpatch.jobs import prune

        print(prune(conn, settings))
    elif args.command == "reset":
        if not args.yes:
            raise SystemExit("Add --yes to confirm deleting all data")
        counts = db.reset(conn)
        total = sum(counts.values())
        print(f"clean slate: {total} baris dihapus")
        for table, n in counts.items():
            print(f"  {table}: {n}")
    elif args.command == "token":
        if args.action == "list":
            for row in conn.execute("SELECT name, scopes, created_at, expires_at, revoked_at, last_used_at FROM api_tokens ORDER BY id"):
                print(dict(row))
        elif not args.name:
            raise SystemExit("--name required")
        elif args.action == "create":
            print(auth.create_token(conn, args.name, [s.strip() for s in args.scopes.split(",") if s.strip()], expires_at=args.expires_at))
            print("Save this token now; only the hash is stored.", file=sys.stderr)
        else:
            print(f"revoked: {auth.revoke_token(conn, args.name)}")
    elif args.command == "db":
        from riskpatch import db as dbmod
        if args.action == "check":
            print(f"schema version: {db.schema_version(conn)}")
            missing = dbmod.missing_indexes(conn)
            print("hot indexes: " + ("all present" if not missing else "MISSING " + ", ".join(missing)))
            if missing:
                raise SystemExit(1)
        else:
            print(f"statistics collected in {dbmod.analyze(conn):.1f}s")
    elif args.command == "user":
        import getpass
        if args.action == "list":
            for row in conn.execute("SELECT username, role, disabled_at, last_login_at FROM users ORDER BY username"):
                print(dict(row))
        elif not args.username:
            raise SystemExit("--username required")
        elif args.action == "create":
            if not args.role:
                raise SystemExit("--role required (viewer, operator, admin)")
            password = getpass.getpass("New password (min 12 characters): ")
            if password != getpass.getpass("Repeat password: "):
                raise SystemExit("passwords do not match")
            print(f"created user {args.username} ({args.role}) id={auth.create_user(conn, args.username, password, args.role, 'cli')}")
        else:
            row = auth.find_user(conn, args.username)
            if row is None:
                raise SystemExit("user not found")
            password = getpass.getpass("New password (min 12 characters): ")
            if password != getpass.getpass("Repeat password: "):
                raise SystemExit("passwords do not match")
            auth.set_password(conn, row["id"], password, "cli")
            print(f"password reset for {args.username}; their sessions were signed out")


def main() -> None:
    drop_root()
    parser = argparse.ArgumentParser(prog="riskpatch")
    sub = parser.add_subparsers(dest="command", required=True)
    validate = sub.add_parser("validate")
    validate.add_argument("path", nargs="?", type=Path)
    sub.add_parser("service")
    sub.add_parser("tui")
    once = sub.add_parser("run-once")
    once.add_argument("--ttl-ok", action="store_true")
    api = sub.add_parser("api", help="FastAPI server + web UI")
    api.add_argument("--host", default="127.0.0.1")
    api.add_argument("--port", type=int, default=8080)
    api.add_argument("--workers", type=int, default=int(os.environ.get("RISKPATCH_WORKERS", "1")), help="proses uvicorn (satu per core CPU); default env RISKPATCH_WORKERS")
    sub.add_parser("worker", help="scheduler: CVE sync tiap jam, analisis tiap 3 jam")
    sub.add_parser("migrate", help="terapkan migrasi SQLite")
    token = sub.add_parser("token", help="kelola API token")
    token.add_argument("action", choices=["create", "list", "revoke"])
    token.add_argument("--name")
    token.add_argument("--scopes", default="read")
    token.add_argument("--expires-at")
    dbcmd = sub.add_parser("db", help="periksa index dan statistik database")
    dbcmd.add_argument("action", choices=["check", "analyze"])
    user = sub.add_parser("user", help="kelola akun login web UI")
    user.add_argument("action", choices=["create", "list", "reset-password"])
    user.add_argument("--username")
    user.add_argument("--role", choices=["viewer", "operator", "admin"])
    backup = sub.add_parser("backup", help="backup SQLite online")
    backup.add_argument("dest", type=Path)
    restore = sub.add_parser("restore", help="restore from backup (stop api/worker first)")
    restore.add_argument("source", type=Path)
    check = sub.add_parser("llm-check", help="Kilo Gateway diagnostics: GET /models (without key) + optional small chat")
    check.add_argument("--chat", action="store_true", help="send one minimal chat request (uses LLM_API_KEY)")
    sub.add_parser("prune", help="terapkan retensi raw payload")
    reset = sub.add_parser("reset", help="wipe all data (clean slate), except schema and tokens")
    reset.add_argument("--yes", action="store_true", help="confirm deleting all data")
    args = parser.parse_args()
    if args.command in {"api", "worker", "migrate", "token", "user", "db", "backup", "restore", "prune", "reset"}:
        server_command(args)
        return
    if args.command == "llm-check":
        import json
        import httpx
        from riskpatch import llm
        with httpx.Client() as client:
            result = llm.diagnose(client, chat_probe=args.chat)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        raise SystemExit(0 if result["models"]["ok"] and result["chat"]["ok"] is not False else 1)
    if args.command == "validate":
        inventory, _reports, _cache = paths()
        path = args.path or inventory
        load_inventory(path)
        print(f"valid: {path}")
        return
    if args.command == "tui":
        run_tui()
        return
    if args.command == "service":
        serve()
        return
    inventory, reports, cache = paths()
    report = run_once(inventory, reports, cache, webhook_url(), ttl_ok=args.ttl_ok)
    print(reports / "latest.md")
    if report.errors:
        print("\n".join(report.errors), file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
