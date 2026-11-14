import itertools

from riskpatch import auth

PASSWORD = "correct horse battery staple"
_numbers = itertools.count(1)


def session_for(client, conn, role: str) -> str:
    username = f"{role}{next(_numbers)}"
    user_id = auth.create_user(conn, username, PASSWORD, role, "test")
    secret = auth.create_session(conn, user_id)
    client.cookies.set("rp_session", secret)
    return secret


def register(conn, *names: str) -> None:
    for name in names:
        if conn.execute("SELECT 1 FROM users WHERE username=?", (name,)).fetchone() is None:
            auth.create_user(conn, name, PASSWORD, "viewer", "test")
