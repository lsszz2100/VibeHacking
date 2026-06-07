"""
취약한 Flask 앱 — SQLi 실습용
의도적으로 취약하게 작성된 코드입니다. 프로덕션에 절대 사용하지 마세요.
"""
from __future__ import annotations

import os
import sqlite3
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)
DB_PATH = os.environ.get("DB_PATH", "/app/users.db")

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>SQLi Target — 취약한 로그인</title>
    <style>
        body { font-family: monospace; background: #1a1a2e; color: #eee; padding: 40px; }
        input, button { padding: 8px 12px; margin: 4px; }
        button { background: #e94560; color: #fff; border: none; cursor: pointer; }
        pre { background: #16213e; padding: 16px; border-radius: 4px; }
        .hint { color: #0f3460; background: #e94560; padding: 8px; border-radius: 4px; }
    </style>
</head>
<body>
    <h1>취약한 사용자 검색</h1>
    <p class="hint">힌트: 이 앱은 SQL 인젝션에 취약합니다!</p>

    <h2>사용자 ID로 검색</h2>
    <form action="/search" method="GET">
        <input type="text" name="id" placeholder="사용자 ID (예: 1)" />
        <button type="submit">검색</button>
    </form>

    <h2>사용자명으로 로그인</h2>
    <form action="/login" method="POST">
        <input type="text" name="username" placeholder="username" />
        <input type="password" name="password" placeholder="password" />
        <button type="submit">로그인</button>
    </form>

    <h2>엔드포인트 목록</h2>
    <pre>
GET  /            — 이 페이지
GET  /search?id=  — ID로 사용자 검색 (취약한 쿼리)
POST /login       — 로그인 (취약한 인증)
GET  /users       — 사용자 목록 (UNION 기반 SQLi 실습)
GET  /api/user?name= — JSON API (블라인드 SQLi 실습)
    </pre>
</body>
</html>
"""


def init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'user',
            secret_flag TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS secrets (
            id INTEGER PRIMARY KEY,
            flag TEXT NOT NULL
        )
    """)
    # 샘플 데이터
    users = [
        (1, "admin",    "sup3r_s3cr3t",  "admin@corp.local",   "admin", "FLAG{sql1_1nj3ct10n_m4st3r}"),
        (2, "alice",    "alice1234",      "alice@corp.local",   "user",  None),
        (3, "bob",      "password123",   "bob@corp.local",     "user",  None),
        (4, "charlie",  "qwerty!@#",     "charlie@corp.local", "user",  None),
    ]
    c.executemany(
        "INSERT OR IGNORE INTO users VALUES (?,?,?,?,?,?)", users
    )
    c.execute("INSERT OR IGNORE INTO secrets VALUES (1, 'FLAG{y0u_g0t_th3_s3cr3t_t4bl3}')")
    conn.commit()
    conn.close()


@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)


# 취약 포인트 1: 문자열 포맷팅으로 쿼리 조합 (SQLi 가능)
@app.route("/search")
def search():
    user_id = request.args.get("id", "")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # 의도적 취약 코드
    query = f"SELECT id, username, email, role FROM users WHERE id = {user_id}"
    try:
        c.execute(query)
        rows = c.fetchall()
        result = [{"id": r[0], "username": r[1], "email": r[2], "role": r[3]} for r in rows]
    except Exception as e:
        result = {"error": str(e), "query": query}
    conn.close()
    return jsonify(result)


# 취약 포인트 2: 로그인 우회 (1=1 트릭)
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # 의도적 취약 코드
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    try:
        c.execute(query)
        row = c.fetchone()
        if row:
            return jsonify({"status": "success", "user": row[1], "role": row[4], "flag": row[5]})
        else:
            return jsonify({"status": "failed", "query": query}), 401
    except Exception as e:
        return jsonify({"error": str(e), "query": query}), 500
    finally:
        conn.close()


# 취약 포인트 3: UNION 기반 SQLi
@app.route("/users")
def users():
    order = request.args.get("order", "id")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # 의도적 취약 코드 (ORDER BY에 직접 삽입)
    query = f"SELECT id, username, email FROM users ORDER BY {order}"
    try:
        c.execute(query)
        rows = c.fetchall()
        result = [{"id": r[0], "username": r[1], "email": r[2]} for r in rows]
    except Exception as e:
        result = {"error": str(e)}
    conn.close()
    return jsonify(result)


# 취약 포인트 4: 블라인드 SQLi
@app.route("/api/user")
def api_user():
    name = request.args.get("name", "")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # 의도적 취약 코드
    query = f"SELECT username FROM users WHERE username='{name}'"
    try:
        c.execute(query)
        row = c.fetchone()
        if row:
            return jsonify({"exists": True, "username": row[0]})
        else:
            return jsonify({"exists": False})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
