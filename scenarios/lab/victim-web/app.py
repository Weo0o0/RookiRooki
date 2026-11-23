#!/usr/bin/env python3
"""의도적으로 취약한 실습용 웹 앱.

팀 Docker 실습망(mini-siem-net)에서 SQL 인젝션·XSS 트래픽을
만들고, 성공한 SQLi는 HTTP 200을 돌려 SEV1 격상 시연에 쓰입니다.
실제 서비스에 쓰지 마세요. 실제 비밀번호·개인정보는 넣지 마세요.
"""

from __future__ import annotations

import html
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

DB_PATH = "/tmp/lab.db"
LISTEN = ("0.0.0.0", 80)

# 실습용 가짜 계정. 실제 비밀번호가 아닙니다.
LAB_USER = "labuser"
LAB_PASS = "labpass"


def init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS users ("
            "id INTEGER PRIMARY KEY, username TEXT, password TEXT)"
        )
        conn.execute("DELETE FROM users")
        conn.execute(
            "INSERT INTO users(username, password) VALUES (?, ?)",
            (LAB_USER, LAB_PASS),
        )
        conn.commit()
    finally:
        conn.close()


def query_login(username: str, password: str):
    """문자열을 그대로 이어 붙여 SQL 인젝션이 되게 둔 실습 코드."""
    conn = sqlite3.connect(DB_PATH)
    try:
        sql = (
            "SELECT id, username FROM users "
            f"WHERE username = '{username}' AND password = '{password}'"
        )
        return conn.execute(sql).fetchone(), None
    except sqlite3.Error as exc:
        return None, str(exc)
    finally:
        conn.close()


INDEX_HTML = """<!doctype html>
<html lang="ko">
<head><meta charset="utf-8"><title>Mini-SIEM lab web</title></head>
<body>
  <h1>victim-web (실습 전용)</h1>
  <p>이 사이트는 팀 격리망에서만 쓰는 취약 실습 앱입니다.</p>
  <h2>로그인 (SQL 인젝션 실습)</h2>
  <form method="get" action="/login">
    <label>username <input name="username" value="labuser"></label><br>
    <label>password <input name="password" type="password"></label><br>
    <button type="submit">로그인</button>
  </form>
  <p>정상: <code>labuser / labpass</code> (가짜 실습 계정)</p>
  <p>성공 시연 예:
    <code>/login?username=admin' OR '1'='1' --&amp;password=test</code>
    → HTTP 200</p>
  <p>실패 예: 틀린 비밀번호 → HTTP 403 (격상 없이 SEV3 시연용)</p>
  <h2>검색 (XSS 실습)</h2>
  <form method="get" action="/search">
    <label>q <input name="q"></label>
    <button type="submit">검색</button>
  </form>
</body>
</html>
"""


class LabHandler(BaseHTTPRequestHandler):
    server_version = "MiniSiemLabWeb/1.0"

    def log_message(self, fmt: str, *args) -> None:
        print("%s - %s" % (self.address_string(), fmt % args), flush=True)

    def _send(self, status: int, body: str, content_type: str = "text/html; charset=utf-8") -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query, keep_blank_values=True)

        if path == "/" or path == "/index.html":
            self._send(200, INDEX_HTML)
            return
        if path == "/health":
            self._send(200, "ok\n", "text/plain; charset=utf-8")
            return
        if path == "/login":
            username = params.get("username", [""])[0]
            password = params.get("password", [""])[0]
            row, err = query_login(username, password)
            if err:
                self._send(
                    500,
                    f"<h1>500</h1><p>SQL error (lab)</p><pre>{html.escape(err)}</pre>",
                )
                return
            if row:
                self._send(
                    200,
                    "<h1>200 login ok</h1>"
                    f"<p>user={html.escape(str(row[1]))}</p>"
                    "<p>이 200 응답이 SQLi SEV1 격상 시연에 필요합니다.</p>",
                )
                return
            self._send(403, "<h1>403 login failed</h1><p>계정 또는 비밀번호가 틀립니다.</p>")
            return
        if path == "/search":
            q = params.get("q", [""])[0]
            # 반사형 XSS: 검색어를 그대로 응답에 넣음. 응답은 항상 200.
            self._send(
                200,
                "<h1>검색 결과</h1>"
                f"<p>q={q}</p>",
            )
            return
        self._send(404, "<h1>404</h1>")


def main() -> None:
    init_db()
    httpd = ThreadingHTTPServer(LISTEN, LabHandler)
    print("victim-web listening on 0.0.0.0:80", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
