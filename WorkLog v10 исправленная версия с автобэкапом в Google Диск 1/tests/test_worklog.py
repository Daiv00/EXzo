"""Проверка WorkLog v10: запуск, вход, смены и автобэкап через фальшивый Apps Script.

Запуск:  python tests/test_worklog.py
Скрипт поднимает приложение на свободном порту, поднимает локальный «Apps Script»
и проверяет весь путь данных до бэкапа. Ничего в интернет не уходит.
"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SECRET = "тестовый-секрет-1234567890"
received = []


class FakeAppsScript(BaseHTTPRequestHandler):
    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        body = json.loads(raw.decode("utf-8"))
        if body.get("secret") != SECRET:
            answer = {"ok": False, "error": "Неверный секретный ключ"}
        else:
            received.append(body)
            answer = {"ok": True, "folder": body.get("folder"),
                      "folderUrl": "https://drive.google.com/drive/folders/TEST",
                      "fileUrl": "https://drive.google.com/file/d/TEST"}
        data = json.dumps(answer).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Client:
    """Мини-клиент с cookie и CSRF-заголовком."""

    def __init__(self, base):
        self.base = base
        self.cookies = {}

    def request(self, method, path, payload=None):
        url = self.base + path
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        if data:
            req.add_header("Content-Type", "application/json")
        if self.cookies:
            req.add_header("Cookie", "; ".join(f"{k}={v}" for k, v in self.cookies.items()))
        if "worklog_csrf" in self.cookies:
            req.add_header("X-CSRF-Token", self.cookies["worklog_csrf"])
        try:
            resp = urllib.request.urlopen(req, timeout=15)
            status, body = resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            status, body, resp = exc.code, exc.read(), exc
        for header in resp.headers.get_all("Set-Cookie") or []:
            name, _, rest = header.partition("=")
            self.cookies[name.strip()] = rest.split(";")[0]
        try:
            return status, json.loads(body.decode("utf-8"))
        except ValueError:
            return status, body.decode("utf-8", "replace")


def check(label, condition, detail=""):
    mark = "✓" if condition else "✕"
    print(f"  {mark} {label}" + (f" — {detail}" if detail and not condition else ""))
    if not condition:
        raise SystemExit(1)


def main():
    hook_port, app_port = free_port(), free_port()
    server = HTTPServer(("127.0.0.1", hook_port), FakeAppsScript)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    tmp = tempfile.mkdtemp(prefix="worklog-test-")
    env = dict(os.environ, WORKLOG_DATA_DIR=tmp, PORT=str(app_port),
               SECRET_KEY="test-secret-key", COOKIE_SECURE="auto")
    proc = subprocess.Popen([sys.executable, str(ROOT / "app.py")], env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    base = f"http://127.0.0.1:{app_port}"
    try:
        for _ in range(80):
            try:
                urllib.request.urlopen(base + "/api/health", timeout=2)
                break
            except Exception:
                if proc.poll() is not None:
                    print(proc.stdout.read())
                    raise SystemExit("приложение не запустилось")
                time.sleep(0.25)

        print("Запуск и здоровье")
        c = Client(base)
        status, health = c.request("GET", "/api/health")
        check("/api/health отвечает", status == 200 and health.get("ok"))
        check("версия 10", health.get("version") == 10, str(health))

        print("Регистрация и вход")
        c.request("GET", "/api/csrf")
        status, out = c.request("POST", "/api/register", {"username": "admin", "password": "admin12345"})
        check("первый пользователь стал админом", status == 200, str(out))
        status, me = c.request("GET", "/api/me")
        check("сессия живёт", me.get("logged_in") and me.get("is_admin"), str(me))

        print("Настройка автобэкапа")
        status, out = c.request("POST", "/api/admin/backup/settings",
                                {"webhook_url": f"http://127.0.0.1:{hook_port}/exec",
                                 "secret": SECRET, "folder_name": "WorkLog — Тест", "enabled": True})
        check("чужие домены отклоняются", status == 400, "проверка ссылки не сработала")

        # Разрешаем локальный адрес только для теста: подменяем проверку в БД напрямую.
        import sqlite3
        sys.path.insert(0, str(ROOT))
        os.environ["WORKLOG_DATA_DIR"] = tmp
        os.environ["SECRET_KEY"] = "test-secret-key"  # тот же ключ, что у приложения
        import importlib
        mod = importlib.import_module("app")
        enc = mod.encrypt_secret(SECRET)
        with sqlite3.connect(Path(tmp) / "worklog.db") as con:
            con.execute("""INSERT INTO backup_config(id,webhook_url,secret_enc,folder_name,enabled)
                           VALUES(1,?,?,?,1) ON CONFLICT(id) DO UPDATE SET webhook_url=excluded.webhook_url,
                           secret_enc=excluded.secret_enc,folder_name=excluded.folder_name,enabled=1""",
                        (f"http://127.0.0.1:{hook_port}/exec", enc, "WorkLog — Тест"))
        status, out = c.request("POST", "/api/backup/test")
        check("проверка связи проходит", status == 200 and out.get("ok"), str(out))
        check("папка создана", received and received[-1].get("ping"), str(received[-1:]))

        print("Смены и автоматическая копия")
        status, shift = c.request("POST", "/api/shifts/start")
        check("смена открылась", status == 201, str(shift))
        status, done = c.request("POST", f"/api/shifts/{shift['id']}/finish", {"tips": 500, "note": "тест", "role": "Бармен"})
        check("смена закрылась", status == 200 and done.get("tips") == 500, str(done))

        def with_tips():
            return [r for r in received
                    if not r.get("ping") and r["data"]["totals"]["tips"] == 500]

        for _ in range(40):
            if with_tips():
                break
            time.sleep(0.25)
        data_posts = [r for r in received if not r.get("ping")]
        check("копия ушла в «Диск»", bool(data_posts), "фоновая отправка не сработала")
        check("копия обновилась после закрытия смены", bool(with_tips()), "свежие данные не дошли")
        payload = with_tips()[-1]
        check("имя файла по логину", payload["filename"] == "admin.json", payload["filename"])
        check("смены внутри JSON", payload["data"]["shifts"] and payload["data"]["version"] == 10)
        check("итоги посчитаны", payload["data"]["totals"]["tips"] == 500, str(payload["data"]["totals"]))

        print("Ручной прогон и статус")
        status, out = c.request("POST", "/api/backup/run")
        check("копии всех пользователей", status == 200 and out.get("ok"), str(out))
        status, st = c.request("GET", "/api/backup/status")
        check("статус: последняя отправка успешна", st.get("last_status") == "ok", str(st))
        check("ссылка на папку сохранена", "drive.google.com" in (st.get("folder_url") or ""), str(st))

        print("Скачивание и отключение")
        status, raw = c.request("GET", "/api/backup")
        check("JSON скачивается", status == 200 and "shifts" in str(raw))
        status, out = c.request("POST", "/api/admin/backup/disconnect")
        check("автобэкап отключается", status == 200 and not out["backup"]["configured"], str(out))

        print("Подсказки при привязке Диска")
        # Поля можно проверять до сохранения: они уходят в тело запроса.
        status, out = c.request("POST", "/api/backup/test",
                                {"webhook_url": "https://script.google.com/macros/s/abc/dev", "secret": "ключ"})
        check("ссылка /dev отклоняется с объяснением", status == 400 and "/dev" in out.get("error", ""), str(out))
        status, out = c.request("POST", "/api/backup/test", {"webhook_url": "https://example.com/exec", "secret": "ключ"})
        check("чужой домен отклоняется с объяснением", status == 400 and "script.google.com" in out.get("error", ""), str(out))
        status, out = c.request("POST", "/api/backup/test", {})
        check("пустые поля объясняют, что нужна ссылка /exec",
              status == 400 and "/exec" in out.get("error", ""), str(out))

        print("\nВсе проверки WorkLog пройдены ✓")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        server.shutdown()


if __name__ == "__main__":
    main()
