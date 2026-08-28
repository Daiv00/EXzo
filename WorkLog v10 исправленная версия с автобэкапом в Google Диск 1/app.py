from flask import Flask, jsonify, render_template, request, redirect, session, url_for, send_file, make_response
from werkzeug.security import generate_password_hash as werkzeug_generate, check_password_hash as werkzeug_check
from werkzeug.middleware.proxy_fix import ProxyFix
from pathlib import Path
from datetime import datetime, date
from urllib.parse import urlparse
import sqlite3, os, io, json, secrets, hashlib, re, time, threading, urllib.request, urllib.error

BASE_DIR = Path(__file__).resolve().parent

DATA_DIR = Path(os.environ.get("WORKLOG_DATA_DIR") or BASE_DIR)
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "worklog.db"

app = Flask(__name__, template_folder=str(BASE_DIR/"templates"), static_folder=str(BASE_DIR/"static"))
# Render и PySpace IDE отдают приложение через обратный прокси. Доверяем одному
# «прыжку», включая префикс пути — так приложение работает и по адресу
# /live/<токен>/ внутри IDE, и на своём домене Render.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_urlsafe(48)

# COOKIE_SECURE=auto (по умолчанию): флаг Secure ставится только на HTTPS. Так
# вход работает и на http://localhost, и внутри IDE, и на Render по HTTPS.
COOKIE_SECURE_MODE = (os.environ.get("COOKIE_SECURE") or "auto").strip().lower()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=COOKIE_SECURE_MODE in {"1", "true", "yes"},
    MAX_CONTENT_LENGTH=256 * 1024,
)
# Разрешить встраивание в iframe (предпросмотр PySpace IDE) — ALLOW_EMBED=1.
ALLOW_EMBED = (os.environ.get("ALLOW_EMBED") or "0").strip() in {"1", "true", "yes"}


def cookie_secure():
    if COOKIE_SECURE_MODE in {"1", "true", "yes"}:
        return True
    if COOKIE_SECURE_MODE in {"0", "false", "no"}:
        return False
    return bool(request.is_secure)


@app.before_request
def _sync_cookie_secure():
    # Session-cookie читает конфиг в момент ответа, поэтому обновляем его здесь.
    app.config["SESSION_COOKIE_SECURE"] = cookie_secure()

# Small in-process rate limiter for authentication endpoints. It is intentionally
# conservative; a reverse proxy/WAF should still be used in production.
_login_attempts = {}

def _rate_limited(ip, bucket="login", limit=8, window=300):
    now=time.time(); key=(bucket, ip)
    arr=[t for t in _login_attempts.get(key, []) if now-t < window]
    if len(arr) >= limit:
        _login_attempts[key]=arr
        return True
    arr.append(now); _login_attempts[key]=arr
    return False

def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    return con

def init_db():
    with db() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS users(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT NOT NULL UNIQUE,
          password_hash TEXT NOT NULL,
          is_admin INTEGER NOT NULL DEFAULT 0,
          created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS shifts(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          work_date TEXT NOT NULL,
          start_time TEXT NOT NULL,
          end_time TEXT,
          role TEXT NOT NULL DEFAULT 'Официант',
          tips REAL NOT NULL DEFAULT 0,
          note TEXT DEFAULT '',
          status TEXT NOT NULL DEFAULT 'completed',
          created_at TEXT DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_shifts_user_date ON shifts(user_id, work_date);
        CREATE TABLE IF NOT EXISTS backup_config(
          id INTEGER PRIMARY KEY CHECK (id=1),
          webhook_url TEXT NOT NULL DEFAULT '',
          secret_enc TEXT NOT NULL DEFAULT '',
          folder_name TEXT NOT NULL DEFAULT 'WorkLog — Смены',
          enabled INTEGER NOT NULL DEFAULT 1,
          last_status TEXT NOT NULL DEFAULT '',
          last_error TEXT NOT NULL DEFAULT '',
          last_ok_at TEXT,
          last_try_at TEXT,
          folder_url TEXT NOT NULL DEFAULT '',
          updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        """)
        # Мягкие миграции для баз, созданных прошлыми версиями архива.
        cols={r[1] for r in con.execute("PRAGMA table_info(users)").fetchall()}
        if "is_admin" not in cols: con.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0")
        bcols={r[1] for r in con.execute("PRAGMA table_info(backup_config)").fetchall()}
        for name, ddl in (
            ("folder_url", "ALTER TABLE backup_config ADD COLUMN folder_url TEXT NOT NULL DEFAULT ''"),
            ("last_try_at", "ALTER TABLE backup_config ADD COLUMN last_try_at TEXT"),
        ):
            if name not in bcols: con.execute(ddl)
        # Старые таблицы Service Account больше не нужны.
        for legacy in ("google_tokens", "drive_backups", "drive_config", "app_settings"):
            con.execute(f"DROP TABLE IF EXISTS {legacy}")
        # Bootstrap the admin role once from the legacy environment setting.
        admin_name=os.environ.get("ADMIN_USERNAME", "admin").strip()
        if admin_name:
            con.execute("UPDATE users SET is_admin=1 WHERE username=?", (admin_name,))
        if con.execute("SELECT COUNT(*) FROM users WHERE is_admin=1").fetchone()[0] == 0:
            first=con.execute("SELECT id FROM users ORDER BY id LIMIT 1").fetchone()
            if first: con.execute("UPDATE users SET is_admin=1 WHERE id=?", (first[0],))


def current_user():
    uid = session.get("user_id")
    if not uid: return None
    with db() as con:
        return con.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()

def is_admin(u): return bool(u and int(u["is_admin"] or 0)==1)

def login_required_page(): return redirect(url_for("auth_page"))

CSRF_COOKIE = "worklog_csrf"

def csrf_token():
    # Keep CSRF independent from the Flask session. This is important for
    # reverse-proxied Web Preview environments where a session may be rotated
    # during login or between preview requests.
    token = request.cookies.get(CSRF_COOKIE)
    if not token or len(token) < 32:
        token = secrets.token_urlsafe(32)
    return token

@app.before_request
def security_gate():
    if request.method not in {"POST","PUT","PATCH","DELETE"} or request.path in {"/api/login","/api/register"}:
        return None

    # PySpace Web Preview can be embedded/proxied in a way that prevents
    # the CSRF cookie from being sent. Prefer a strict same-origin check
    # when the browser supplies Origin/Referer, and use the CSRF token when
    # available. This keeps protection effective without breaking preview.
    origin = request.headers.get("Origin")
    if origin:
        from urllib.parse import urlparse
        try:
            o = urlparse(origin)
            if o.scheme != request.scheme or o.netloc != request.host:
                return jsonify(error="Проверка безопасности не пройдена."), 403
        except Exception:
            return jsonify(error="Проверка безопасности не пройдена."), 403

    referer = request.headers.get("Referer")
    if referer and not origin:
        from urllib.parse import urlparse
        try:
            r = urlparse(referer)
            if r.scheme != request.scheme or r.netloc != request.host:
                return jsonify(error="Проверка безопасности не пройдена."), 403
        except Exception:
            return jsonify(error="Проверка безопасности не пройдена."), 403

    supplied = request.headers.get("X-CSRF-Token", "")
    expected = request.cookies.get(CSRF_COOKIE, "")
    if expected and supplied:
        if len(supplied) > 200 or not secrets.compare_digest(supplied, expected):
            return jsonify(error="Проверка безопасности не пройдена. Обнови страницу и попробуй снова."), 403
    # If the proxy/browser strips the CSRF cookie/header, same-origin Origin
    # or Referer validation above remains the fallback protection.

@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"]="nosniff"
    if not ALLOW_EMBED:
        resp.headers["X-Frame-Options"]="DENY"
    resp.headers["Referrer-Policy"]="same-origin"
    resp.headers["Permissions-Policy"]="camera=(), microphone=(), geolocation=()"
    frame_ancestors = "*" if ALLOW_EMBED else "'none'"
    resp.headers["Content-Security-Policy"]=("default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        f"script-src 'self'; connect-src 'self'; frame-ancestors {frame_ancestors}; base-uri 'self'; form-action 'self'")
    if request.is_secure:
        resp.headers["Strict-Transport-Security"]="max-age=31536000; includeSubDomains"
    return resp

def hours_between(start, end):
    if not start or not end: return 0
    try:
        a=datetime.strptime(start,"%H:%M"); b=datetime.strptime(end,"%H:%M")
        mins=(b-a).total_seconds()/60
        if mins < 0: mins += 1440
        return round(mins/60,2)
    except ValueError: return 0

def serialize(r):
    x=dict(r); x["hours"]=hours_between(x["start_time"],x["end_time"]); return x

def valid_text(v, max_len=300):
    s=str(v or "").strip()
    return s if len(s)<=max_len else None

# ---- password / encryption helpers ----
def password_hash(password):
    try:
        from argon2 import PasswordHasher
        return "argon2$" + PasswordHasher(time_cost=2,memory_cost=19456,parallelism=1).hash(password)
    except ImportError:
        return werkzeug_generate(password, method="scrypt")

def password_check(stored,password):
    if stored.startswith("argon2$"):
        try:
            from argon2 import PasswordHasher
            return PasswordHasher(time_cost=2,memory_cost=19456,parallelism=1).verify(stored[7:], password)
        except Exception: return False
    try: return werkzeug_check(stored,password)
    except Exception: return False

def password_needs_upgrade(stored): return not stored.startswith("argon2$")

def crypto():
    from cryptography.fernet import Fernet
    digest=hashlib.sha256(app.secret_key.encode()).digest()
    return Fernet(__import__('base64').urlsafe_b64encode(digest))

def encrypt_secret(value): return crypto().encrypt(value.encode()).decode() if value else ""
def decrypt_secret(value):
    if not value: return ""
    try: return crypto().decrypt(value.encode()).decode()
    except Exception: return ""

# ---- pages / auth ----
@app.get("/")
def index():
    if not current_user(): return login_required_page()
    return render_template("index.html", user=current_user()["username"], is_admin=is_admin(current_user()))

@app.get("/login")
def auth_page():
    if current_user(): return redirect(url_for("index"))
    return render_template("auth.html")

@app.get("/api/csrf")
def api_csrf():
    token = csrf_token()
    resp = make_response(jsonify(token=token))
    resp.set_cookie(CSRF_COOKIE, token, httponly=False, secure=cookie_secure(), samesite="Lax", path=request.headers.get("X-Forwarded-Prefix") or "/")
    return resp

@app.post("/api/register")
def register():
    ip=request.remote_addr or "unknown"
    if _rate_limited(ip,"auth",8,300): return jsonify(error="Слишком много попыток. Попробуй позже."),429
    data=request.get_json(silent=True) or {}; username=valid_text(data.get("username"),40); password=str(data.get("password", ""))
    if not username or len(username)<3 or len(password)<8: return jsonify(error="Логин минимум 3 символа, пароль минимум 8"),400
    if not re.fullmatch(r"[A-Za-zА-Яа-яЁё0-9_.-]+",username): return jsonify(error="В логине разрешены буквы, цифры, _, . и -"),400
    try:
        with db() as con:
            count=con.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            cur=con.execute("INSERT INTO users(username,password_hash,is_admin) VALUES(?,?,?)",(username,password_hash(password),1 if count==0 else 0)); uid=cur.lastrowid
        session.clear(); session["user_id"]=uid; csrf_token(); auto_backup(uid)
        return jsonify(ok=True)
    except sqlite3.IntegrityError: return jsonify(error="Такой логин уже занят"),409

@app.post("/api/login")
def login():
    ip=request.remote_addr or "unknown"
    if _rate_limited(ip,"auth",8,300): return jsonify(error="Слишком много попыток. Попробуй позже."),429
    data=request.get_json(silent=True) or {}; username=valid_text(data.get("username"),40); password=str(data.get("password",""))
    with db() as con: user=con.execute("SELECT * FROM users WHERE username=?",(username or "",)).fetchone()
    if not user or not password_check(user["password_hash"],password): return jsonify(error="Неверный логин или пароль"),401
    session.clear(); session["user_id"]=user["id"]; csrf_token()
    if password_needs_upgrade(user["password_hash"]):
        with db() as con: con.execute("UPDATE users SET password_hash=? WHERE id=?",(password_hash(password),user["id"]))
    return jsonify(ok=True)

@app.post("/api/logout")
def logout(): session.clear(); return jsonify(ok=True)

@app.get("/api/me")
def me():
    u=current_user(); return jsonify(logged_in=bool(u),username=u["username"] if u else None,is_admin=is_admin(u),csrf=session.get("csrf_token"))

# ---- shifts ----
def require_user():
    u=current_user(); return u

@app.get("/api/shifts")
def shifts():
    u=require_user()
    if not u:return jsonify(error="Не авторизован"),401
    q=str(request.args.get("q",""))[:100].strip().lower(); month=str(request.args.get("month",""))[:7].strip()
    sql="SELECT * FROM shifts WHERE user_id=?"; params=[u["id"]]
    if month: sql+=" AND substr(work_date,1,7)=?"; params.append(month)
    if q:
        like=f"%{q}%"; sql+=" AND (lower(work_date) LIKE ? OR lower(role) LIKE ? OR lower(note) LIKE ? OR printf('%.2f',tips) LIKE ?)"; params += [like,like,like,like]
    sql+=" ORDER BY work_date DESC, COALESCE(end_time,start_time) DESC, id DESC"
    with db() as con: rows=con.execute(sql,params).fetchall()
    return jsonify([serialize(r) for r in rows])

@app.get("/api/active")
def active():
    u=require_user()
    if not u:return jsonify(error="Не авторизован"),401
    with db() as con:r=con.execute("SELECT * FROM shifts WHERE user_id=? AND status='active' ORDER BY id DESC LIMIT 1",(u["id"],)).fetchone()
    return jsonify(serialize(r) if r else None)

@app.post("/api/shifts/start")
def start_shift():
    u=require_user()
    if not u:return jsonify(error="Не авторизован"),401
    with db() as con:
        if con.execute("SELECT id FROM shifts WHERE user_id=? AND status='active'",(u["id"],)).fetchone(): return jsonify(error="У тебя уже открыта смена"),409
        now=datetime.now(); cur=con.execute("INSERT INTO shifts(user_id,work_date,start_time,role,status) VALUES(?,?,?,?, 'active')",(u["id"],now.strftime("%Y-%m-%d"),now.strftime("%H:%M"),"Официант")); r=con.execute("SELECT * FROM shifts WHERE id=?",(cur.lastrowid,)).fetchone()
    out=serialize(r); out["backup"]=auto_backup(u["id"]); return jsonify(out),201

@app.post("/api/shifts/<int:sid>/finish")
def finish_shift(sid):
    u=require_user()
    if not u:return jsonify(error="Не авторизован"),401
    data=request.get_json(silent=True) or {}
    try: tips=float(data.get("tips",0) or 0)
    except: return jsonify(error="Чаевые должны быть числом"),400
    if tips<0 or tips>100000000:return jsonify(error="Некорректная сумма чаевых"),400
    note=valid_text(data.get("note"),1000); role=valid_text(data.get("role","Официант"),60) or "Официант"
    if note is None:return jsonify(error="Заметка слишком длинная"),400
    end=datetime.now().strftime("%H:%M")
    with db() as con:
        r=con.execute("SELECT * FROM shifts WHERE id=? AND user_id=? AND status='active'",(sid,u["id"])).fetchone()
        if not r:return jsonify(error="Активная смена не найдена"),404
        con.execute("UPDATE shifts SET end_time=?,tips=?,note=?,role=?,status='completed' WHERE id=? AND user_id=?",(end,tips,note,role,sid,u["id"])); r=con.execute("SELECT * FROM shifts WHERE id=?",(sid,)).fetchone()
    out=serialize(r); out["backup"]=auto_backup(u["id"]); return jsonify(out)

@app.post("/api/shifts")
def create_shift():
    u=require_user()
    if not u:return jsonify(error="Не авторизован"),401
    data=request.get_json(silent=True) or {}; work_date=valid_text(data.get("work_date"),10); start=valid_text(data.get("start_time"),5); end=valid_text(data.get("end_time"),5); role=valid_text(data.get("role","Официант"),60) or "Официант"; note=valid_text(data.get("note"),1000)
    try: tips=float(data.get("tips",0) or 0)
    except: return jsonify(error="Некорректные чаевые"),400
    if note is None or tips<0 or tips>100000000:return jsonify(error="Некорректные данные"),400
    try: date.fromisoformat(work_date); datetime.strptime(start,"%H:%M"); datetime.strptime(end,"%H:%M")
    except (ValueError,TypeError): return jsonify(error="Некорректная дата или время"),400
    with db() as con:
        cur=con.execute("INSERT INTO shifts(user_id,work_date,start_time,end_time,role,tips,note,status) VALUES(?,?,?,?,?,?,?,'completed')",(u["id"],work_date,start,end,role,tips,note)); r=con.execute("SELECT * FROM shifts WHERE id=?",(cur.lastrowid,)).fetchone()
    out=serialize(r); out["backup"]=auto_backup(u["id"]); return jsonify(out),201

@app.delete("/api/shifts/<int:sid>")
def delete_shift(sid):
    u=require_user()
    if not u:return jsonify(error="Не авторизован"),401
    with db() as con: cur=con.execute("DELETE FROM shifts WHERE id=? AND user_id=?",(sid,u["id"]))
    if not cur.rowcount:return jsonify(error="Смена не найдена"),404
    return jsonify(ok=True,backup=auto_backup(u["id"]))

@app.get("/api/summary")
def summary():
    u=require_user()
    if not u:return jsonify(error="Не авторизован"),401
    month=request.args.get("month") or date.today().strftime("%Y-%m")
    with db() as con: rows=con.execute("SELECT * FROM shifts WHERE user_id=? AND substr(work_date,1,7)=? AND status='completed'",(u["id"],month)).fetchall()
    return jsonify(month=month,shifts=len(rows),hours=round(sum(hours_between(r["start_time"],r["end_time"]) for r in rows),2),tips=round(sum(float(r["tips"] or 0) for r in rows),2))

@app.get("/api/backup")
def backup():
    u=require_user()
    if not u:return jsonify(error="Не авторизован"),401
    raw=json.dumps(_user_payload(u["id"]),ensure_ascii=False,indent=2).encode("utf-8")
    return send_file(io.BytesIO(raw),as_attachment=True,download_name=f"worklog-{u['username']}-{date.today()}.json",mimetype="application/json")

# ---- настройки администратора ----
def backup_row():
    with db() as con:
        row = con.execute("SELECT * FROM backup_config WHERE id=1").fetchone()
    return row

def backup_configured():
    row = backup_row()
    return bool(row and row["webhook_url"])

def backup_public():
    row = backup_row()
    if not row:
        return {"configured": False, "enabled": False, "webhook_set": False, "folder_name": "WorkLog — Смены",
                "secret_set": False, "last_status": "", "last_error": "", "last_ok_at": None, "last_try_at": None,
                "folder_url": ""}
    return {"configured": bool(row["webhook_url"]), "enabled": bool(row["enabled"]), "webhook_set": bool(row["webhook_url"]),
            "webhook_host": urlparse(row["webhook_url"]).netloc if row["webhook_url"] else "",
            "secret_set": bool(row["secret_enc"]), "folder_name": row["folder_name"] or "WorkLog — Смены",
            "last_status": row["last_status"] or "", "last_error": row["last_error"] or "",
            "last_ok_at": row["last_ok_at"], "last_try_at": row["last_try_at"], "folder_url": row["folder_url"] or ""}

@app.get("/api/admin/settings")
def admin_settings_get():
    u=current_user()
    if not is_admin(u):return jsonify(error="Доступ только для администратора"),403
    return jsonify(username=u["username"], backup=backup_public())

@app.post("/api/admin/account")
def admin_account():
    u=current_user()
    if not is_admin(u):return jsonify(error="Доступ только для администратора"),403
    data=request.get_json(silent=True) or {}; current=str(data.get("current_password","")); new_username=valid_text(data.get("username"),40); new_password=str(data.get("new_password","")); confirm=str(data.get("confirm_password",""))
    if not password_check(u["password_hash"],current):return jsonify(error="Текущий пароль неверный"),400
    if not new_username or not re.fullmatch(r"[A-Za-zА-Яа-яЁё0-9_.-]+",new_username):return jsonify(error="Некорректный логин"),400
    if new_password and (len(new_password)<8 or new_password!=confirm):return jsonify(error="Новый пароль: минимум 8 символов, подтверждение должно совпадать"),400
    try:
        with db() as con: con.execute("UPDATE users SET username=?, password_hash=? WHERE id=?",(new_username,password_hash(new_password) if new_password else u["password_hash"],u["id"]))
        return jsonify(ok=True,username=new_username)
    except sqlite3.IntegrityError:return jsonify(error="Такой логин уже занят"),409

@app.post("/api/admin/backup/settings")
def admin_backup_settings():
    """Сохранить адрес веб-приложения Apps Script и общий секрет."""
    u=current_user()
    if not is_admin(u):return jsonify(error="Доступ только для администратора"),403
    data=request.get_json(silent=True) or {}
    url=(valid_text(data.get("webhook_url"),400) or "").strip()
    secret=str(data.get("secret","")).strip()
    folder=valid_text(data.get("folder_name"),100) or "WorkLog — Смены"
    enabled=bool(data.get("enabled",True))
    if url:
        bad=url_problem(url)
        if bad:return jsonify(error=bad),400
    old=backup_row()
    secret_enc=encrypt_secret(secret) if secret else (old["secret_enc"] if old else "")
    if url and not secret_enc:
        return jsonify(error="Укажи секретный ключ — тот же, что в Apps Script"),400
    save_backup_config(url, secret_enc, folder, enabled)
    return jsonify(ok=True, backup=backup_public())

def url_problem(url):
    """Понятное объяснение, если ссылка не похожа на адрес веб-приложения Apps Script."""
    parsed=urlparse(url)
    if parsed.scheme!="https" or not parsed.netloc.endswith("google.com"):
        return ("Это не адрес веб-приложения. Нужна ссылка с script.google.com: в редакторе скрипта "
                "нажми «Развернуть» → «Новое развёртывание» → тип «Веб-приложение» и скопируй "
                "выданный адрес — он выглядит как https://script.google.com/macros/s/…/exec")
    if not parsed.path.rstrip("/").endswith("/exec"):
        if parsed.path.rstrip("/").endswith("/dev"):
            return ("Это ссылка /dev — она работает только для тебя в браузере. Скопируй адрес "
                    "развёртывания, который заканчивается на /exec.")
        return ("Ссылка должна заканчиваться на /exec. Скопируй её из окна «Развёртывание "
                "обновлено» (поле «URL веб-приложения»), а не из адресной строки редактора.")
    return ""

def save_backup_config(url, secret_enc, folder, enabled):
    with db() as con:
        con.execute("""INSERT INTO backup_config(id,webhook_url,secret_enc,folder_name,enabled,updated_at)
                       VALUES(1,?,?,?,?,CURRENT_TIMESTAMP)
                       ON CONFLICT(id) DO UPDATE SET webhook_url=excluded.webhook_url,secret_enc=excluded.secret_enc,
                         folder_name=excluded.folder_name,enabled=excluded.enabled,updated_at=CURRENT_TIMESTAMP""",
                    (url, secret_enc, folder, 1 if enabled else 0))

@app.post("/api/admin/backup/disconnect")
def admin_backup_disconnect():
    u=current_user()
    if not is_admin(u):return jsonify(error="Доступ только для администратора"),403
    with db() as con:
        con.execute("""UPDATE backup_config SET webhook_url='',secret_enc='',enabled=0,last_status='',last_error='',
                       folder_url='',updated_at=CURRENT_TIMESTAMP WHERE id=1""")
    return jsonify(ok=True, backup=backup_public())

# ---- автобэкап в Google Диск через Apps Script ----
# Никакого Google Cloud: админ разворачивает маленький скрипт (apps_script/Code.gs)
# как веб-приложение и вставляет его ссылку и секрет в «Настройки». Приложение
# просто отправляет JSON POST-запросом, а скрипт сам пишет файл в Диск.
BACKUP_TIMEOUT = float(os.environ.get("BACKUP_TIMEOUT", "20"))

def _user_payload(user_id):
    """JSON одного пользователя: он уходит и в Диск, и в кнопку «Скачать»."""
    with db() as con:
        user = con.execute("SELECT username FROM users WHERE id=?", (user_id,)).fetchone()
        rows = con.execute("""SELECT id,work_date,start_time,end_time,role,tips,note,status,created_at
                              FROM shifts WHERE user_id=? ORDER BY work_date,start_time""", (user_id,)).fetchall()
    shifts = [serialize(r) for r in rows]
    return {"app": "WorkLog", "version": 10, "user": user["username"] if user else f"user-{user_id}",
            "exported_at": datetime.now().isoformat(timespec="seconds"),
            "totals": {"shifts": len(shifts),
                       "hours": round(sum(x["hours"] for x in shifts), 2),
                       "tips": round(sum(float(x["tips"] or 0) for x in shifts), 2)},
            "shifts": shifts}

def safe_file_name(username, user_id):
    name = "".join(c if c.isalnum() or c in " ._-" else "_" for c in (username or "")).strip()
    return (name or f"user-{user_id}") + ".json"

def _record_backup(status, error="", folder_url=""):
    with db() as con:
        con.execute("""UPDATE backup_config SET last_status=?,last_error=?,last_try_at=CURRENT_TIMESTAMP,
                       last_ok_at=CASE WHEN ?='ok' THEN CURRENT_TIMESTAMP ELSE last_ok_at END,
                       folder_url=CASE WHEN ?<>'' THEN ? ELSE folder_url END WHERE id=1""",
                    (status, error[:400], status, folder_url, folder_url))

def _post_json(url, payload):
    raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(url, data=raw, method="POST",
                                headers={"Content-Type": "application/json; charset=utf-8"})
    with urllib.request.urlopen(req, timeout=BACKUP_TIMEOUT) as resp:
        body = resp.read(64 * 1024).decode("utf-8", "replace")
    try:
        return json.loads(body)
    except ValueError:
        raise RuntimeError("Apps Script ответил не JSON: " + body[:200])

def backup_user(user_id):
    """Отправить данные одного пользователя в Диск. Возвращает (ок, сообщение, ссылка)."""
    row = backup_row()
    if not row or not row["webhook_url"]:
        return False, "Автобэкап не настроен", None
    if not row["enabled"]:
        return False, "Автобэкап выключен", None
    secret = decrypt_secret(row["secret_enc"])
    if not secret:
        return False, "Секретный ключ потерян — сохрани настройки заново", None
    payload = _user_payload(user_id)
    body = {"secret": secret, "folder": row["folder_name"] or "WorkLog — Смены",
            "filename": safe_file_name(payload["user"], user_id), "data": payload}
    try:
        answer = _post_json(row["webhook_url"], body)
    except urllib.error.HTTPError as exc:
        msg = f"HTTP {exc.code} от Apps Script"
        _record_backup("error", msg)
        return False, msg, None
    except Exception as exc:
        msg = "Не удалось связаться с Apps Script: " + str(exc)[:200]
        _record_backup("error", msg)
        return False, msg, None
    if not answer.get("ok"):
        msg = "Apps Script вернул ошибку: " + str(answer.get("error", ""))[:200]
        _record_backup("error", msg)
        return False, msg, None
    _record_backup("ok", "", answer.get("folderUrl") or "")
    return True, "Сохранено в Google Диск", answer.get("fileUrl") or answer.get("folderUrl")

def backup_all_users():
    with db() as con:
        ids = [r["id"] for r in con.execute("SELECT id FROM users ORDER BY id").fetchall()]
    return [(uid,) + backup_user(uid) for uid in ids]

def auto_backup(uid):
    """Фоновая отправка: смена сохраняется мгновенно, Диск обновляется следом."""
    if not backup_configured():
        return False
    def worker():
        try:
            backup_user(uid)
        except Exception:
            pass
    threading.Thread(target=worker, daemon=True).start()
    return True

@app.get("/api/health")
def health():
    return jsonify(ok=True, backup_configured=backup_configured(), secure=request.is_secure, version=10)

@app.get("/api/backup/status")
def backup_status():
    u=current_user()
    if not u:return jsonify(error="Не авторизован"),401
    info=backup_public(); info["is_admin"]=is_admin(u)
    return jsonify(info)

@app.post("/api/backup/test")
def backup_test():
    u=current_user()
    if not is_admin(u):return jsonify(error="Доступ только для администратора"),403
    # Проверять можно и то, что ещё не сохранено: поля из формы приходят в теле
    # запроса. Если связь есть — сразу сохраняем, чтобы не нажимать «Сохранить»
    # отдельно.
    data=request.get_json(silent=True) or {}
    row=backup_row()
    draft_url=(valid_text(data.get("webhook_url"),400) or "").strip()
    draft_secret=str(data.get("secret","")).strip()
    draft_folder=valid_text(data.get("folder_name"),100) or ""
    url=draft_url or (row["webhook_url"] if row else "")
    if not url:
        return jsonify(error="Вставь ссылку веб-приложения Apps Script — адрес вида "
                             "https://script.google.com/macros/s/…/exec, который Google выдаёт после "
                             "«Развернуть» → «Новое развёртывание» → «Веб-приложение»."),400
    if draft_url:
        bad=url_problem(draft_url)
        if bad:return jsonify(error=bad),400
    secret=draft_secret or (decrypt_secret(row["secret_enc"]) if row and row["secret_enc"] else "")
    if not secret:
        return jsonify(error="Укажи секретный ключ — ровно тот же, что в строке SECRET файла Code.gs."),400
    folder=draft_folder or (row["folder_name"] if row else "") or "WorkLog — Смены"
    try:
        answer=_post_json(url, {"secret":secret,"ping":True,"folder":folder})
    except Exception as exc:
        msg="Не удалось связаться с Apps Script: "+str(exc)[:220]; _record_backup("error",msg)
        return jsonify(error=msg),400
    if not answer.get("ok"):
        msg="Apps Script вернул ошибку: "+str(answer.get("error",""))[:220]; _record_backup("error",msg)
        return jsonify(error=msg),400
    if draft_url or draft_secret or draft_folder:
        enabled=bool(data.get("enabled",True)) if "enabled" in data else (bool(row["enabled"]) if row else True)
        save_backup_config(url, encrypt_secret(secret), folder, enabled)
    _record_backup("ok","",answer.get("folderUrl") or "")
    return jsonify(ok=True, folder_url=answer.get("folderUrl") or "", folder=answer.get("folder") or "", backup=backup_public())

@app.post("/api/backup/run")
def backup_run():
    u=current_user()
    if not is_admin(u):return jsonify(error="Доступ только для администратора"),403
    results=backup_all_users(); bad=[x for x in results if not x[1]]
    return jsonify(ok=not bad, failed=len(bad), total=len(results),
                   error=bad[0][2] if bad else "", backup=backup_public())

init_db()

if __name__=="__main__":
    # PORT задают и Render, и PySpace IDE. HOST=0.0.0.0 нужен, чтобы приложение
    # было видно снаружи контейнера и через прокси предпросмотра.
    app.run(host=os.environ.get("HOST","0.0.0.0"),
            port=int(os.environ.get("PORT","5000")),
            debug=False, threaded=True)
