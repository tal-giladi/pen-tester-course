#!/usr/bin/env python3
"""Northwind Shop (LAB) — a DELIBERATELY VULNERABLE web app for module 07/08 exercises.

LAB TARGET ONLY. Runs on an isolated (no-egress) Docker network with synthetic data and
benign flag markers. Every vulnerability here is intentional and documented in the lessons.
Do not deploy this anywhere reachable. There is no real data and no real secret.
"""
import base64, hashlib, hmac, json, os, sqlite3, subprocess, urllib.request
from flask import Flask, request, jsonify, render_template_string, send_file, g, make_response

app = Flask(__name__)
DB = "/tmp/northwind.db"
JWT_SECRET = "secret"                       # INTENTIONALLY weak HMAC secret (07.2 JWT attack)
FLAG_SQLI = "LAB-FLAG-sqli-1a2b3c"
FLAG_SSRF = "LAB-FLAG-ssrf-internal-9z8y7x"
UPLOAD_DIR = "/tmp/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# --------------------------------------------------------------------------- db
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db

def seed():
    c = sqlite3.connect(DB); cur = c.cursor()
    cur.executescript("""
    DROP TABLE IF EXISTS users; DROP TABLE IF EXISTS orders; DROP TABLE IF EXISTS secrets;
    CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT, bio TEXT);
    CREATE TABLE orders(id INTEGER PRIMARY KEY, user_id INTEGER, item TEXT, total REAL);
    CREATE TABLE secrets(id INTEGER PRIMARY KEY, name TEXT, value TEXT);
    """)
    cur.executemany("INSERT INTO users VALUES(?,?,?,?,?)", [
        (1, "alice", "alice123", "customer", "Hi, I'm Alice."),
        (2, "bob",   "bobpass",  "customer", "Bob here."),
        (3, "admin", "S3cure-Admin!", "admin", "Store administrator."),
    ])
    cur.executemany("INSERT INTO orders VALUES(?,?,?,?)", [
        (1001, 1, "Blue Widget", 19.99), (1002, 1, "Red Widget", 24.50),
        (1003, 2, "Green Widget", 12.00), (1004, 3, "Admin Console License", 999.0),
    ])
    cur.execute("INSERT INTO secrets VALUES(1,'db_flag',?)", (FLAG_SQLI,))
    c.commit(); c.close()

# --------------------------------------------------------------------------- JWT (weak on purpose)
def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def b64ud(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def make_jwt(payload):
    h = {"alg": "HS256", "typ": "JWT"}
    seg = b64u(json.dumps(h).encode()) + "." + b64u(json.dumps(payload).encode())
    sig = b64u(hmac.new(JWT_SECRET.encode(), seg.encode(), hashlib.sha256).digest())
    return seg + "." + sig

def verify_jwt(token):
    """INTENTIONALLY FLAWED: accepts alg=none, and uses a weak secret for HS256."""
    try:
        h_b, p_b, sig = token.split(".")
        header = json.loads(b64ud(h_b)); payload = json.loads(b64ud(p_b))
        if header.get("alg", "").lower() == "none":     # FLAW: alg:none accepted
            return payload
        expect = b64u(hmac.new(JWT_SECRET.encode(), f"{h_b}.{p_b}".encode(), hashlib.sha256).digest())
        return payload if hmac.compare_digest(expect, sig) else None
    except Exception:
        return None

# --------------------------------------------------------------------------- routes
@app.route("/")
def index():
    return ("Northwind Shop (LAB). Try /search?q=widget, /login, /api/orders/<id>, "
            "/profile, /fetch?url=, /ping?host=, /download?file=, /render?name=, /upload\n")

# --- SQL injection + reflected XSS (07.3, 07.4) ---
@app.route("/search")
def search():
    q = request.args.get("q", "")
    # VULN: string-formatted SQL (SQLi). Also reflects q unescaped (reflected XSS).
    sql = "SELECT item,total FROM orders WHERE item LIKE '%%%s%%'" % q
    try:
        rows = db().execute(sql).fetchall()
        items = "".join(f"<li>{r['item']} — ${r['total']}</li>" for r in rows)
    except Exception as e:
        items = f"<li>query error: {e}</li>"
    return render_template_string(f"<h1>Results for {q}</h1><ul>{items}</ul>")  # reflected + SSTI-ish

# --- IDOR / BOLA (07.2, 08.1 API1): no ownership check ---
@app.route("/api/orders/<int:oid>")
def get_order(oid):
    r = db().execute("SELECT * FROM orders WHERE id=?", (oid,)).fetchone()
    if not r:
        return jsonify(error="not found"), 404
    return jsonify(id=r["id"], user_id=r["user_id"], item=r["item"], total=r["total"])

# --- login → weak JWT (07.2) ---
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return '<form method=post><input name=username><input name=password type=password><button>login</button></form>'
    u = request.form.get("username"); p = request.form.get("password")
    row = db().execute("SELECT * FROM users WHERE username=? AND password=?", (u, p)).fetchone()
    if not row:
        return "invalid", 401
    token = make_jwt({"sub": row["id"], "username": u, "role": row["role"]})
    resp = make_response(jsonify(token=token))
    resp.set_cookie("session", token)          # note: no HttpOnly/Secure/SameSite (07.1)
    return resp

# --- BFLA (08.1 API5): admin function trusting a client-controlled role claim ---
@app.route("/api/admin/users")
def admin_users():
    token = request.headers.get("Authorization", "").replace("Bearer ", "") or request.cookies.get("session", "")
    payload = verify_jwt(token)
    if not payload:
        return jsonify(error="unauthenticated"), 401
    if payload.get("role") != "admin":         # bypass via alg:none or forged role
        return jsonify(error="forbidden"), 403
    rows = db().execute("SELECT id,username,role FROM users").fetchall()
    return jsonify(users=[dict(r) for r in rows], note="admin-only data")

# --- stored XSS (07.4): bio stored and rendered unescaped ---
@app.route("/profile", methods=["GET", "POST"])
def profile():
    if request.method == "POST":
        bio = request.form.get("bio", "")
        db().execute("UPDATE users SET bio=? WHERE id=1", (bio,)); db().commit()
    r = db().execute("SELECT username,bio FROM users WHERE id=1").fetchone()
    return render_template_string(f"<h1>{r['username']}</h1><div>{r['bio']}</div>"
                                  "<form method=post><textarea name=bio></textarea><button>save</button></form>")

# --- SSRF (07.4, 08 API7): fetch an arbitrary URL server-side (confused deputy) ---
@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    try:
        with urllib.request.urlopen(url, timeout=3) as r:   # VULN: no allowlist
            return r.read()[:2000]
    except Exception as e:
        return f"fetch error: {e}", 502

# --- OS command injection (07.3) ---
@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # VULN: shell=True with user input
    out = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True, timeout=5)
    return f"<pre>{out.stdout}{out.stderr}</pre>"

# --- path traversal (07.5) ---
@app.route("/download")
def download():
    fn = request.args.get("file", "readme.txt")
    path = os.path.join("/srv/files", fn)      # VULN: no normalization; ../ escapes
    try:
        return send_file(path)
    except Exception as e:
        return f"error: {e}", 404

# --- SSTI (07.3): renders user input as a template ---
@app.route("/render")
def render():
    name = request.args.get("name", "guest")
    return render_template_string("Hello " + name)   # VULN: Jinja SSTI

# --- file upload (07.5): stores as-is, then serves ---
@app.route("/upload", methods=["GET", "POST"])
def upload():
    if request.method == "GET":
        return '<form method=post enctype=multipart/form-data><input type=file name=f><button>upload</button></form>'
    f = request.files.get("f")
    if not f:
        return "no file", 400
    dest = os.path.join(UPLOAD_DIR, f.filename)   # VULN: no extension/type/name checks
    f.save(dest)
    return f"stored at /files/{f.filename}"

if __name__ == "__main__":
    seed()
    # seed a couple of files for the traversal exercise
    os.makedirs("/srv/files", exist_ok=True)
    open("/srv/files/readme.txt", "w").write("Northwind file service (LAB).\n")
    app.run(host="0.0.0.0", port=5000)
