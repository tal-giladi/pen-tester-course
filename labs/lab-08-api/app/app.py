#!/usr/bin/env python3
"""Northwind API (LAB) — a DELIBERATELY VULNERABLE REST + GraphQL API for module 08.

LAB TARGET ONLY. Isolated network, synthetic data, benign LAB-FLAG markers. Maps to the
OWASP API Security Top 10 (2023): API1 BOLA, API2 broken auth, API3 object-property authz
(mass assignment / excessive data exposure), API4 resource consumption, API5 BFLA,
API9 improper inventory (v1 vs v2). Intentional flaws — do not deploy anywhere reachable.
"""
import base64, hmac, hashlib, json
from flask import Flask, request, jsonify

app = Flask(__name__)
JWT_SECRET = "changeme"          # INTENTIONALLY weak (API2)
FLAG = "LAB-FLAG-api-graphql-42"

USERS = {
    1: {"id": 1, "username": "alice", "role": "customer", "email": "alice@northwind.lab",
        "ssn": "LAB-SSN-000-11-1111", "password_hash": "e10adc3949ba59abbe56e057f20f883e"},
    2: {"id": 2, "username": "bob", "role": "customer", "email": "bob@northwind.lab",
        "ssn": "LAB-SSN-000-22-2222", "password_hash": "5f4dcc3b5aa765d61d8327deb882cf99"},
    3: {"id": 3, "username": "admin", "role": "admin", "email": "admin@northwind.lab",
        "ssn": "LAB-SSN-000-33-3333", "password_hash": "21232f297a57a5a743894a0e4a801fc3"},
}
ORDERS = {1001: {"id": 1001, "user_id": 1, "total": 19.99},
          1004: {"id": 1004, "user_id": 3, "total": 999.0}}

# ---- tiny JWT (weak on purpose) ----
def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def b64ud(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
def make_jwt(p):
    seg = b64u(b'{"alg":"HS256","typ":"JWT"}') + "." + b64u(json.dumps(p).encode())
    return seg + "." + b64u(hmac.new(JWT_SECRET.encode(), seg.encode(), hashlib.sha256).digest())
def read_jwt(tok):
    try:
        h, p, s = tok.split(".")
        exp = b64u(hmac.new(JWT_SECRET.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest())
        return json.loads(b64ud(p)) if hmac.compare_digest(exp, s) else None
    except Exception:
        return None
def caller():
    tok = request.headers.get("Authorization", "").replace("Bearer ", "")
    return read_jwt(tok)

# =========================== REST (v1) ===========================
@app.post("/api/v1/login")
def login():
    b = request.get_json(force=True, silent=True) or {}
    for u in USERS.values():
        if u["username"] == b.get("username") and b.get("password") == "password":  # synthetic
            return jsonify(token=make_jwt({"sub": u["id"], "role": u["role"]}))
    return jsonify(error="invalid"), 401

# API1 BOLA + API3 excessive data exposure: no ownership check, returns sensitive fields
@app.get("/api/v1/users/<int:uid>")
def get_user(uid):
    if not caller():
        return jsonify(error="unauthenticated"), 401
    u = USERS.get(uid)
    return (jsonify(u), 200) if u else (jsonify(error="not found"), 404)  # returns ssn/hash too

# API3 mass assignment: trusts client-supplied fields incl. role
@app.post("/api/v1/users")
def create_user():
    b = request.get_json(force=True, silent=True) or {}
    nid = max(USERS) + 1
    USERS[nid] = {"id": nid, "username": b.get("username", f"u{nid}"),
                  "role": b.get("role", "customer"),          # VULN: client sets role
                  "email": b.get("email", ""), "ssn": "", "password_hash": ""}
    return jsonify(USERS[nid]), 201

# API5 BFLA: admin-only function without a real authorization check
@app.get("/api/v1/admin/flag")
def admin_flag():
    p = caller()
    if not p:
        return jsonify(error="unauthenticated"), 401
    # VULN: checks that a role claim EXISTS, not that it equals admin
    if "role" not in p:
        return jsonify(error="forbidden"), 403
    return jsonify(flag=FLAG, note="admin-only business function")

# API9 improper inventory: an old, less-protected v2 shadow of the user endpoint
@app.get("/api/v2/users/<int:uid>")
def get_user_v2(uid):
    u = USERS.get(uid)                                     # VULN: v2 forgot auth entirely
    return (jsonify({k: u[k] for k in ("id", "username", "role", "email")}), 200) if u else (jsonify(error="not found"), 404)

# =========================== GraphQL ===========================
# Minimal hand-rolled GraphQL with introspection, to avoid heavy deps. Supports the
# introspection query (schema recon) and a few fields, including a flawed adminSecret.
SCHEMA = {
    "types": ["Query", "User", "Order"],
    "Query": {"me": "User", "user(id)": "User", "allUsers": "[User]", "adminSecret": "String"},
    "User": {"id": "Int", "username": "String", "role": "String", "email": "String", "ssn": "String"},
    "Order": {"id": "Int", "userId": "Int", "total": "Float"},
}

@app.post("/graphql")
def graphql():
    body = request.get_json(force=True, silent=True) or {}
    q = (body.get("query") or "").strip()
    # introspection (schema recon) — enabled on purpose (API misconfig)
    if "__schema" in q or "IntrospectionQuery" in q:
        return jsonify(data={"__schema": SCHEMA})
    if "adminSecret" in q:
        # VULN: no authorization on a sensitive field
        return jsonify(data={"adminSecret": FLAG})
    if "allUsers" in q:
        return jsonify(data={"allUsers": [{"id": u["id"], "username": u["username"],
                                           "role": u["role"], "ssn": u["ssn"]} for u in USERS.values()]})
    if "me" in q:
        p = caller()
        if not p:
            return jsonify(errors=[{"message": "unauthenticated"}]), 200
        u = USERS[p["sub"]]
        return jsonify(data={"me": {"id": u["id"], "username": u["username"], "role": u["role"]}})
    return jsonify(errors=[{"message": "unknown query; try {__schema} or {adminSecret}"}])

@app.get("/")
def index():
    return ("Northwind API (LAB). REST: /api/v1/... and /api/v2/... ; GraphQL: POST /graphql. "
            "See swagger at /api/v1/openapi.json\n")

@app.get("/api/v1/openapi.json")
def openapi():
    return jsonify({"openapi": "3.0.0", "info": {"title": "Northwind API", "version": "1.0"},
                    "paths": {"/api/v1/users/{id}": {}, "/api/v1/admin/flag": {}, "/graphql": {}}})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
