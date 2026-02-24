import os
import jwt
import bcrypt
import psycopg2
import psycopg2.extras
import json
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Any

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

DATABASE_URL = os.environ.get("DATABASE_URL")
JWT_SECRET   = os.environ.get("JWT_SECRET", "change-this-secret!")
JWT_DAYS     = 30

# ── DB connection ──
def get_db():
    conn = psycopg2.connect(DATABASE_URL)
    try:
        yield conn
    finally:
        conn.close()

# ── Create tables on startup ──
@app.on_event("startup")
def init_db():
    conn = psycopg2.connect(DATABASE_URL)
    cur  = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id         SERIAL PRIMARY KEY,
            email      TEXT UNIQUE NOT NULL,
            password   TEXT NOT NULL,
            name       TEXT NOT NULL,
            created_at TIMESTAMPTZ DEFAULT NOW()
        );
        CREATE TABLE IF NOT EXISTS user_data (
            user_id  INTEGER REFERENCES users(id) ON DELETE CASCADE,
            key      TEXT NOT NULL,
            value    JSONB,
            PRIMARY KEY (user_id, key)
        );
    """)
    conn.commit()
    cur.close()
    conn.close()
    print("✅ Database ready")

# ── JWT helpers ──
def create_token(user_id: int, email: str, name: str) -> str:
    payload = {
        "id":    user_id,
        "email": email,
        "name":  name,
        "exp":   datetime.utcnow() + timedelta(days=JWT_DAYS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def verify_token(authorization: str = Header(...)) -> dict:
    token = authorization.replace("Bearer ", "")
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

# ── Models ──
class RegisterBody(BaseModel):
    email:    str
    password: str
    name:     str

class LoginBody(BaseModel):
    email:    str
    password: str

class DataBody(BaseModel):
    value: Any

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# ROUTES
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@app.get("/")
def health():
    return {"status": "🥗 Diet API running"}

# POST /api/register
@app.post("/api/register")
def register(body: RegisterBody, conn=Depends(get_db)):
    if not body.email or not body.password or not body.name:
        raise HTTPException(400, "Please fill all fields")
    if len(body.password) < 6:
        raise HTTPException(400, "Password must be at least 6 characters")

    hashed = bcrypt.hashpw(body.password.encode(), bcrypt.gensalt()).decode()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute(
            "INSERT INTO users (email, password, name) VALUES (%s, %s, %s) RETURNING id, email, name",
            (body.email.lower().strip(), hashed, body.name.strip())
        )
        user = cur.fetchone()
        conn.commit()
    except psycopg2.errors.UniqueViolation:
        raise HTTPException(409, "Email already registered")
    finally:
        cur.close()

    token = create_token(user["id"], user["email"], user["name"])
    return {"token": token, "user": {"id": user["id"], "email": user["email"], "name": user["name"]}}

# POST /api/login
@app.post("/api/login")
def login(body: LoginBody, conn=Depends(get_db)):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM users WHERE email = %s", (body.email.lower().strip(),))
    user = cur.fetchone()
    cur.close()

    if not user:
        raise HTTPException(401, "Email not found")
    if not bcrypt.checkpw(body.password.encode(), user["password"].encode()):
        raise HTTPException(401, "Wrong password")

    token = create_token(user["id"], user["email"], user["name"])
    return {"token": token, "user": {"id": user["id"], "email": user["email"], "name": user["name"]}}

# GET /api/me
@app.get("/api/me")
def me(user=Depends(verify_token)):
    return {"user": user}

# GET /api/data/{key}
@app.get("/api/data/{key}")
def get_data(key: str, user=Depends(verify_token), conn=Depends(get_db)):
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT value FROM user_data WHERE user_id=%s AND key=%s", (user["id"], key))
    row = cur.fetchone()
    cur.close()
    return {"value": row["value"] if row else None}

# PUT /api/data/{key}
@app.put("/api/data/{key}")
def save_data(key: str, body: DataBody, user=Depends(verify_token), conn=Depends(get_db)):
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO user_data (user_id, key, value)
        VALUES (%s, %s, %s)
        ON CONFLICT (user_id, key) DO UPDATE SET value = EXCLUDED.value
    """, (user["id"], key, json.dumps(body.value)))
    conn.commit()
    cur.close()
    return {"ok": True}
