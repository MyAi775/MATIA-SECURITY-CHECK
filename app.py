import os
import secrets
import socket
import sqlite3
import hmac
from datetime import datetime
from functools import wraps
from urllib.parse import urlparse
from flask import Flask, request, redirect, session, url_for, jsonify, render_template_string


# =========================================================
# MATIA // SECURITY CHECK
# =========================================================

app = Flask(__name__)

SECRET_KEY = os.environ.get("MATIA_SECRET_KEY") or secrets.token_hex(32)

ADMIN_PASSWORD = os.environ.get("MATIA_ADMIN_PASSWORD", "")

ALLOWED_ADMIN_EMAILS = {
    "kleimatia1@gmail.com",
    "vantyx199@gmail.com",
}

DB_FILE = os.environ.get(
    "MATIA_DB_FILE",
    "matia_security.db"
)

app.config.update(
    SECRET_KEY=SECRET_KEY,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=(
        os.environ.get("SESSION_COOKIE_SECURE", "0") == "1"
    ),
    SESSION_COOKIE_NAME="matia_admin_session",
)


# =========================================================
# HELPERS
# =========================================================

def current_time():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def get_request(request_id):
    conn = get_db()

    item = conn.execute(
        "SELECT * FROM requests WHERE id = ?",
        (request_id,)
    ).fetchone()

    conn.close()

    return item


# =========================================================
# DATABASE
# =========================================================

def init_db():
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            target TEXT NOT NULL,
            target_ip TEXT,
            scope TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'PENDING',
            client_ip TEXT,
            created TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id INTEGER NOT NULL,
            sender TEXT NOT NULL,
            message TEXT NOT NULL,
            created TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id INTEGER NOT NULL,
            code TEXT NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            evidence TEXT NOT NULL,
            impact TEXT NOT NULL,
            recommendation TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


# =========================================================
# DNS / IP LOOKUP
# =========================================================

def extract_hostname(target):
    value = (target or "").strip()

    if not value:
        return None

    if "://" not in value:
        value = "https://" + value

    try:
        return urlparse(value).hostname
    except ValueError:
        return None


def resolve_target_ip(target):
    hostname = extract_hostname(target)

    if not hostname:
        return "IP NOT FOUND"

    try:
        addresses = socket.getaddrinfo(
            hostname,
            None,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM
        )

        ips = []

        for item in addresses:
            ip = item[4][0]

            if ip not in ips:
                ips.append(ip)

        if not ips:
            return "IP NOT FOUND"

        return ", ".join(ips[:10])

    except socket.gaierror:
        return "IP NOT FOUND"

    except Exception:
        return "IP LOOKUP ERROR"


# =========================================================
# ADMIN AUTH
# =========================================================

def is_admin():
    email = (
        session.get("admin_email") or ""
    ).strip().lower()

    return (
        session.get("admin_logged_in") is True
        and email in ALLOWED_ADMIN_EMAILS
    )


def admin_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not is_admin():
            return redirect(
                url_for(
                    "admin_login",
                    next=request.path
                )
            )

        return view(*args, **kwargs)

    return wrapper


# =========================================================
# GUI STYLE
# =========================================================

STYLE = """
<style>

:root {
    --bg: #05080d;
    --panel: #0b121a;
    --panel2: #0f1822;
    --line: #1b2a38;
    --cyan: #00e5ff;
    --green: #4ade80;
    --red: #ff5a6f;
    --yellow: #fbbf24;
    --text: #eaf4ff;
    --muted: #8da0b5;
}

* {
    box-sizing: border-box;
}

html {
    scroll-behavior: smooth;
}

body {
    margin: 0;
    color: var(--text);
    font-family: Inter, Segoe UI, Arial, sans-serif;
    min-height: 100vh;

    background:
        radial-gradient(
            circle at 20% -10%,
            rgba(0,229,255,.10),
            transparent 30%
        ),
        radial-gradient(
            circle at 100% 20%,
            rgba(74,222,128,.06),
            transparent 28%
        ),
        linear-gradient(
            180deg,
            #04070b,
            #070c12 55%,
            #04070b
        );
}

body:before {
    content: "";
    position: fixed;
    inset: 0;
    pointer-events: none;
    opacity: .25;

    background-image:
        linear-gradient(
            rgba(255,255,255,.025) 1px,
            transparent 1px
        ),
        linear-gradient(
            90deg,
            rgba(255,255,255,.025) 1px,
            transparent 1px
        );

    background-size: 32px 32px;
}

nav {
    position: sticky;
    top: 0;
    z-index: 20;

    border-bottom: 1px solid var(--line);

    background: rgba(5,8,13,.86);

    backdrop-filter: blur(16px);
}

.navin {
    max-width: 1200px;
    margin: auto;

    padding: 16px 22px;

    display: flex;
    align-items: center;
    justify-content: space-between;

    gap: 14px;
}

.logo {
    font-weight: 900;
    letter-spacing: 2px;
    color: var(--cyan);
}

.navlinks {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
}

.navlinks a {
    color: var(--muted);
    padding: 9px 12px;

    border: 1px solid transparent;
    border-radius: 10px;

    text-decoration: none;
}

.navlinks a:hover {
    color: var(--text);
    border-color: var(--line);
    background: #0a1118;
}

.container {
    max-width: 1200px;
    margin: auto;

    padding: 30px 18px 60px;
}

.card {
    background:
        linear-gradient(
            180deg,
            rgba(15,24,34,.96),
            rgba(8,14,20,.96)
        );

    border: 1px solid var(--line);
    border-radius: 18px;

    padding: 24px;
    margin-bottom: 18px;

    box-shadow:
        0 20px 60px rgba(0,0,0,.35);
}

.hero {
    text-align: center;
    padding: 72px 25px;
}

.kicker {
    color: var(--cyan);
    font-size: 12px;
    letter-spacing: 2px;
    font-weight: 800;
}

h1,
h2,
h3 {
    margin-top: 0;
}

h1 {
    font-size: clamp(32px, 6vw, 60px);
}

h2 {
    color: #dffaff;
}

.muted {
    color: var(--muted);
}

.small {
    font-size: 12px;
}

.grid {
    display: grid;
    grid-template-columns:
        repeat(
            auto-fit,
            minmax(220px, 1fr)
        );

    gap: 16px;
}

.stats {
    display: grid;

    grid-template-columns:
        repeat(
            auto-fit,
            minmax(160px, 1fr)
        );

    gap: 14px;
}

.stat {
    padding: 18px;

    border: 1px solid var(--line);

    border-radius: 16px;

    background: #081019;
}

.stat .num {
    font-size: 32px;
    font-weight: 900;
    color: var(--cyan);
}

label {
    display: block;

    color: #c9d9e7;

    font-size: 13px;
    font-weight: 700;

    margin: 14px 0 7px;
}

input,
textarea,
select {
    width: 100%;

    padding: 13px 14px;

    border-radius: 12px;

    border: 1px solid #243647;

    background: #050a10;

    color: #fff;

    outline: none;
}

input:focus,
textarea:focus,
select:focus {
    border-color: var(--cyan);

    box-shadow:
        0 0 0 3px rgba(0,229,255,.08);
}

textarea {
    min-height: 120px;
    resize: vertical;
}

button,
.btn {
    display: inline-block;

    border: 0;

    border-radius: 12px;

    padding: 12px 16px;

    background: var(--cyan);

    color: #021117;

    font-weight: 900;

    cursor: pointer;

    text-decoration: none;
}

button:hover,
.btn:hover {
    filter: brightness(1.06);
    transform: translateY(-1px);
}

.btn.secondary {
    background: #14212d;
    color: #dce9f5;
    border: 1px solid var(--line);
}

.btn.green {
    background: var(--green);
    color: #05220e;
}

.btn.red {
    background: var(--red);
    color: #fff;
}

.btn.yellow {
    background: var(--yellow);
    color: #241800;
}

.actions {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
}

.badge {
    display: inline-flex;

    align-items: center;
    gap: 6px;

    padding: 5px 10px;

    border-radius: 999px;

    font-size: 12px;
    font-weight: 900;

    background: #152330;
    color: #d8e9f6;

    border: 1px solid #233747;
}

.badge.pending {
    color: #fbbf24;
}

.badge.accepted,
.badge.in_progress,
.badge.completed {
    color: #4ade80;
}

.badge.declined {
    color: #ff6b7a;
}

table {
    width: 100%;
    border-collapse: collapse;
}

th,
td {
    text-align: left;

    padding: 13px 10px;

    border-bottom: 1px solid var(--line);

    vertical-align: top;
}

th {
    color: #8fa5b8;

    font-size: 12px;

    text-transform: uppercase;

    letter-spacing: .08em;
}

.table-wrap {
    overflow: auto;
}

.chat {
    border: 1px solid var(--line);

    border-radius: 16px;

    padding: 14px;

    background: #050a10;

    max-height: 480px;

    overflow: auto;
}

.msg {
    max-width: 82%;

    padding: 12px 14px;

    margin: 10px 0;

    border-radius: 15px;

    border: 1px solid var(--line);
}

.msg.client {
    margin
