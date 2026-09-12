import os
import secrets
import socket
import sqlite3
from datetime import datetime
from functools import wraps
from html import escape
from urllib.parse import urlparse

from flask import (
    Flask,
    jsonify,
    redirect,
    render_template_string,
    request,
    session,
    url_for,
)

# =========================================================
# MATIA // SECURITY CHECK
# FINAL BOSS EDITION
# =========================================================

app = Flask(__name__)

# ---------------------------------------------------------
# ENVIRONMENT
# ---------------------------------------------------------

ADMIN_USER = os.environ.get("MATIA_ADMIN_USER", "")
ADMIN_PASSWORD = os.environ.get("MATIA_ADMIN_PASSWORD", "")
SECRET_KEY = os.environ.get("MATIA_SECRET_KEY")

if not SECRET_KEY:
    SECRET_KEY = secrets.token_hex(32)

app.config.update(
    SECRET_KEY=SECRET_KEY,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=True,
)

DB_FILE = os.environ.get("DB_FILE", "matia_security.db")


# =========================================================
# DATABASE
# =========================================================

def get_db():
    conn = sqlite3.connect(DB_FILE, timeout=20)
    conn.row_factory = sqlite3.Row
    return conn


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
            created TEXT NOT NULL,
            read_by_client INTEGER NOT NULL DEFAULT 0,
            read_by_admin INTEGER NOT NULL DEFAULT 0
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

    # Migration for older databases.
    columns = {
        row["name"]
        for row in conn.execute(
            "PRAGMA table_info(messages)"
        ).fetchall()
    }

    if "read_by_client" not in columns:
        conn.execute("""
            ALTER TABLE messages
            ADD COLUMN read_by_client INTEGER NOT NULL DEFAULT 0
        """)

    if "read_by_admin" not in columns:
        conn.execute("""
            ALTER TABLE messages
            ADD COLUMN read_by_admin INTEGER NOT NULL DEFAULT 0
        """)

    conn.commit()
    conn.close()


# IMPORTANT FOR RENDER / GUNICORN
init_db()


# =========================================================
# HELPERS
# =========================================================

def now():
    return datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )


def esc(value):
    return escape(str(value))


def get_request(request_id):
    conn = get_db()

    row = conn.execute(
        """
        SELECT *
        FROM requests
        WHERE id = ?
        """,
        (request_id,)
    ).fetchone()

    conn.close()

    return row


def admin_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):

        if not session.get("admin"):
            return redirect(
                url_for("admin_login")
            )

        return view(*args, **kwargs)

    return wrapper


def resolve_hostname(target):

    value = target.strip()

    if not value:
        return None

    if "://" not in value:
        value = "https://" + value

    try:
        return urlparse(value).hostname
    except Exception:
        return None


def resolve_target_ip(target):

    hostname = resolve_hostname(target)

    if not hostname:
        return "IP NOT FOUND"

    try:

        results = socket.getaddrinfo(
            hostname,
            None,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM
        )

        ips = []

        for result in results:

            ip = result[4][0]

            if ip not in ips:
                ips.append(ip)

        return (
            ", ".join(ips[:10])
            if ips
            else "IP NOT FOUND"
        )

    except socket.gaierror:
        return "IP NOT FOUND"

    except Exception:
        return "IP LOOKUP ERROR"


def render_messages(messages):

    html = ""

    for msg in messages:

        sender = esc(msg["sender"])

        html += f"""
        <div class="message {sender}">

            <div class="message-top">

                <strong>
                    {sender.upper()}
                </strong>

                <span class="message-time">
                    {esc(msg["created"])}
                </span>

            </div>

            <div class="message-text">
                {esc(msg["message"])}
            </div>

        </div>
        """

    if not html:
        html = """
        <div class="empty-chat">
            No messages yet.
            Start the conversation.
        </div>
        """

    return html


# =========================================================
# DESIGN
# =========================================================

STYLE = """
<style>

:root {
    --bg: #04070b;
    --panel: #0a1017;
    --panel2: #071019;
    --border: #1b2a38;
    --text: #eaf7ff;
    --muted: #8297a9;
    --cyan: #00eaff;
    --green: #4ade80;
    --red: #ff5757;
    --yellow: #facc15;
    --purple: #a78bfa;
}

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    background:
        radial-gradient(
            circle at top right,
            rgba(0,234,255,.08),
            transparent 30%
        ),
        radial-gradient(
            circle at bottom left,
            rgba(167,139,250,.06),
            transparent 30%
        ),
        var(--bg);
    color: var(--text);
    font-family:
        Inter,
        Arial,
        Helvetica,
        sans-serif;
}

body::before {
    content: "";
    position: fixed;
    inset: 0;
    pointer-events: none;
    opacity: .06;
    background-image:
        linear-gradient(
            rgba(255,255,255,.04) 1px,
            transparent 1px
        ),
        linear-gradient(
            90deg,
            rgba(255,255,255,.04) 1px,
            transparent 1px
        );
    background-size: 40px 40px;
}

nav {
    position: sticky;
    top: 0;
    z-index: 50;
    backdrop-filter: blur(14px);
    background: rgba(4,7,11,.86);
    border-bottom: 1px solid var(--border);
    padding: 16px 24px;
}

.nav-inner {
    max-width: 1180px;
    margin: auto;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
}

.logo {
    color: var(--cyan);
    font-weight: 950;
    letter-spacing: 2.5px;
    font-size: 14px;
}

.logo span {
    color: white;
}

.container {
    max-width: 1180px;
    margin: auto;
    padding: 30px 20px 70px;
}

.card {
    background:
        linear-gradient(
            180deg,
            rgba(255,255,255,.02),
            transparent
        ),
        var(--panel);
    border: 1px solid var(--border);
    border-radius: 18px;
    padding: 24px;
    margin-bottom: 20px;
    box-shadow:
        0 15px 50px rgba(0,0,0,.20);
}

.hero {
    padding: 70px 30px;
    text-align: center;
}

.hero-badge {
    display: inline-block;
    padding: 8px 13px;
    border-radius: 999px;
    background: rgba(0,234,255,.08);
    border: 1px solid rgba(0,234,255,.18);
    color: var(--cyan);
    font-weight: 900;
    font-size: 12px;
    letter-spacing: 1.5px;
}

h1,
h2 {
    color: var(--cyan);
}

h1 {
    font-size: clamp(30px, 6vw, 58px);
    margin: 15px 0;
}

h2 {
    margin-top: 0;
}

h3 {
    color: #d9f8ff;
}

p {
    line-height: 1.7;
}

.muted,
.message-time {
    color: var(--muted);
}

.grid {
    display: grid;
    grid-template-columns:
        repeat(auto-fit, minmax(220px, 1fr));
    gap: 15px;
}

.stat-grid {
    display: grid;
    grid-template-columns:
        repeat(auto-fit, minmax(180px, 1fr));
    gap: 12px;
}

.stat {
    padding: 18px;
    background: var(--panel2);
    border: 1px solid var(--border);
    border-radius: 14px;
}

.stat-number {
    font-size: 27px;
    font-weight: 950;
    color: var(--cyan);
}

input,
textarea,
select {
    width: 100%;
    background: #050a0f;
    color: white;
    border: 1px solid #233443;
    border-radius: 11px;
    padding: 13px;
    margin-top: 7px;
    margin-bottom: 16px;
    outline: none;
}

input:focus,
textarea:focus,
select:focus {
    border-color: var(--cyan);
    box-shadow:
        0 0 0 3px rgba(0,234,255,.08);
}

textarea {
    min-height: 125px;
    resize: vertical;
}

button {
    border: 0;
    border-radius: 11px;
    padding: 12px 18px;
    font-weight: 950;
    cursor: pointer;
    background: var(--cyan);
    color: #021015;
    transition: .16s ease;
}

button:hover {
    transform: translateY(-1px);
    filter: brightness(1.05);
}

button:disabled {
    opacity: .5;
    cursor: wait;
    transform: none;
}

.green {
    background: var(--green);
}

.red {
    background: var(--red);
    color: white;
}

.secondary {
    background: #152331;
    color: var(--text);
    border: 1px solid var(--border);
}

a {
    color: var(--cyan);
    text-decoration: none;
}

.badge {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 5px 9px;
    border-radius: 999px;
    background: #142532;
    font-size: 12px;
    font-weight: 900;
}

.notification {
    display: none;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    background:
        linear-gradient(
            90deg,
            rgba(0,234,255,.18),
            rgba(74,222,128,.10)
        );
    border: 1px solid rgba(0,234,255,.30);
    color: white;
    border-radius: 14px;
    padding: 14px 17px;
    margin-bottom: 18px;
    font-weight: 900;
}

.notification.show {
    display: flex;
}

.chat-shell {
    overflow: hidden;
    border: 1px solid var(--border);
    border-radius: 15px;
    background: #050a0f;
}

.chat-header {
    padding: 14px 16px;
    border-bottom: 1px solid var(--border);
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.chat-online {
    color: var(--green);
    font-size: 12px;
    font-weight: 900;
}

.chat-box {
    min-height: 260px;
    max-height: 520px;
    overflow-y: auto;
    padding: 15px;
}

.message {
    width: min(82%, 720px);
    background: #0b141d;
    border: 1px solid #1d2e3d;
    border-left: 3px solid #506777;
    padding: 12px 14px;
    margin: 9px 0;
    border-radius: 13px;
}

.message.matia {
    margin-left: auto;
    border-left-color: var(--cyan);
}

.message.client {
    border-left-color: var(--green);
}

.message-top {
    display: flex;
    justify-content: space-between;
    gap: 12px;
    font-size: 12px;
}

.message-text {
    margin-top: 8px;
    line-height: 1.6;
    white-space: pre-wrap;
    word-break: break-word;
}

.empty-chat {
    padding: 60px 20px;
    text-align: center;
    color: var(--muted);
}

.chat-compose {
    border-top: 1px solid var(--border);
    padding: 14px;
}

.chat-compose textarea {
    min-height: 85px;
    margin-bottom: 8px;
}

.chat-actions {
    display: flex;
    justify-content: flex-end;
}

table {
    width: 100%;
    border-collapse: collapse;
}

th,
td {
    text-align: left;
    padding: 13px 10px;
    border-bottom: 1px solid var(--border);
}

th {
    color: var(--muted);
    font-size: 12px;
    text-transform: uppercase;
}

.ip-box {
    background: #061019;
    border: 1px solid #173141;
    padding: 15px;
    border-radius: 12px;
    margin: 12px 0;
}

pre {
    white-space: pre-wrap;
    word-break: break-word;
    font-family:
        "SFMono-Regular",
        Consolas,
        monospace;
    line-height: 1.6;
}

.notice {
    padding: 13px 15px;
    border-radius: 12px;
    background: rgba(250,204,21,.08);
    border: 1px solid rgba(250,204,21,.16);
    color: #fde68a;
}

.footer {
    text-align: center;
    color: var(--muted);
    font-size: 12px;
    padding: 20px;
}

.pulse {
    animation: pulse 1.5s infinite;
}

@keyframes pulse {
    0%, 100% {
        box-shadow:
            0 0 0 0 rgba(0,234,255,.15);
    }
    50% {
        box-shadow:
            0 0 0 8px rgba(0,234,255,0);
    }
}

@media(max-width:700px) {
    .container {
        padding: 20px 12px 50px;
    }

    .card {
        padding: 17px;
    }

    .message {
        width: 94%;
    }

    table {
        display: block;
        overflow-x: auto;
    }
}

</style>
"""


def page(title, content, scripts=""):

    return render_template_string(
        f"""
        <!doctype html>

        <html lang="en">

        <head>

            <meta charset="utf-8">

            <meta
                name="viewport"
                content="width=device-width,
                initial-scale=1"
            >

            <meta
                name="description"
                content="MATIA Security Check"
            >

            <meta
                name="theme-color"
                content="#05080c"
            >

            <title>{esc(title)}</title>

            {STYLE}

        </head>

        <body>

            <nav>

                <div class="nav-inner">

                    <div class="logo">
                        MATIA
                        <span>// SECURITY CHECK</span>
                    </div>

                    <div class="muted">
                        AUTHORIZED ASSESSMENT
                    </div>

                </div>

            </nav>

            <main class="container">

                {content}

            </main>

            <div class="footer">
                MATIA // SECURITY CHECK • Authorized testing only
            </div>

            {scripts}

        </body>

        </html>
        """
    )


# =========================================================
# HOME
# =========================================================

@app.route("/")
def home():

    return page(
        "MATIA // SECURITY CHECK",
        """
        <section class="card hero">

            <div class="hero-badge">
                SECURE • AUTHORIZED • PROFESSIONAL
            </div>

            <h1>
                MATIA<br>
                SECURITY CHECK
            </h1>

            <p class="muted">
                A clean workspace for authorized web
                security assessment requests,
                communication and reporting.
            </p>

            <br>

            <a href="/request">
                <button class="pulse">
                    REQUEST A SECURITY CHECK
                </button>
            </a>

        </section>

        <section class="grid">

            <div class="card">
                <h2>01</h2>
                <h3>REQUEST</h3>
                <p class="muted">
                    Submit a target and clearly defined
                    authorized scope.
                </p>
            </div>

            <div class="card">
                <h2>02</h2>
                <h3>REVIEW</h3>
                <p class="muted">
                    Matia reviews the request before
                    assessment begins.
                </p>
            </div>

            <div class="card">
                <h2>03</h2>
                <h3>LIVE CHAT</h3>
                <p class="muted">
                    Client and admin can communicate
                    with live notifications.
                </p>
            </div>

            <div class="card">
                <h2>04</h2>
                <h3>REPORT</h3>
                <p class="muted">
                    Findings are documented clearly
                    with evidence and recommendations.
                </p>
            </div>

        </section>

        <section class="card">

            <h2>AUTHORIZED USE ONLY</h2>

            <p class="muted">
                Only submit systems you own or systems
                for which you have explicit permission
                to perform security testing.
            </p>

        </section>
        """
    )


# =========================================================
# CREATE REQUEST
# =========================================================

@app.route("/request", methods=["GET", "POST"])
def create_request():

    if request.method == "POST":

        name = request.form.get(
            "name", ""
        ).strip()

        email = request.form.get(
            "email", ""
        ).strip()

        target = request.form.get(
            "target", ""
        ).strip()

        scope = request.form.get(
            "scope", ""
        ).strip()

        authorization = request.form.get(
            "authorization"
        )

        if not all([
            name,
            email,
            target,
            scope
        ]):
            return (
                "Please complete all fields.",
                400
            )

        if not authorization:
            return (
                "Authorization confirmation is required.",
                400
            )

        target_ip = resolve_target_ip(target)

        client_ip = (
            request.headers.get("CF-Connecting-IP")
            or request.remote_addr
            or "unknown"
        )

        conn = get_db()

        cursor = conn.execute(
            """
            INSERT INTO requests
            (
                name,
                email,
                target,
                target_ip,
                scope,
                status,
                client_ip,
                created
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                name,
                email,
                target,
                target_ip,
                scope,
                "PENDING",
                client_ip,
                now()
            )
        )

        conn.commit()

        request_id = cursor.lastrowid

        conn.close()

        return redirect(
            url_for(
                "request_status",
                request_id=request_id
            )
        )

    return page(
        "Request Security Check",
        """
        <div class="card">

            <div class="hero-badge">
                REQUEST INTAKE
            </div>

            <h1>
                Start a Security Check
            </h1>

            <p class="muted">
                Submit your target and exact scope.
                No automated scanning is performed.
            </p>

            <form method="POST">

                <label>
                    Name
                </label>

                <input
                    name="name"
                    autocomplete="name"
                    required
                >

                <label>
                    Email
                </label>

                <input
                    name="email"
                    type="email"
                    autocomplete="email"
                    required
                >

                <label>
                    Target Website
                </label>

                <input
                    name="target"
                    placeholder="https://example.com"
                    required
                >

                <label>
                    Authorized Scope
                </label>

                <textarea
                    name="scope"
                    placeholder="Example: public web application only"
                    required
                ></textarea>

                <label>

                    <input
                        type="checkbox"
                        name="authorization"
                        required
                        style="width:auto"
                    >

                    I confirm I own or am authorized
                    to request testing for this target
                    within the scope above.

                </label>

                <br>

                <button type="submit">
                    CREATE REQUEST
                </button>

            </form>

        </div>
        """
    )


# =========================================================
# CLIENT STATUS
# =========================================================

@app.route("/status/<int:request_id>")
def request_status(request_id):

    item = get_request(request_id)

    if not item:
        return "Request not found.", 404

    conn = get_db()

    messages = conn.execute(
        """
        SELECT *
        FROM messages
        WHERE request_id = ?
        ORDER BY id
        """,
        (request_id,)
    ).fetchall()

    findings = conn.execute(
        """
        SELECT *
        FROM findings
        WHERE request_id = ?
        ORDER BY id
        """,
        (request_id,)
    ).fetchall()

    conn.execute(
        """
        UPDATE messages
        SET read_by_client = 1
        WHERE request_id = ?
        AND sender = 'matia'
        """,
        (request_id,)
    )

    conn.commit()
    conn.close()

    findings_html = ""

    for finding in findings:

        findings_html += f"""
        <div class="card">

            <h2>
                {esc(finding['code'])}
                —
                {esc(finding['title'])}
            </h2>

            <p>
                Severity:
                <span class="badge">
                    {esc(finding['severity'])}
                </span>
            </p>

            <h3>
                Evidence
            </h3>

            <pre>
{esc(finding['evidence'])}
            </pre>

            <h3>
                Impact
            </h3>

            <pre>
{esc(finding['impact'])}
            </pre>

            <h3>
                Recommendation
            </h3>

            <pre>
{esc(finding['recommendation'])}
            </pre>

        </div>
        """

    scripts = f"""
    <script>

    let lastUnread = 0;

    async function askNotifications() {{

        if (
            "Notification" in window &&
            Notification.permission === "default"
        ) {{

            try {{
                await Notification.requestPermission();
            }} catch (_) {{}}

        }}

    }}


    async function checkNotifications() {{

        try {{

            const r = await fetch(
                "/api/client/{request_id}/notifications",
                {{ cache: "no-store" }}
            );

            if (!r.ok) return;

            const data = await r.json();

            const box =
                document.getElementById(
                    "clientNotification"
                );

            const text =
                document.getElementById(
                    "clientNotificationText"
                );

            if (data.unread > 0) {{

                text.textContent =
                    "🔔 " +
                    data.unread +
                    " new message" +
                    (
                        data.unread === 1
                        ? ""
                        : "s"
                    ) +
                    " from Matia";

                box.classList.add("show");

                if (
                    data.unread > lastUnread &&
                    "Notification" in window &&
                    Notification.permission === "granted"
                ) {{

                    try {{
                        new Notification(
                            "MATIA // SECURITY CHECK",
                            {{
                                body:
                                    "You have a new message from Matia."
                            }}
                        );
                    }} catch (_) {{}}

                }}

            }} else {{

                box.classList.remove("show");

            }}

            lastUnread = data.unread;

        }} catch (_) {{}}

    }}


    async function refreshMessages() {{

        try {{

            const r = await fetch(
                "/api/client/{request_id}/messages",
                {{ cache: "no-store" }}
            );

            if (!r.ok) return;

            const data = await r.json();

            const box =
                document.getElementById(
                    "clientMessages"
                );

            const shouldScroll =
                box.scrollTop +
                box.clientHeight >=
                box.scrollHeight - 100;

            box.innerHTML = data.html;

            if (shouldScroll) {{
                box.scrollTop =
                    box.scrollHeight;
            }}

        }} catch (_) {{}}

    }}


    async function sendClientMessage(event) {{

        event.preventDefault();

        const input =
            document.getElementById(
                "clientMessage"
            );

        const button =
            document.getElementById(
                "clientSend"
            );

        const message =
            input.value.trim();

        if (!message) return;

        button.disabled = true;

        try {{

            const r = await fetch(
                "/status/{request_id}/message",
                {{
                    method: "POST",
                    headers: {{
                        "Content-Type":
                            "application/x-www-form-urlencoded"
                    }},
                    body:
                        "message=" +
                        encodeURIComponent(message)
                }}
            );

            if (r.ok) {{
                input.value = "";
                await refreshMessages();
            }}

        }} finally {{
            button.disabled = false;
        }}

    }}


    document.addEventListener(
        "DOMContentLoaded",
        function() {{

            askNotifications();

            document
                .getElementById("clientChatForm")
                .addEventListener(
                    "submit",
                    sendClientMessage
                );

            setInterval(
                checkNotifications,
                2000
            );

            setInterval(
                refreshMessages,
                2500
            );

            checkNotifications();

        }}
    );

    </script>
    """

    return page(
        f"Request #{request_id}",

        f"""

        <div
            id="clientNotification"
            class="notification"
        >
            <span id="clientNotificationText">
                New message
            </span>
            <span>💬</span>
        </div>

        <div class="card">

            <div class="hero-badge">
                REQUEST #{item['id']}
            </div>

            <h1>
                Assessment Workspace
            </h1>

            <p>
                <b>Status:</b>
                <span class="badge">
                    {esc(item['status'])}
                </span>
            </p>

            <p>
                <b>Target:</b>
                {esc(item['target'])}
            </p>

            <div class="ip-box">

                <b>
                    Resolved Target IP
                </b>

                <br><br>

                {esc(item['target_ip'])}

                <p class="muted">
                    DNS resolution only.
                    Automatic target scanning is disabled.
                </p>

            </div>

            <h3>
                Authorized Scope
            </h3>

            <pre>
{esc(item['scope'])}
            </pre>

        </div>


        <div class="card">

            <h2>
                💬 MATIA CHAT
            </h2>

            <div class="chat-shell">

                <div class="chat-header">

                    <strong>
                        Assessment Support
                    </strong>

                    <span class="chat-online">
                        ● LIVE
                    </span>

                </div>

                <div
                    id="clientMessages"
                    class="chat-box"
                >
                    {render_messages(messages)}
                </div>

                <div class="chat-compose">

                    <form id="clientChatForm">

                        <textarea
                            id="clientMessage"
                            placeholder="Write a message to Matia..."
                            required
                        ></textarea>

                        <div class="chat-actions">

                            <button
                                id="clientSend"
                                type="submit"
                            >
                                SEND MESSAGE
                            </button>

                        </div>

                    </form>

                </div>

            </div>

        </div>


        {findings_html}

        """,

        scripts
    )


# =========================================================
# CLIENT MESSAGE
# =========================================================

@app.post("/status/<int:request_id>/message")
def client_message(request_id):

    if not get_request(request_id):
        return jsonify({
            "error": "Request not found"
        }), 404

    message = request.form.get(
        "message",
        ""
    ).strip()

    if not message:
        return jsonify({
            "error": "Empty message"
        }), 400

    if len(message) > 4000:
        return jsonify({
            "error": "Message too long"
        }), 400

    conn = get_db()

    conn.execute(
        """
        INSERT INTO messages
        (
            request_id,
            sender,
            message,
            created,
            read_by_client,
            read_by_admin
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            request_id,
            "client",
            message,
            now(),
            1,
            0
        )
    )

    conn.commit()
    conn.close()

    return jsonify({
        "success": True
    })


# =========================================================
# CLIENT API
# =========================================================

@app.get(
    "/api/client/<int:request_id>/notifications"
)
def client_notifications(request_id):

    if not get_request(request_id):
        return jsonify({
            "error": "Request not found"
        }), 404

    conn = get_db()

    count = conn.execute(
        """
        SELECT COUNT(*) AS total
        FROM messages
        WHERE request_id = ?
        AND sender = 'matia'
        AND read_by_client = 0
        """,
        (request_id,)
    ).fetchone()["total"]

    conn.close()

    return jsonify({
        "unread": count
    })


@app.get(
    "/api/client/<int:request_id>/messages"
)
def client_messages(request_id):

    if not get_request(request_id):
        return jsonify({
            "error": "Request not found"
        }), 404

    conn = get_db()

    messages = conn.execute(
        """
        SELECT *
        FROM messages
        WHERE request_id = ?
        ORDER BY id
        """,
        (request_id,)
    ).fetchall()

    conn.close()

    return jsonify({
        "html": render_messages(messages)
    })


# =========================================================
# ADMIN LOGIN
# =========================================================

@app.route(
    "/admin/login",
    methods=["GET", "POST"]
)
def admin_login():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        if not ADMIN_USER or not ADMIN_PASSWORD:
            return (
                "MATIA_ADMIN_USER and "
                "MATIA_ADMIN_PASSWORD must be "
                "configured in Render.",
                500
            )

        valid_user = secrets.compare_digest(
            username,
            ADMIN_USER
        )

        valid_password = secrets.compare_digest(
            password,
            ADMIN_PASSWORD
        )

        if valid_user and valid_password:

            session.clear()
            session["admin"] = True

            return redirect(
                url_for("admin_panel")
            )

        return (
            "Invalid username or password.",
            401
        )

    return page(
        "Admin Login",
        """
        <div
            class="card"
            style="max-width:460px;margin:60px auto"
        >

            <div class="hero-badge">
                ADMIN ACCESS
            </div>

            <h1>
                MATIA CONTROL
            </h1>

            <p class="muted">
                Authorized administrator login.
            </p>

            <form method="POST">

                <label>
                    Username
                </label>

                <input
                    name="username"
                    autocomplete="username"
                    required
                >

                <label>
                    Password
                </label>

                <input
                    name="password"
                    type="password"
                    autocomplete="current-password"
                    required
                >

                <button
                    type="submit"
                    style="width:100%"
                >
                    ENTER CONTROL CENTER
                </button>

            </form>

        </div>
        """
    )


# =========================================================
# ADMIN NOTIFICATIONS
# =========================================================

@app.get("/api/admin/notifications")
@admin_required
def admin_notifications():

    conn = get_db()

    count = conn.execute(
        """
        SELECT COUNT(*) AS total
        FROM messages
        WHERE sender = 'client'
        AND read_by_admin = 0
        """
    ).fetchone()["total"]

    conn.close()

    return jsonify({
        "unread": count
    })


# =========================================================
# ADMIN DASHBOARD
# =========================================================

@app.route("/admin")
@admin_required
def admin_panel():

    conn = get_db()

    requests_list = conn.execute(
        """
        SELECT *
        FROM requests
        ORDER BY id DESC
        """
    ).fetchall()

    pending = conn.execute(
        """
        SELECT COUNT(*) AS total
        FROM requests
        WHERE status = 'PENDING'
        """
    ).fetchone()["total"]

    accepted = conn.execute(
        """
        SELECT COUNT(*) AS total
        FROM requests
        WHERE status = 'ACCEPTED'
        """
    ).fetchone()["total"]

    completed = conn.execute(
        """
        SELECT COUNT(*) AS total
        FROM requests
        WHERE status = 'COMPLETED'
        """
    ).fetchone()["total"]

    conn.close()

    rows = ""

    for item in requests_list:

        rows += f"""
        <tr>

            <td>
                <strong>#{item['id']}</strong>
            </td>

            <td>
                {esc(item['name'])}
            </td>

            <td>
                {esc(item['target'])}
            </td>

            <td>

                <span class="badge">
                    {esc(item['status'])}
                </span>

            </td>

            <td>

                <a href="/admin/request/{item['id']}">
                    OPEN →
                </a>

            </td>

        </tr>
        """

    if not rows:

        rows = """
        <tr>
            <td colspan="5">
                <span class="muted">
                    No requests yet.
                </span>
            </td>
        </tr>
        """

    scripts = """

    <script>

    let lastUnread = 0;

    async function checkAdminNotifications() {

        try {

            const r = await fetch(
                "/api/admin/notifications",
                { cache: "no-store" }
            );

            if (!r.ok) return;

            const data = await r.json();

            const box =
                document.getElementById(
                    "adminNotification"
                );

            const text =
                document.getElementById(
                    "adminNotificationText"
                );

            if (data.unread > 0) {

                text.textContent =
                    "🔔 " +
                    data.unread +
                    " new client message" +
                    (
                        data.unread === 1
                        ? ""
                        : "s"
                    );

                box.classList.add("show");

                if (
                    data.unread > lastUnread &&
                    "Notification" in window &&
                    Notification.permission === "granted"
                ) {

                    try {

                        new Notification(
                            "MATIA // SECURITY CHECK",
                            {
                                body:
                                    "A client sent you a new message."
                            }
                        );

                    } catch (_) {}

                }

            } else {

                box.classList.remove("show");

            }

            lastUnread = data.unread;

        } catch (_) {}

    }


    document.addEventListener(
        "DOMContentLoaded",
        function() {

            if (
                "Notification" in window &&
                Notification.permission === "default"
            ) {
                Notification.requestPermission()
                    .catch(function(){});
            }

            checkAdminNotifications();

            setInterval(
                checkAdminNotifications,
                2000
            );

        }
    );

    </script>

    """

    return page(
        "MATIA Control Center",

        f"""

        <div
            id="adminNotification"
            class="notification"
        >
            <span id="adminNotificationText">
                New message
            </span>
            <span>💬</span>
        </div>


        <div class="card">

            <div class="hero-badge">
                CONTROL CENTER
            </div>

            <h1>
                MATIA ADMIN
            </h1>

            <p class="muted">
                Security assessment operations dashboard.
            </p>

        </div>


        <div class="stat-grid">

            <div class="stat">
                <div class="muted">
                    PENDING
                </div>
                <div class="stat-number">
                    {pending}
                </div>
            </div>

            <div class="stat">
                <div class="muted">
                    ACCEPTED
                </div>
                <div class="stat-number">
                    {accepted}
                </div>
            </div>

            <div class="stat">
                <div class="muted">
                    COMPLETED
                </div>
                <div class="stat-number">
                    {completed}
                </div>
            </div>

            <div class="stat">
                <div class="muted">
                    TOTAL
                </div>
                <div class="stat-number">
                    {len(requests_list)}
                </div>
            </div>

        </div>


        <div class="card">

            <h2>
                REQUEST QUEUE
            </h2>

            <table>

                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Client</th>
                        <th>Target</th>
                        <th>Status</th>
                        <th>Open</th>
                    </tr>
                </thead>

                <tbody>
                    {rows}
                </tbody>

            </table>

        </div>


        <div class="card">

            <a href="/admin/logout">
                LOG OUT
            </a>

        </div>

        """,

        scripts
    )


# =========================================================
# ADMIN REQUEST
# =========================================================

@app.route(
    "/admin/request/<int:request_id>",
    methods=["GET", "POST"]
)
@admin_required
def admin_request(request_id):

    item = get_request(request_id)

    if not item:
        return "Request not found.", 404

    conn = get_db()

    if request.method == "POST":

        action = request.form.get(
            "action"
        )

        if action == "accept":

            conn.execute(
                """
                UPDATE requests
                SET status = 'ACCEPTED'
                WHERE id = ?
                """,
                (request_id,)
            )

        elif action == "decline":

            conn.execute(
                """
                UPDATE requests
                SET status = 'DECLINED'
                WHERE id = ?
                """,
                (request_id,)
            )

        elif action == "complete":

            conn.execute(
                """
                UPDATE requests
                SET status = 'COMPLETED'
                WHERE id = ?
                """,
                (request_id,)
            )

        conn.commit()

        item = conn.execute(
            """
            SELECT *
            FROM requests
            WHERE id = ?
            """,
            (request_id,)
        ).fetchone()

    # Opening request marks client messages as read.
    conn.execute(
        """
        UPDATE messages
        SET read_by_admin = 1
        WHERE request_id = ?
        AND sender = 'client'
        """,
        (request_id,)
    )

    messages = conn.execute(
        """
        SELECT *
        FROM messages
        WHERE request_id = ?
        ORDER BY id
        """,
        (request_id,)
    ).fetchall()

    findings = conn.execute(
        """
        SELECT *
        FROM findings
        WHERE request_id = ?
        ORDER BY id
        """,
        (request_id,)
    ).fetchall()

    conn.commit()
    conn.close()

    findings_html = ""

    for finding in findings:

        findings_html += f"""
        <div class="card">

            <h2>
                {esc(finding['code'])}
                —
                {esc(finding['title'])}
            </h2>

            <p>
                Severity:
                <span class="badge">
                    {esc(finding['severity'])}
                </span>
            </p>

            <h3>Evidence</h3>

            <pre>
{esc(finding['evidence'])}
            </pre>

            <h3>Impact</h3>

            <pre>
{esc(finding['impact'])}
            </pre>

            <h3>Recommendation</h3>

            <pre>
{esc(finding['recommendation'])}
            </pre>

        </div>
        """

    scripts = f"""

    <script>

    let lastUnread = 0;


    async function checkNotifications() {{

        try {{

            const r = await fetch(
                "/api/admin/notifications",
                {{ cache: "no-store" }}
            );

            if (!r.ok) return;

            const data = await r.json();

            const box =
                document.getElementById(
                    "requestNotification"
                );

            const text =
                document.getElementById(
                    "requestNotificationText"
                );

            if (data.unread > 0) {{

                text.textContent =
                    "🔔 " +
                    data.unread +
                    " new client message" +
                    (
                        data.unread === 1
                        ? ""
                        : "s"
                    );

                box.classList.add("show");

            }} else {{

                box.classList.remove("show");

            }}

            if (
                data.unread > lastUnread &&
                "Notification" in window &&
                Notification.permission === "granted"
            ) {{

                try {{
                    new Notification(
                        "MATIA // SECURITY CHECK",
                        {{
                            body:
                                "A client sent a new message."
                        }}
                    );
                }} catch (_) {{}}

            }}

            lastUnread = data.unread;

        }} catch (_) {{}}

    }}


    async function refreshChat() {{

        try {{

            const r = await fetch(
                "/api/admin/request/{request_id}/messages",
                {{ cache: "no-store" }}
            );

            if (!r.ok) return;

            const data = await r.json();

            const box =
                document.getElementById(
                    "adminMessages"
                );

            const atBottom =
                box.scrollTop +
                box.clientHeight >=
                box.scrollHeight - 100;

            box.innerHTML = data.html;

            if (atBottom) {{
                box.scrollTop =
                    box.scrollHeight;
            }}

        }} catch (_) {{}}

    }}


    async function sendAdminMessage(event) {{

        event.preventDefault();

        const input =
            document.getElementById(
                "adminMessage"
            );

        const button =
            document.getElementById(
                "adminSend"
            );

        const message =
            input.value.trim();

        if (!message) return;

        button.disabled = true;

        try {{

            const r = await fetch(
                "/admin/request/{request_id}/message",
                {{
                    method: "POST",
                    headers: {{
                        "Content-Type":
                            "application/x-www-form-urlencoded"
                    }},
                    body:
                        "message=" +
                        encodeURIComponent(message)
                }}
            );

            if (r.ok) {{
                input.value = "";
                await refreshChat();
            }}

        }} finally {{
            button.disabled = false;
        }}

    }}


    document.addEventListener(
        "DOMContentLoaded",
        function() {{

            if (
                "Notification" in window &&
                Notification.permission === "default"
            ) {{
                Notification.requestPermission()
                    .catch(function(){{}});
            }}

            document
                .getElementById("adminChatForm")
                .addEventListener(
                    "submit",
                    sendAdminMessage
                );

            checkNotifications();

            setInterval(
                checkNotifications,
                2000
            );

            setInterval(
                refreshChat,
                2500
            );

        }}
    );

    </script>

    """

    return page(
        f"Request #{request_id}",

        f"""

        <div
            id="requestNotification"
            class="notification"
        >
            <span id="requestNotificationText">
                New client message
            </span>
            <span>💬</span>
        </div>


        <div class="card">

            <div class="hero-badge">
                REQUEST #{item['id']}
            </div>

            <h1>
                CLIENT ASSESSMENT
            </h1>

            <div class="stat-grid">

                <div class="stat">
                    <div class="muted">
                        STATUS
                    </div>
                    <div>
                        <span class="badge">
                            {esc(item['status'])}
                        </span>
                    </div>
                </div>

                <div class="stat">
                    <div class="muted">
                        CLIENT
                    </div>
                    <div>
                        {esc(item['name'])}
                    </div>
                </div>

                <div class="stat">
                    <div class="muted">
                        TARGET
                    </div>
                    <div>
                        {esc(item['target'])}
                    </div>
                </div>

            </div>

            <p>
                <b>Email:</b>
                {esc(item['email'])}
            </p>

            <p>
                <b>Client IP:</b>
                {esc(item['client_ip'])}
            </p>

            <div class="ip-box">

                <b>
                    Resolved Target IP
                </b>

                <br><br>

                {esc(item['target_ip'])}

            </div>

            <h3>
                Authorized Scope
            </h3>

            <pre>
{esc(item['scope'])}
            </pre>

        </div>


        <div class="card">

            <form method="POST">

                <button
                    name="action"
                    value="accept"
                    class="green"
                >
                    ACCEPT
                </button>

                <button
                    name="action"
                    value="decline"
                    class="red"
                >
                    DECLINE
                </button>

                <button
                    name="action"
                    value="complete"
                    class="secondary"
                >
                    COMPLETE
                </button>

            </form>

        </div>


        <div class="card">

            <h2>
                💬 LIVE CLIENT CHAT
            </h2>

            <div class="chat-shell">

                <div class="chat-header">

                    <strong>
                        Client #{item['id']}
                    </strong>

                    <span class="chat-online">
                        ● LIVE
                    </span>

                </div>

                <div
                    id="adminMessages"
                    class="chat-box"
                >
                    {render_messages(messages)}
                </div>

                <div class="chat-compose">

                    <form id="adminChatForm">

                        <textarea
                            id="adminMessage"
                            placeholder="Write a message to the client..."
                            required
                        ></textarea>

                        <div class="chat-actions">

                            <button
                                id="adminSend"
                                type="submit"
                            >
                                SEND MESSAGE
                            </button>

                        </div>

                    </form>

                </div>

            </div>

        </div>


        <div class="card">

            <h2>
                ADD FINDING
            </h2>

            <form
                method="POST"
                action="/admin/request/{request_id}/finding"
            >

                <label>
                    Finding ID
                </label>

                <input
                    name="code"
                    placeholder="F-001"
                    required
                >

                <label>
                    Title
                </label>

                <input
                    name="title"
                    placeholder="Information Disclosure"
                    required
                >

                <label>
                    Severity
                </label>

                <select name="severity">

                    <option>Informational</option>
                    <option>Low</option>
                    <option>Low-Medium</option>
                    <option>Medium</option>
                    <option>High</option>
                    <option>Critical</option>

                </select>

                <label>
                    Evidence
                </label>

                <textarea
                    name="evidence"
                    required
                ></textarea>

                <label>
                    Impact
                </label>

                <textarea
                    name="impact"
                    required
                ></textarea>

                <label>
                    Recommendation
                </label>

                <textarea
                    name="recommendation"
                    required
                ></textarea>

                <button type="submit">
                    ADD FINDING
                </button>

            </form>

        </div>


        {findings_html}


        <div class="card">

            <a
                href="/admin/request/{request_id}/report"
            >
                <button class="secondary">
                    OPEN FINAL REPORT
                </button>
            </a>

        </div>

        """,

        scripts
    )


# =========================================================
# ADMIN MESSAGE
# =========================================================

@app.post(
    "/admin/request/<int:request_id>/message"
)
@admin_required
def admin_message(request_id):

    if not get_request(request_id):
        return jsonify({
            "error": "Request not found"
        }), 404

    message = request.form.get(
        "message",
        ""
    ).strip()

    if not message:
        return jsonify({
            "error": "Empty message"
        }), 400

    if len(message) > 4000:
        return jsonify({
            "error": "Message too long"
        }), 400

    conn = get_db()

    conn.execute(
        """
        INSERT INTO messages
        (
            request_id,
            sender,
            message,
            created,
            read_by_client,
            read_by_admin
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            request_id,
            "matia",
            message,
            now(),
            0,
            1
        )
    )

    item = conn.execute(
        """
        SELECT status
        FROM requests
        WHERE id = ?
        """,
        (request_id,)
    ).fetchone()

    if item and item["status"] == "ACCEPTED":

        conn.execute(
            """
            UPDATE requests
            SET status = 'IN_PROGRESS'
            WHERE id = ?
            """,
            (request_id,)
        )

    conn.commit()
    conn.close()

    return jsonify({
        "success": True
    })


# =========================================================
# ADMIN CHAT API
# =========================================================

@app.get(
    "/api/admin/request/<int:request_id>/messages"
)
@admin_required
def admin_messages(request_id):

    if not get_request(request_id):
        return jsonify({
            "error": "Request not found"
        }), 404

    conn = get_db()

    messages = conn.execute(
        """
        SELECT *
        FROM messages
        WHERE request_id = ?
        ORDER BY id
        """,
        (request_id,)
    ).fetchall()

    conn.close()

    return jsonify({
        "html": render_messages(messages)
    })


# =========================================================
# FINDING
# =========================================================

@app.post(
    "/admin/request/<int:request_id>/finding"
)
@admin_required
def add_finding(request_id):

    if not get_request(request_id):
        return "Request not found.", 404

    fields = {
        "code": request.form.get(
            "code", ""
        ).strip(),

        "title": request.form.get(
            "title", ""
        ).strip(),

        "severity": request.form.get(
            "severity", ""
        ).strip(),

        "evidence": request.form.get(
            "evidence", ""
        ).strip(),

        "impact": request.form.get(
            "impact", ""
        ).strip(),

        "recommendation": request.form.get(
            "recommendation", ""
        ).strip(),
    }

    if not all(fields.values()):
        return (
            "Complete all finding fields.",
            400
        )

    conn = get_db()

    conn.execute(
        """
        INSERT INTO findings
        (
            request_id,
            code,
            title,
            severity,
            evidence,
            impact,
            recommendation
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            request_id,
            fields["code"],
            fields["title"],
            fields["severity"],
            fields["evidence"],
            fields["impact"],
            fields["recommendation"],
        )
    )

    conn.commit()
    conn.close()

    return redirect(
        url_for(
            "admin_request",
            request_id=request_id
        )
    )


# =========================================================
# REPORT
# =========================================================

@app.route(
    "/admin/request/<int:request_id>/report"
)
@admin_required
def report(request_id):

    item = get_request(request_id)

    if not item:
        return "Request not found.", 404

    conn = get_db()

    findings = conn.execute(
        """
        SELECT *
        FROM findings
        WHERE request_id = ?
        ORDER BY id
        """,
        (request_id,)
    ).fetchall()

    conn.close()

    findings_html = ""

    for finding in findings:

        findings_html += f"""
        <div class="card">

            <h2>
                {esc(finding['code'])}
                —
                {esc(finding['title'])}
            </h2>

            <p>
                Severity:
                <span class="badge">
                    {esc(finding['severity'])}
                </span>
            </p>

            <h3>Evidence</h3>

            <pre>
{esc(finding['evidence'])}
            </pre>

            <h3>Impact</h3>

            <pre>
{esc(finding['impact'])}
            </pre>

            <h3>Recommendation</h3>

            <pre>
{esc(finding['recommendation'])}
            </pre>

        </div>
        """

    return page(
        f"Security Report #{request_id}",

        f"""

        <div class="card">

            <div class="hero-badge">
                FINAL REPORT
            </div>

            <h1>
                WEB SECURITY ASSESSMENT
            </h1>

            <p>
                <b>Request:</b>
                #{item['id']}
            </p>

            <p>
                <b>Client:</b>
                {esc(item['name'])}
            </p>

            <p>
                <b>Target:</b>
                {esc(item['target'])}
            </p>

            <p>
                <b>Resolved IP:</b>
                {esc(item['target_ip'])}
            </p>

            <p>
                <b>Date:</b>
                {esc(
                    datetime.now().strftime(
                        "%Y-%m-%d"
                    )
                )}
            </p>

        </div>


        <div class="card">

            <h2>
                EXECUTIVE SUMMARY
            </h2>

            <p class="muted">
                This assessment was performed only
                within the client-authorized scope.
                The service is a basic assessment
                platform and does not guarantee complete
                security.
            </p>

        </div>


        {findings_html}


        <div class="card">

            <h2>
                FINAL STATEMENT
            </h2>

            <p class="muted">
                Testing was limited to the authorized
                target and scope.
            </p>

            <strong>
                MATIA // SECURITY CHECK
            </strong>

        </div>

        """
    )


# =========================================================
# LOGOUT
# =========================================================

@app.route("/admin/logout")
def admin_logout():

    session.clear()

    return redirect("/")


# =========================================================
# START
# =========================================================

if __name__ == "__main__":

    port = int(
        os.environ.get(
            "PORT",
            "5000"
        )
    )

    print("=" * 65)
    print("MATIA // SECURITY CHECK")
    print("FINAL BOSS EDITION")
    print("=" * 65)
    print("Host: 0.0.0.0")
    print("Port:", port)
    print("Live chat: ENABLED")
    print("Notifications: ENABLED")
    print("Automatic target scanning: DISABLED")
    print("=" * 65)

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )
