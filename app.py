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

app = Flask(__name__)

# =========================================================
# CONFIG
# =========================================================

ADMIN_USER = os.environ.get("MATIA_ADMIN_USER", "")
ADMIN_PASSWORD = os.environ.get("MATIA_ADMIN_PASSWORD", "")
SECRET_KEY = os.environ.get("MATIA_SECRET_KEY")

if not SECRET_KEY:
    SECRET_KEY = secrets.token_hex(32)

app.config["SECRET_KEY"] = SECRET_KEY
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = True

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


init_db()


# =========================================================
# HELPERS
# =========================================================

def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


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
            return redirect(url_for("admin_login"))
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

        return ", ".join(ips[:10]) if ips else "IP NOT FOUND"

    except socket.gaierror:
        return "IP NOT FOUND"

    except Exception:
        return "IP LOOKUP ERROR"


def status_info(status):
    data = {
        "PENDING": {
            "label": "Pending",
            "message": "Your request is waiting for review.",
            "class": "pending",
        },
        "ACCEPTED": {
            "label": "Accepted by Matia",
            "message": "Your security assessment has been accepted by Matia.",
            "class": "accepted",
        },
        "IN_PROGRESS": {
            "label": "Assessment in progress",
            "message": "Your security assessment is currently in progress.",
            "class": "progress",
        },
        "COMPLETED": {
            "label": "Assessment completed",
            "message": "Your security assessment has been completed.",
            "class": "completed",
        },
        "DECLINED": {
            "label": "Declined by Matia",
            "message": "This request was declined by Matia.",
            "class": "declined",
        },
    }

    return data.get(
        status,
        {
            "label": status,
            "message": "Request status updated.",
            "class": "pending",
        }
    )


def render_messages(messages):
    if not messages:
        return """
        <div class="empty-chat">
            No messages yet.<br>
            Start the conversation.
        </div>
        """

    html = ""

    for msg in messages:
        sender = esc(msg["sender"])

        html += f"""
        <div class="message {sender}">

            <div class="message-top">
                <strong>{sender.upper()}</strong>
                <span>{esc(msg["created"])}</span>
            </div>

            <div class="message-text">
                {esc(msg["message"])}
            </div>

        </div>
        """

    return html


# =========================================================
# STYLE
# =========================================================

STYLE = """
<style>

:root {
    --black: #050505;
    --panel: #0b0b0b;
    --panel2: #101010;
    --border: #242424;
    --white: #f7f7f7;
    --gray: #9a9a9a;
    --soft: #d5d5d5;
    --green: #d7ffd9;
    --red: #ffd8d8;
}

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    background:
        radial-gradient(
            circle at top,
            #181818 0%,
            #080808 42%,
            #030303 100%
        );
    color: var(--white);
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
    opacity: .035;
    background-image:
        linear-gradient(
            rgba(255,255,255,.2) 1px,
            transparent 1px
        ),
        linear-gradient(
            90deg,
            rgba(255,255,255,.2) 1px,
            transparent 1px
        );
    background-size: 50px 50px;
}

nav {
    position: sticky;
    top: 0;
    z-index: 20;
    background: rgba(5,5,5,.82);
    backdrop-filter: blur(18px);
    border-bottom: 1px solid var(--border);
    padding: 18px 24px;
}

.nav-inner {
    max-width: 1180px;
    margin: auto;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.logo {
    font-size: 13px;
    font-weight: 900;
    letter-spacing: 3px;
}

.logo span {
    color: var(--gray);
}

.live-dot {
    font-size: 11px;
    color: #ddd;
    letter-spacing: 1px;
}

.container {
    max-width: 1180px;
    margin: auto;
    padding: 35px 20px 70px;
}

.card {
    background:
        linear-gradient(
            180deg,
            rgba(255,255,255,.025),
            rgba(255,255,255,.005)
        ),
        var(--panel);
    border: 1px solid var(--border);
    border-radius: 20px;
    padding: 26px;
    margin-bottom: 20px;
    box-shadow:
        0 20px 60px rgba(0,0,0,.28);
}

.hero {
    text-align: center;
    padding: 75px 25px;
}

.kicker {
    font-size: 11px;
    font-weight: 900;
    letter-spacing: 3px;
    color: var(--gray);
}

h1 {
    font-size: clamp(36px, 7vw, 68px);
    margin: 15px 0;
    letter-spacing: -3px;
}

h2 {
    margin-top: 0;
}

h1,
h2 {
    color: var(--white);
}

h3 {
    color: var(--soft);
}

p {
    line-height: 1.7;
}

.muted {
    color: var(--gray);
}

.grid {
    display: grid;
    grid-template-columns:
        repeat(auto-fit, minmax(220px, 1fr));
    gap: 16px;
}

input,
textarea,
select {
    width: 100%;
    background: #070707;
    color: white;
    border: 1px solid #303030;
    border-radius: 12px;
    padding: 14px;
    margin: 7px 0 17px;
    outline: none;
}

input:focus,
textarea:focus,
select:focus {
    border-color: #777;
}

textarea {
    min-height: 120px;
    resize: vertical;
}

button {
    border: 1px solid #444;
    border-radius: 12px;
    background: white;
    color: black;
    padding: 12px 18px;
    font-weight: 900;
    cursor: pointer;
    transition: .16s ease;
}

button:hover {
    transform: translateY(-1px);
    background: #eaeaea;
}

button:disabled {
    opacity: .45;
    cursor: wait;
}

.btn-dark {
    background: #111;
    color: white;
    border-color: #333;
}

.btn-danger {
    background: #171717;
    color: #ffdddd;
    border-color: #553333;
}

.btn-success {
    background: #f2fff2;
    color: #111;
}

a {
    color: white;
    text-decoration: none;
}

.badge {
    display: inline-block;
    border: 1px solid #373737;
    border-radius: 999px;
    padding: 5px 10px;
    background: #101010;
    font-size: 12px;
    font-weight: 900;
}

.status-card {
    border-radius: 18px;
    padding: 22px;
    border: 1px solid var(--border);
    background: #090909;
}

.status-title {
    font-size: 25px;
    font-weight: 900;
    margin-bottom: 7px;
}

.status-message {
    color: var(--gray);
}

.status-pending {
    border-left: 4px solid #777;
}

.status-accepted {
    border-left: 4px solid #eee;
}

.status-progress {
    border-left: 4px solid #bbb;
}

.status-completed {
    border-left: 4px solid white;
}

.status-declined {
    border-left: 4px solid #777;
    background:
        linear-gradient(
            90deg,
            rgba(255,255,255,.035),
            transparent
        );
}

.notification {
    display: none;
    padding: 14px 17px;
    border: 1px solid #555;
    background: #111;
    border-radius: 14px;
    margin-bottom: 18px;
    font-weight: 800;
}

.notification.show {
    display: flex;
    justify-content: space-between;
}

.chat {
    border: 1px solid var(--border);
    border-radius: 17px;
    overflow: hidden;
    background: #070707;
}

.chat-head {
    border-bottom: 1px solid var(--border);
    padding: 14px 16px;
    display: flex;
    justify-content: space-between;
}

.chat-live {
    color: #d8d8d8;
    font-size: 11px;
    letter-spacing: 1px;
}

.chat-box {
    min-height: 280px;
    max-height: 510px;
    overflow-y: auto;
    padding: 15px;
}

.message {
    width: min(82%, 700px);
    background: #0f0f0f;
    border: 1px solid #252525;
    border-radius: 14px;
    padding: 12px 14px;
    margin: 9px 0;
}

.message.client {
    border-left: 3px solid #aaa;
}

.message.matia {
    margin-left: auto;
    border-right: 3px solid white;
}

.message-top {
    display: flex;
    justify-content: space-between;
    gap: 15px;
    color: #aaa;
    font-size: 11px;
}

.message-text {
    margin-top: 8px;
    line-height: 1.55;
    white-space: pre-wrap;
    word-break: break-word;
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
    padding: 13px 9px;
    border-bottom: 1px solid var(--border);
}

th {
    color: var(--gray);
    font-size: 11px;
    letter-spacing: 1px;
}

.stat-grid {
    display: grid;
    grid-template-columns:
        repeat(auto-fit, minmax(170px, 1fr));
    gap: 12px;
}

.stat {
    background: #090909;
    border: 1px solid var(--border);
    border-radius: 15px;
    padding: 18px;
}

.stat-number {
    font-size: 28px;
    font-weight: 950;
    margin-top: 8px;
}

.ip-box {
    background: #080808;
    border: 1px solid #262626;
    border-radius: 14px;
    padding: 15px;
    margin: 15px 0;
}

pre {
    white-space: pre-wrap;
    word-break: break-word;
    line-height: 1.6;
}

.empty-chat {
    text-align: center;
    padding: 65px 20px;
    color: var(--gray);
}

.footer {
    text-align: center;
    padding: 25px;
    color: #666;
    font-size: 11px;
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
                content="width=device-width,initial-scale=1"
            >

            <meta
                name="theme-color"
                content="#050505"
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

                    <div class="live-dot">
                        ● SYSTEM ONLINE
                    </div>

                </div>

            </nav>

            <main class="container">
                {content}
            </main>

            <div class="footer">
                MATIA // SECURITY CHECK
                • AUTHORIZED ASSESSMENT PLATFORM
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
        <div class="card hero">

            <div class="kicker">
                AUTHORIZED SECURITY ASSESSMENT
            </div>

            <h1>
                MATIA<br>
                SECURITY CHECK
            </h1>

            <p class="muted">
                A minimalist workspace for authorized
                security assessment requests,
                communication and reporting.
            </p>

            <br>

            <a href="/request">
                <button>
                    REQUEST SECURITY CHECK
                </button>
            </a>

        </div>

        <div class="grid">

            <div class="card">
                <div class="kicker">01</div>
                <h2>REQUEST</h2>
                <p class="muted">
                    Submit the target and authorized scope.
                </p>
            </div>

            <div class="card">
                <div class="kicker">02</div>
                <h2>REVIEW</h2>
                <p class="muted">
                    Matia reviews the request.
                </p>
            </div>

            <div class="card">
                <div class="kicker">03</div>
                <h2>LIVE CHAT</h2>
                <p class="muted">
                    Communicate directly through
                    the private assessment workspace.
                </p>
            </div>

            <div class="card">
                <div class="kicker">04</div>
                <h2>REPORT</h2>
                <p class="muted">
                    Document confirmed findings
                    and recommendations.
                </p>
            </div>

        </div>

        <div class="card">
            <h2>AUTHORIZED USE ONLY</h2>
            <p class="muted">
                Only request testing for systems you
                own or are explicitly authorized to test.
            </p>
        </div>
        """
    )


# =========================================================
# CREATE REQUEST
# =========================================================

@app.route("/request", methods=["GET", "POST"])
def create_request():

    if request.method == "POST":

        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        target = request.form.get("target", "").strip()
        scope = request.form.get("scope", "").strip()
        authorization = request.form.get("authorization")

        if not all([
            name,
            email,
            target,
            scope
        ]):
            return "Please complete all fields.", 400

        if not authorization:
            return (
                "Authorization confirmation is required.",
                400
            )

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
                resolve_target_ip(target),
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

            <div class="kicker">
                REQUEST INTAKE
            </div>

            <h1>
                Start a Security Check
            </h1>

            <p class="muted">
                Submit your target and exact authorized scope.
            </p>

            <form method="POST">

                <label>Name</label>

                <input
                    name="name"
                    required
                >

                <label>Email</label>

                <input
                    name="email"
                    type="email"
                    required
                >

                <label>Target Website</label>

                <input
                    name="target"
                    placeholder="https://example.com"
                    required
                >

                <label>Authorized Scope</label>

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

                    I confirm that I own or am authorized
                    to request testing for this target.

                </label>

                <br><br>

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

    conn.close()

    status = status_info(item["status"])

    findings_html = ""

    for finding in findings:

        findings_html += f"""
        <div class="card">

            <div class="kicker">
                {esc(finding['code'])}
            </div>

            <h2>
                {esc(finding['title'])}
            </h2>

            <p>
                <span class="badge">
                    {esc(finding['severity'])}
                </span>
            </p>

            <h3>Evidence</h3>
            <pre>{esc(finding['evidence'])}</pre>

            <h3>Impact</h3>
            <pre>{esc(finding['impact'])}</pre>

            <h3>Recommendation</h3>
            <pre>{esc(finding['recommendation'])}</pre>

        </div>
        """

    scripts = f"""
    <script>

    let lastUnread = 0;
    let lastStatus = "{esc(item['status'])}";

    async function updateStatus() {{

        try {{

            const r = await fetch(
                "/api/client/{request_id}/status",
                {{ cache: "no-store" }}
            );

            if (!r.ok) return;

            const data = await r.json();

            const card =
                document.getElementById(
                    "statusCard"
                );

            card.className =
                "status-card status-" +
                data.class_name;

            document.getElementById(
                "statusTitle"
            ).textContent =
                data.label;

            document.getElementById(
                "statusMessage"
            ).textContent =
                data.message;

            if (
                data.status !== lastStatus &&
                "Notification" in window &&
                Notification.permission === "granted"
            ) {{

                try {{

                    new Notification(
                        "MATIA // SECURITY CHECK",
                        {{
                            body:
                                data.label +
                                " — " +
                                data.message
                        }}
                    );

                }} catch (_) {{}}
            }}

            lastStatus = data.status;

        }} catch (_) {{}}

    }}


    async function updateMessages() {{

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


    async function notifications() {{

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
                    "NEW MESSAGE • " +
                    data.unread;

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
                                    "Matia sent you a new message."
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


    async function sendMessage(event) {{

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
                updateMessages();
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
                .getElementById("clientChatForm")
                .addEventListener(
                    "submit",
                    sendMessage
                );

            updateStatus();
            updateMessages();
            notifications();

            setInterval(
                updateStatus,
                2000
            );

            setInterval(
                updateMessages,
                2500
            );

            setInterval(
                notifications,
                2000
            );

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
                NEW MESSAGE
            </span>
            <span>💬</span>
        </div>


        <div class="card">

            <div class="kicker">
                REQUEST #{item['id']}
            </div>

            <h1>
                Assessment Workspace
            </h1>

            <div
                id="statusCard"
                class="status-card status-{status['class']}"
            >

                <div
                    id="statusTitle"
                    class="status-title"
                >
                    {esc(status['label'])}
                </div>

                <div
                    id="statusMessage"
                    class="status-message"
                >
                    {esc(status['message'])}
                </div>

            </div>

            <p>
                <strong>Target:</strong>
                {esc(item['target'])}
            </p>

            <div class="ip-box">

                <strong>
                    Resolved Target IP
                </strong>

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

            <div class="chat">

                <div class="chat-head">

                    <strong>
                        Assessment Support
                    </strong>

                    <span class="chat-live">
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
# CLIENT STATUS API
# =========================================================

@app.get("/api/client/<int:request_id>/status")
def client_status(request_id):

    item = get_request(request_id)

    if not item:
        return jsonify({
            "error": "Request not found"
        }), 404

    info = status_info(item["status"])

    return jsonify({
        "status": item["status"],
        "label": info["label"],
        "message": info["message"],
        "class_name": info["class"]
    })


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
# CLIENT MESSAGE APIs
# =========================================================

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


@app.get(
    "/api/client/<int:request_id>/notifications"
)
def client_notifications(request_id):

    if not get_request(request_id):
        return jsonify({
            "error": "Request not found"
        }), 404

    conn = get_db()

    unread = conn.execute(
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
        "unread": unread
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
                "Admin credentials are not configured.",
                500
            )

        if (
            secrets.compare_digest(
                username,
                ADMIN_USER
            )
            and
            secrets.compare_digest(
                password,
                ADMIN_PASSWORD
            )
        ):

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
            style="max-width:460px;margin:70px auto"
        >

            <div class="kicker">
                ADMIN ACCESS
            </div>

            <h1>
                MATIA CONTROL
            </h1>

            <p class="muted">
                Authorized administrator access only.
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

    unread = conn.execute(
        """
        SELECT COUNT(*) AS total
        FROM messages
        WHERE sender = 'client'
        AND read_by_admin = 0
        """
    ).fetchone()["total"]

    conn.close()

    return jsonify({
        "unread": unread
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

    conn.close()

    rows = ""

    for item in requests_list:

        rows += f"""
        <tr>

            <td>
                #{item['id']}
            </td>

            <td>
                {esc(item['name'])}
            </td>

            <td>
                {esc(item['target'])}
            </td>

            <td>
                <span class="badge">
                    {esc(status_info(item['status'])['label'])}
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
                {cache:"no-store"}
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
                    "NEW CLIENT MESSAGE • " +
                    data.unread;

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
                NEW CLIENT MESSAGE
            </span>
            <span>💬</span>
        </div>


        <div class="card">

            <div class="kicker">
                CONTROL CENTER
            </div>

            <h1>
                MATIA ADMIN
            </h1>

            <p class="muted">
                Security assessment operations.
            </p>

        </div>


        <div class="card">

            <h2>
                REQUESTS
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

        action = request.form.get("action")

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

            <div class="kicker">
                {esc(finding['code'])}
            </div>

            <h2>
                {esc(finding['title'])}
            </h2>

            <p>
                <span class="badge">
                    {esc(finding['severity'])}
                </span>
            </p>

            <h3>Evidence</h3>
            <pre>{esc(finding['evidence'])}</pre>

            <h3>Impact</h3>
            <pre>{esc(finding['impact'])}</pre>

            <h3>Recommendation</h3>
            <pre>{esc(finding['recommendation'])}</pre>

        </div>
        """

    scripts = f"""

    <script>

    let lastUnread = 0;

    async function checkNotifications() {{

        try {{

            const r = await fetch(
                "/api/admin/notifications",
                {{cache:"no-store"}}
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

            if (data.unread > 0) {{

                text.textContent =
                    "NEW CLIENT MESSAGE • " +
                    data.unread;

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
                                    "A client sent a new message."
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


    async function refreshChat() {{

        try {{

            const r = await fetch(
                "/api/admin/request/{request_id}/messages",
                {{cache:"no-store"}}
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
                box.scrollTop = box.scrollHeight;
            }}

        }} catch (_) {{}}

    }}


    async function sendMessage(event) {{

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
                    method:"POST",
                    headers:{{
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
                refreshChat();
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
                    sendMessage
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

    status = status_info(item["status"])

    return page(
        f"Request #{request_id}",

        f"""

        <div
            id="adminNotification"
            class="notification"
        >
            <span id="adminNotificationText">
                NEW CLIENT MESSAGE
            </span>
            <span>💬</span>
        </div>


        <div class="card">

            <div class="kicker">
                REQUEST #{item['id']}
            </div>

            <h1>
                CLIENT ASSESSMENT
            </h1>

            <div
                class="status-card status-{status['class']}"
            >

                <div class="status-title">
                    {esc(status['label'])}
                </div>

                <div class="status-message">
                    {esc(status['message'])}
                </div>

            </div>

            <p>
                <strong>Client:</strong>
                {esc(item['name'])}
            </p>

            <p>
                <strong>Email:</strong>
                {esc(item['email'])}
            </p>

            <p>
                <strong>Target:</strong>
                {esc(item['target'])}
            </p>

            <div class="ip-box">

                <strong>
                    Resolved Target IP
                </strong>

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
                    class="btn-success"
                >
                    ACCEPT
                </button>

                <button
                    name="action"
                    value="decline"
                    class="btn-danger"
                >
                    DECLINE
                </button>

                <button
                    name="action"
                    value="complete"
                    class="btn-dark"
                >
                    COMPLETE
                </button>

            </form>

        </div>


        <div class="card">

            <h2>
                💬 LIVE CLIENT CHAT
            </h2>

            <div class="chat">

                <div class="chat-head">

                    <strong>
                        Client #{item['id']}
                    </strong>

                    <span class="chat-live">
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
                <button class="btn-dark">
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

    item = get_request(request_id)

    if not item:
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

    if item["status"] == "ACCEPTED":

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
        return "Complete all finding fields.", 400

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

    html = ""

    for finding in findings:

        html += f"""
        <div class="card">

            <div class="kicker">
                {esc(finding['code'])}
            </div>

            <h2>
                {esc(finding['title'])}
            </h2>

            <p>
                <span class="badge">
                    {esc(finding['severity'])}
                </span>
            </p>

            <h3>Evidence</h3>
            <pre>{esc(finding['evidence'])}</pre>

            <h3>Impact</h3>
            <pre>{esc(finding['impact'])}</pre>

            <h3>Recommendation</h3>
            <pre>{esc(finding['recommendation'])}</pre>

        </div>
        """

    return page(
        f"Security Report #{request_id}",

        f"""

        <div class="card">

            <div class="kicker">
                FINAL REPORT
            </div>

            <h1>
                WEB SECURITY ASSESSMENT
            </h1>

            <p>
                <strong>Request:</strong>
                #{item['id']}
            </p>

            <p>
                <strong>Client:</strong>
                {esc(item['name'])}
            </p>

            <p>
                <strong>Target:</strong>
                {esc(item['target'])}
            </p>

            <p>
                <strong>Resolved IP:</strong>
                {esc(item['target_ip'])}
            </p>

            <p>
                <strong>Date:</strong>
                {datetime.now().strftime("%Y-%m-%d")}
            </p>

        </div>

        <div class="card">

            <h2>
                EXECUTIVE SUMMARY
            </h2>

            <p class="muted">
                This assessment was performed only
                within the client-authorized scope.
                This is a basic assessment and does
                not guarantee complete security.
            </p>

        </div>

        {html}

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

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )
