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
    request,
    redirect,
    session,
    url_for,
    render_template_string,
    jsonify
)

# =========================================================
# MATIA // SECURITY CHECK
# =========================================================

app = Flask(__name__)

# =========================================================
# SECURITY CONFIG
# =========================================================

ADMIN_USER = os.environ.get("MATIA_ADMIN_USER", "")
ADMIN_PASSWORD = os.environ.get("MATIA_ADMIN_PASSWORD", "")
app.config["SECRET_KEY"] = os.environ.get(
    "MATIA_SECRET_KEY",
    "CHANGE-ME-IN-RENDER"
)

DB_FILE = os.environ.get(
    "DB_FILE",
    "matia_security.db"
)

# =========================================================
# DATABASE
# =========================================================

def get_db():
    conn = sqlite3.connect(DB_FILE)
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

    # -----------------------------------------------------
    # DATABASE MIGRATION FOR OLD DATABASES
    # -----------------------------------------------------

    columns = conn.execute(
        "PRAGMA table_info(messages)"
    ).fetchall()

    column_names = {
        row["name"] for row in columns
    }

    if "read_by_client" not in column_names:
        conn.execute("""
            ALTER TABLE messages
            ADD COLUMN read_by_client INTEGER NOT NULL DEFAULT 0
        """)

    if "read_by_admin" not in column_names:
        conn.execute("""
            ALTER TABLE messages
            ADD COLUMN read_by_admin INTEGER NOT NULL DEFAULT 0
        """)

    conn.commit()
    conn.close()


# Important for Render + Gunicorn
init_db()


# =========================================================
# HELPERS
# =========================================================

def now():
    return datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )


def e(value):
    return escape(str(value))


def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):

        if not session.get("admin"):
            return redirect(
                url_for("admin_login")
            )

        return func(*args, **kwargs)

    return wrapper


def get_request(request_id):

    conn = get_db()

    item = conn.execute(
        """
        SELECT *
        FROM requests
        WHERE id = ?
        """,
        (request_id,)
    ).fetchone()

    conn.close()

    return item


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


# =========================================================
# HTML
# =========================================================

STYLE = """

<style>

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    background: #05080c;
    color: #eaf3ff;
    font-family: Arial, sans-serif;
}

nav {
    background: #080d13;
    border-bottom: 1px solid #22313f;
    padding: 18px 25px;
}

.logo {
    color: #00eaff;
    font-weight: 900;
    letter-spacing: 2px;
}

.container {
    max-width: 1100px;
    margin: auto;
    padding: 30px 20px;
}

.card {
    background: #0c1219;
    border: 1px solid #22313f;
    border-radius: 15px;
    padding: 25px;
    margin-bottom: 20px;
}

.hero {
    text-align: center;
    padding: 55px 25px;
}

h1,
h2 {
    color: #00eaff;
}

h3 {
    color: #d8f8ff;
}

p {
    line-height: 1.6;
}

.muted {
    color: #8ea0b2;
}

input,
textarea,
select {
    width: 100%;
    background: #070b10;
    color: white;
    border: 1px solid #2a3948;
    border-radius: 9px;
    padding: 12px;
    margin-top: 7px;
    margin-bottom: 15px;
}

textarea {
    min-height: 120px;
    resize: vertical;
}

button {
    background: #00eaff;
    color: #031017;
    border: 0;
    border-radius: 9px;
    padding: 12px 18px;
    font-weight: 900;
    cursor: pointer;
}

button:hover {
    opacity: .9;
}

.green {
    background: #4ade80;
}

.red {
    background: #ff5757;
    color: white;
}

a {
    color: #00eaff;
    text-decoration: none;
}

.badge {
    display: inline-block;
    padding: 5px 10px;
    border-radius: 999px;
    background: #162532;
}

.notification {
    display: none;
    background: #00eaff;
    color: #031017;
    border-radius: 12px;
    padding: 14px 18px;
    margin-bottom: 20px;
    font-weight: 900;
}

.notification.show {
    display: block;
}

.chat-box {
    max-height: 500px;
    overflow-y: auto;
    margin-bottom: 15px;
}

.message {
    background: #080e14;
    border-left: 3px solid #566778;
    padding: 12px;
    margin: 8px 0;
    border-radius: 8px;
}

.message.matia {
    border-left-color: #00eaff;
}

.message.client {
    border-left-color: #4ade80;
}

.message-header {
    display: flex;
    justify-content: space-between;
    gap: 10px;
}

pre {
    white-space: pre-wrap;
    font-family: Arial, sans-serif;
    line-height: 1.5;
}

.ip-box {
    background: #071119;
    border: 1px solid #18313f;
    padding: 14px;
    border-radius: 10px;
    margin-top: 10px;
}

.grid {
    display: grid;
    grid-template-columns:
        repeat(auto-fit, minmax(220px, 1fr));
    gap: 15px;
}

table {
    width: 100%;
    border-collapse: collapse;
}

th,
td {
    text-align: left;
    padding: 12px;
    border-bottom: 1px solid #22313f;
}

.small-badge {
    display: inline-block;
    min-width: 24px;
    text-align: center;
    padding: 3px 7px;
    border-radius: 999px;
    background: #ff5757;
    color: white;
    font-size: 12px;
    font-weight: 900;
}

</style>

"""


def page(title, content, scripts=""):

    return render_template_string(
        f"""
        <!DOCTYPE html>
        <html>

        <head>

            <meta charset="UTF-8">

            <meta
                name="viewport"
                content="width=device-width,
                initial-scale=1.0"
            >

            <title>{e(title)}</title>

            {STYLE}

        </head>

        <body>

            <nav>

                <div class="logo">
                    MATIA // SECURITY CHECK
                </div>

            </nav>

            <div class="container">

                {content}

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
        "MATIA SECURITY CHECK",
        """
        <div class="card hero">

            <p class="muted">
                AUTHORIZED SECURITY ASSESSMENT
            </p>

            <h1>
                MATIA SECURITY CHECK
            </h1>

            <h2>
                FREE WEB SECURITY CHECK
            </h2>

            <p>
                Request a free basic security assessment
                for a website you own or are authorized to test.
            </p>

            <a href="/request">
                <button>
                    REQUEST FREE SECURITY CHECK
                </button>
            </a>

        </div>

        <div class="grid">

            <div class="card">
                <h2>01 — REQUEST</h2>
                <p class="muted">
                    Client submits the authorized target.
                </p>
            </div>

            <div class="card">
                <h2>02 — REVIEW</h2>
                <p class="muted">
                    Matia reviews the request.
                </p>
            </div>

            <div class="card">
                <h2>03 — CHAT</h2>
                <p class="muted">
                    Client and Matia can communicate directly.
                </p>
            </div>

            <div class="card">
                <h2>04 — REPORT</h2>
                <p class="muted">
                    Confirmed findings are documented.
                </p>
            </div>

        </div>
        """
    )


# =========================================================
# CREATE REQUEST
# =========================================================

@app.route("/request", methods=["GET", "POST"])
def create_request():

    if request.method == "POST":

        name = request.form.get(
            "name",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip()

        target = request.form.get(
            "target",
            ""
        ).strip()

        scope = request.form.get(
            "scope",
            ""
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
            return "Please complete all fields.", 400

        if not authorization:
            return (
                "Authorization confirmation is required.",
                400
            )

        target_ip = resolve_target_ip(
            target
        )

        client_ip = (
            request.remote_addr
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

            <h1>
                REQUEST A FREE SECURITY CHECK
            </h1>

            <p class="muted">
                No payment required.
            </p>

            <form method="POST">

                <label>
                    Name
                </label>

                <input
                    name="name"
                    required
                >

                <label>
                    Email
                </label>

                <input
                    name="email"
                    type="email"
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
                    placeholder="Example: public website only"
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
                    to request security testing for this
                    target within the scope above.

                </label>

                <br><br>

                <button type="submit">
                    SEND FREE REQUEST
                </button>

            </form>

        </div>
        """
    )


# =========================================================
# CHAT HTML
# =========================================================

def render_messages(messages):

    html = ""

    for message in messages:

        sender = e(
            message["sender"]
        )

        html += f"""
        <div class="message {sender}">

            <div class="message-header">

                <b>
                    {sender.upper()}
                </b>

                <span class="muted">
                    {e(message["created"])}
                </span>

            </div>

            <pre>
{e(message["message"])}
            </pre>

        </div>
        """

    return html


# =========================================================
# CLIENT STATUS + CHAT
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

    # Opening the page means client has seen admin messages.
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
                {e(finding['code'])}
                —
                {e(finding['title'])}
            </h2>

            <p>
                Severity:
                <span class="badge">
                    {e(finding['severity'])}
                </span>
            </p>

            <h3>Evidence</h3>

            <pre>
{e(finding['evidence'])}
            </pre>

            <h3>Impact</h3>

            <pre>
{e(finding['impact'])}
            </pre>

            <h3>Recommendation</h3>

            <pre>
{e(finding['recommendation'])}
            </pre>

        </div>
        """

    messages_html = render_messages(
        messages
    )

    scripts = f"""

    <script>

    let lastClientNotificationCount = 0;
    let notificationPermissionAsked = false;

    async function enableNotifications() {{

        if (
            "Notification" in window &&
            Notification.permission === "default" &&
            !notificationPermissionAsked
        ) {{

            notificationPermissionAsked = true;

            try {{
                await Notification.requestPermission();
            }} catch (e) {{}}
        }}
    }}

    function showClientNotification(count) {{

        const box = document.getElementById(
            "clientNotification"
        );

        const text = document.getElementById(
            "clientNotificationText"
        );

        if (count > 0) {{

            text.textContent =
                "🔔 You have " +
                count +
                " new message" +
                (count === 1 ? "" : "s") +
                " from Matia.";

            box.classList.add("show");

            if (
                count > lastClientNotificationCount &&
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
                }} catch (e) {{}}
            }}

        }} else {{

            box.classList.remove("show");

        }}

        lastClientNotificationCount = count;
    }}

    async function checkClientNotifications() {{

        try {{

            const response = await fetch(
                "/api/client/{request_id}/notifications",
                {{
                    cache: "no-store"
                }}
            );

            if (!response.ok) {{
                return;
            }}

            const data =
                await response.json();

            showClientNotification(
                data.unread
            );

        }} catch (e) {{}}
    }}

    async function sendClientMessage(event) {{

        event.preventDefault();

        const form =
            document.getElementById(
                "clientChatForm"
            );

        const button =
            document.getElementById(
                "clientSendButton"
            );

        const textarea =
            document.getElementById(
                "clientMessage"
            );

        const message =
            textarea.value.trim();

        if (!message) {{
            return;
        }}

        button.disabled = true;

        try {{

            const response = await fetch(
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

            if (response.ok) {{
                textarea.value = "";
                await refreshClientMessages();
            }}

        }} catch (e) {{

            alert("Message could not be sent.");

        }}

        button.disabled = false;
    }}

    async function refreshClientMessages() {{

        try {{

            const response = await fetch(
                "/api/client/{request_id}/messages",
                {{
                    cache: "no-store"
                }}
            );

            if (!response.ok) {{
                return;
            }}

            const data =
                await response.json();

            document.getElementById(
                "clientMessages"
            ).innerHTML = data.html;

            await fetch(
                "/api/client/{request_id}/read",
                {{
                    method: "POST"
                }}
            );

        }} catch (e) {{}}
    }}

    document.addEventListener(
        "DOMContentLoaded",
        async function() {{

            const form =
                document.getElementById(
                    "clientChatForm"
                );

            if (form) {{
                form.addEventListener(
                    "submit",
                    sendClientMessage
                );
            }}

            enableNotifications();

            checkClientNotifications();

            setInterval(
                checkClientNotifications,
                2000
            );

            setInterval(
                refreshClientMessages,
                3000
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
                New message
            </span>
        </div>

        <div class="card">

            <p class="muted">
                MATIA SECURITY CHECK
            </p>

            <h1>
                REQUEST #{item['id']}
            </h1>

            <p>
                Status:
                <span class="badge">
                    {e(item['status'])}
                </span>
            </p>

            <p>
                <b>Target:</b>
                {e(item['target'])}
            </p>

            <div class="ip-box">

                <b>
                    Resolved Target IP:
                </b>

                <br><br>

                {e(item['target_ip'])}

                <p class="muted">
                    DNS resolution only.
                    No automatic target scanning.
                </p>

            </div>

            <h3>
                Authorized Scope
            </h3>

            <pre>
{e(item['scope'])}
            </pre>

        </div>


        <div class="card">

            <h2>
                💬 CHAT WITH MATIA
            </h2>

            <div
                id="clientMessages"
                class="chat-box"
            >
                {messages_html}
            </div>

            <form
                id="clientChatForm"
            >

                <textarea
                    id="clientMessage"
                    placeholder="Write a message to Matia..."
                    required
                ></textarea>

                <button
                    id="clientSendButton"
                    type="submit"
                >
                    SEND MESSAGE
                </button>

            </form>

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

    item = get_request(request_id)

    if not item:
        return "Request not found.", 404

    message = request.form.get(
        "message",
        ""
    ).strip()

    if message:

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
# CLIENT NOTIFICATIONS
# =========================================================

@app.get(
    "/api/client/<int:request_id>/notifications"
)
def client_notifications(request_id):

    item = get_request(request_id)

    if not item:
        return jsonify({
            "error": "Request not found"
        }), 404

    conn = get_db()

    unread = conn.execute(
        """
        SELECT COUNT(*) AS count
        FROM messages
        WHERE request_id = ?
        AND sender = 'matia'
        AND read_by_client = 0
        """,
        (request_id,)
    ).fetchone()["count"]

    conn.close()

    return jsonify({
        "unread": unread
    })


# =========================================================
# CLIENT MESSAGES
# =========================================================

@app.get(
    "/api/client/<int:request_id>/messages"
)
def client_messages(request_id):

    item = get_request(request_id)

    if not item:
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
# CLIENT READ
# =========================================================

@app.post(
    "/api/client/<int:request_id>/read"
)
def client_read(request_id):

    conn = get_db()

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

    return jsonify({
        "success": True
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
            style="max-width:450px;margin:auto"
        >

            <h1>
                MATIA ADMIN LOGIN
            </h1>

            <form method="POST">

                <label>
                    Username
                </label>

                <input
                    name="username"
                    required
                >

                <label>
                    Password
                </label>

                <input
                    name="password"
                    type="password"
                    required
                >

                <button>
                    LOGIN
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
        SELECT COUNT(*) AS count
        FROM messages
        WHERE sender = 'client'
        AND read_by_admin = 0
        """
    ).fetchone()["count"]

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
                {e(item['name'])}
            </td>

            <td>
                {e(item['target'])}
            </td>

            <td>
                <span class="badge">
                    {e(item['status'])}
                </span>
            </td>

            <td>

                <a href="/admin/request/{item['id']}">
                    OPEN
                </a>

            </td>

        </tr>
        """

    scripts = """

    <script>

    let lastAdminNotificationCount = 0;

    async function enableAdminNotifications() {

        if (
            "Notification" in window &&
            Notification.permission === "default"
        ) {

            try {
                await Notification.requestPermission();
            } catch (e) {}

        }

    }

    async function checkAdminNotifications() {

        try {

            const response = await fetch(
                "/api/admin/notifications",
                {
                    cache: "no-store"
                }
            );

            if (!response.ok) {
                return;
            }

            const data =
                await response.json();

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
                    ) +
                    ".";

                box.classList.add("show");

                if (
                    data.unread >
                        lastAdminNotificationCount &&
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

                    } catch (e) {}

                }

            } else {

                box.classList.remove("show");

            }

            lastAdminNotificationCount =
                data.unread;

        } catch (e) {}

    }

    document.addEventListener(
        "DOMContentLoaded",
        function() {

            enableAdminNotifications();

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
        "MATIA Admin Panel",

        f"""

        <div
            id="adminNotification"
            class="notification"
        >

            <span id="adminNotificationText">
                New client message
            </span>

        </div>

        <div class="card">

            <h1>
                MATIA // ADMIN PANEL
            </h1>

            <p class="muted">
                FREE SECURITY ASSESSMENT REQUESTS
            </p>

        </div>

        <div class="card">

            <table>

                <tr>

                    <th>ID</th>
                    <th>Client</th>
                    <th>Target</th>
                    <th>Status</th>
                    <th>Open</th>

                </tr>

                {rows}

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

    messages_html = render_messages(
        messages
    )

    findings_html = ""

    for finding in findings:

        findings_html += f"""
        <div class="card">

            <h2>
                {e(finding['code'])}
                —
                {e(finding['title'])}
            </h2>

            <p>
                Severity:
                <span class="badge">
                    {e(finding['severity'])}
                </span>
            </p>

            <h3>Evidence</h3>

            <pre>
{e(finding['evidence'])}
            </pre>

            <h3>Impact</h3>

            <pre>
{e(finding['impact'])}
            </pre>

            <h3>Recommendation</h3>

            <pre>
{e(finding['recommendation'])}
            </pre>

        </div>
        """

    scripts = f"""

    <script>

    let lastRequestNotificationCount = 0;

    async function checkRequestNotifications() {{

        try {{

            const response = await fetch(
                "/api/admin/notifications",
                {{
                    cache: "no-store"
                }}
            );

            if (!response.ok) {{
                return;
            }}

            const data =
                await response.json();

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
                    ) +
                    ".";

                box.classList.add("show");

                if (
                    data.unread >
                        lastRequestNotificationCount &&
                    "Notification" in window &&
                    Notification.permission === "granted"
                ) {{

                    try {{

                        new Notification(
                            "MATIA // SECURITY CHECK",
                            {{
                                body:
                                    "A client sent you a new message."
                            }}
                        );

                    }} catch (e) {{}}

                }}

            }} else {{

                box.classList.remove("show");

            }}

            lastRequestNotificationCount =
                data.unread;

        }} catch (e) {{}}

    }}


    async function sendAdminMessage(event) {{

        event.preventDefault();

        const form =
            document.getElementById(
                "adminChatForm"
            );

        const button =
            document.getElementById(
                "adminSendButton"
            );

        const textarea =
            document.getElementById(
                "adminMessage"
            );

        const message =
            textarea.value.trim();

        if (!message) {{
            return;
        }}

        button.disabled = true;

        try {{

            const response = await fetch(
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

            if (response.ok) {{

                textarea.value = "";

                await refreshAdminMessages();

            }}

        }} catch (e) {{

            alert(
                "Message could not be sent."
            );

        }}

        button.disabled = false;
    }}


    async function refreshAdminMessages() {{

        try {{

            const response = await fetch(
                "/api/admin/request/{request_id}/messages",
                {{
                    cache: "no-store"
                }}
            );

            if (!response.ok) {{
                return;
            }}

            const data =
                await response.json();

            document.getElementById(
                "adminMessages"
            ).innerHTML = data.html;

            await fetch(
                "/api/admin/request/{request_id}/read",
                {{
                    method: "POST"
                }}
            );

        }} catch (e) {{}}

    }}


    document.addEventListener(
        "DOMContentLoaded",
        function() {{

            const form =
                document.getElementById(
                    "adminChatForm"
                );

            if (form) {{

                form.addEventListener(
                    "submit",
                    sendAdminMessage
                );

            }}

            if (
                "Notification" in window &&
                Notification.permission === "default"
            ) {{

                Notification.requestPermission()
                    .catch(function() {{}});

            }}

            checkRequestNotifications();

            setInterval(
                checkRequestNotifications,
                2000
            );

            setInterval(
                refreshAdminMessages,
                3000
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

        </div>

        <div class="card">

            <h1>
                REQUEST #{item['id']}
            </h1>

            <p>
                <b>Client:</b>
                {e(item['name'])}
            </p>

            <p>
                <b>Email:</b>
                {e(item['email'])}
            </p>

            <p>
                <b>Target:</b>
                {e(item['target'])}
            </p>

            <div class="ip-box">

                <b>
                    Resolved Target IP:
                </b>

                <br><br>

                {e(item['target_ip'])}

            </div>

            <p>
                <b>
                    Client Connection IP:
                </b>

                {e(item['client_ip'])}
            </p>

            <h3>
                Authorized Scope
            </h3>

            <pre>
{e(item['scope'])}
            </pre>

            <p>

                <b>Status:</b>

                <span class="badge">
                    {e(item['status'])}
                </span>

            </p>

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

            </form>

        </div>


        <div class="card">

            <h2>
                💬 CLIENT CHAT
            </h2>

            <div
                id="adminMessages"
                class="chat-box"
            >
                {messages_html}
            </div>

            <form
                id="adminChatForm"
            >

                <textarea
                    id="adminMessage"
                    placeholder="Message client..."
                    required
                ></textarea>

                <button
                    id="adminSendButton"
                    type="submit"
                >
                    SEND MESSAGE
                </button>

            </form>

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

                    <option>
                        Informational
                    </option>

                    <option>
                        Low
                    </option>

                    <option>
                        Low-Medium
                    </option>

                    <option>
                        Medium
                    </option>

                    <option>
                        High
                    </option>

                    <option>
                        Critical
                    </option>

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

                <button>
                    ADD FINDING
                </button>

            </form>

        </div>


        {findings_html}


        <div class="card">

            <a
                href="/admin/request/{request_id}/report"
            >

                <button>
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
        return "Request not found.", 404

    message = request.form.get(
        "message",
        ""
    ).strip()

    if message:

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
# ADMIN MESSAGES
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
# ADMIN READ
# =========================================================

@app.post(
    "/api/admin/request/<int:request_id>/read"
)
@admin_required
def admin_read(request_id):

    conn = get_db()

    conn.execute(
        """
        UPDATE messages
        SET read_by_admin = 1
        WHERE request_id = ?
        AND sender = 'client'
        """,
        (request_id,)
    )

    conn.commit()
    conn.close()

    return jsonify({
        "success": True
    })


# =========================================================
# ADD FINDING
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
            "code",
            ""
        ).strip(),

        "title": request.form.get(
            "title",
            ""
        ).strip(),

        "severity": request.form.get(
            "severity",
            ""
        ).strip(),

        "evidence": request.form.get(
            "evidence",
            ""
        ).strip(),

        "impact": request.form.get(
            "impact",
            ""
        ).strip(),

        "recommendation": request.form.get(
            "recommendation",
            ""
        ).strip()
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
            fields["recommendation"]
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
                {e(finding['code'])}
                —
                {e(finding['title'])}
            </h2>

            <p>

                Severity:

                <span class="badge">
                    {e(finding['severity'])}
                </span>

            </p>

            <h3>
                Evidence
            </h3>

            <pre>
{e(finding['evidence'])}
            </pre>

            <h3>
                Impact
            </h3>

            <pre>
{e(finding['impact'])}
            </pre>

            <h3>
                Recommendation
            </h3>

            <pre>
{e(finding['recommendation'])}
            </pre>

        </div>
        """

    return page(
        f"Security Report #{request_id}",

        f"""

        <div class="card">

            <p class="muted">
                MATIA // SECURITY ASSESSMENT
            </p>

            <h1>
                FREE WEB SECURITY ASSESSMENT REPORT
            </h1>

            <p>
                <b>Request:</b>
                #{item['id']}
            </p>

            <p>
                <b>Client:</b>
                {e(item['name'])}
            </p>

            <p>
                <b>Target:</b>
                {e(item['target'])}
            </p>

            <p>
                <b>Resolved IP:</b>
                {e(item['target_ip'])}
            </p>

            <p>
                <b>Date:</b>
                {e(
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

            <p>
                This assessment was performed only within
                the client-authorized scope recorded for
                this request.
            </p>

            <p>
                This is a free basic security assessment.
                It does not guarantee complete security.
            </p>

        </div>


        {findings_html}


        <div class="card">

            <h2>
                FINAL STATEMENT
            </h2>

            <p>
                Testing was limited to the authorized
                target and scope.
            </p>

            <p>
                <strong>
                    MATIA // SECURITY CHECK
                </strong>
            </p>

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
# LOCAL START
# =========================================================

if __name__ == "__main__":

    port = int(
        os.environ.get(
            "PORT",
            "5000"
        )
    )

    print("=" * 60)
    print("MATIA // SECURITY CHECK")
    print("=" * 60)
    print("Host: 0.0.0.0")
    print("Port:", port)
    print("Chat notifications: ENABLED")
    print("=" * 60)

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )
