
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

from authlib.integrations.flask_client import OAuth


# =========================================================
# MATIA // SECURITY CHECK
# GOOGLE ADMIN AUTH
# =========================================================

app = Flask(__name__)


# =========================================================
# CONFIG
# =========================================================

SECRET_KEY = os.environ.get("MATIA_SECRET_KEY")

if not SECRET_KEY:
    SECRET_KEY = secrets.token_hex(32)

DB_FILE = os.environ.get(
    "MATIA_DB_FILE",
    "matia_security.db",
)

GOOGLE_CLIENT_ID = os.environ.get(
    "GOOGLE_CLIENT_ID",
    "",
)

GOOGLE_CLIENT_SECRET = os.environ.get(
    "GOOGLE_CLIENT_SECRET",
    "",
)

# =========================================================
# TWO ALLOWED GOOGLE ADMIN ACCOUNTS
# =========================================================

ALLOWED_ADMIN_EMAILS = {
    "kleimatia1@gmail.com",
    "vantyx199@gmail.com",
}


app.config["SECRET_KEY"] = SECRET_KEY
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = (
    os.environ.get(
        "SESSION_COOKIE_SECURE",
        "1",
    ) == "1"
)


# =========================================================
# GOOGLE OAUTH
# =========================================================

oauth = OAuth(app)

google = oauth.register(
    name="google",
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url=(
        "https://accounts.google.com/"
        ".well-known/openid-configuration"
    ),
    client_kwargs={
        "scope": "openid email profile",
    },
)


# =========================================================
# DATABASE
# =========================================================

def db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db()

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
            evidence TEXT,
            impact TEXT,
            recommendation TEXT
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
            ADD COLUMN read_by_client
            INTEGER NOT NULL DEFAULT 0
        """)

    if "read_by_admin" not in columns:
        conn.execute("""
            ALTER TABLE messages
            ADD COLUMN read_by_admin
            INTEGER NOT NULL DEFAULT 0
        """)

    conn.commit()
    conn.close()


init_db()


# =========================================================
# HELPERS
# =========================================================

def now():
    return datetime.utcnow().strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )


def esc(value):
    return escape(str(value or ""))


def nl2br(value):
    return esc(value).replace(
        "\n",
        "<br>",
    )


def get_request(request_id):
    conn = db()

    row = conn.execute(
        """
        SELECT *
        FROM requests
        WHERE id = ?
        """,
        (request_id,),
    ).fetchone()

    conn.close()

    return row


def current_admin_email():
    return (
        session.get(
            "admin_email",
            "",
        )
        .strip()
        .lower()
    )


def is_admin():
    email = current_admin_email()

    return (
        session.get("admin_logged_in") is True
        and email in ALLOWED_ADMIN_EMAILS
    )


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):

        if not is_admin():
            session.clear()

            return redirect(
                url_for(
                    "google_login"
                )
            )

        return fn(
            *args,
            **kwargs
        )

    return wrapper


def resolve_hostname(target):
    try:
        parsed = urlparse(
            target
            if "://" in target
            else "//" + target
        )

        hostname = parsed.hostname

        if not hostname:
            return None

        return socket.gethostbyname(
            hostname
        )

    except Exception:
        return None


def resolve_target_ip(target):
    return resolve_hostname(target)


def status_info(status):
    values = {
        "PENDING": (
            "PENDING",
            "Request received and waiting for review.",
            "pending",
        ),
        "ACCEPTED": (
            "ACCEPTED",
            "Assessment request accepted.",
            "accepted",
        ),
        "DECLINED": (
            "DECLINED",
            "Assessment request was declined.",
            "declined",
        ),
        "COMPLETED": (
            "COMPLETED",
            "Assessment completed.",
            "completed",
        ),
    }

    return values.get(
        status,
        (
            "UNKNOWN",
            "Unknown status.",
            "unknown",
        ),
    )


# =========================================================
# NOTIFICATIONS
# =========================================================

NOTIFICATION_SCRIPT = r"""
<script>
(function () {

    let matiaAudio = null;

    let matiaSoundEnabled =
        localStorage.getItem("matia_sound") !== "off";

    let matiaNotificationsEnabled =
        localStorage.getItem("matia_notifications") === "on";


    function initMatiaAudio() {

        try {

            if (!matiaAudio) {

                const AudioContext =
                    window.AudioContext ||
                    window.webkitAudioContext;

                if (AudioContext) {
                    matiaAudio = new AudioContext();
                }
            }

            if (
                matiaAudio &&
                matiaAudio.state === "suspended"
            ) {
                matiaAudio.resume();
            }

        } catch (e) {

            console.log(
                "Audio initialization failed:",
                e
            );
        }
    }


    window.matiaRing = function () {

        if (!matiaSoundEnabled) return;

        try {

            initMatiaAudio();

            if (!matiaAudio) return;

            const ctx = matiaAudio;
            const start = ctx.currentTime;


            function tone(
                freq,
                offset,
                duration
            ) {

                const osc =
                    ctx.createOscillator();

                const gain =
                    ctx.createGain();

                osc.type = "sine";

                osc.frequency.setValueAtTime(
                    freq,
                    start + offset
                );

                gain.gain.setValueAtTime(
                    0.0001,
                    start + offset
                );

                gain.gain.exponentialRampToValueAtTime(
                    0.18,
                    start + offset + 0.02
                );

                gain.gain.exponentialRampToValueAtTime(
                    0.0001,
                    start + offset + duration
                );

                osc.connect(gain);
                gain.connect(ctx.destination);

                osc.start(
                    start + offset
                );

                osc.stop(
                    start +
                    offset +
                    duration +
                    0.03
                );
            }


            tone(880, 0, 0.18);
            tone(660, 0.23, 0.22);

        } catch (e) {

            console.log(
                "Ring failed:",
                e
            );
        }
    };


    window.enableMatiaNotifications =
        async function () {

        try {

            initMatiaAudio();

            if (!("Notification" in window)) {

                alert(
                    "Browser notifications are not supported."
                );

                return;
            }

            const permission =
                await Notification.requestPermission();

            if (permission === "granted") {

                matiaNotificationsEnabled = true;

                localStorage.setItem(
                    "matia_notifications",
                    "on"
                );

                matiaDesktopNotification(
                    "MATIA // SECURITY CHECK",
                    "Notifications enabled."
                );
            }

            updateNotificationButtons();

        } catch (e) {

            console.log(e);
        }
    };


    window.matiaDesktopNotification =
        function (
            title,
            body
        ) {

        if (!matiaNotificationsEnabled)
            return;

        if (!("Notification" in window))
            return;

        if (
            Notification.permission !==
            "granted"
        )
            return;

        try {

            new Notification(
                title,
                {
                    body: body,
                    icon: "/favicon.ico"
                }
            );

        } catch (e) {

            console.log(
                "Notification failed:",
                e
            );
        }
    };


    window.toggleMatiaSound =
        function () {

        matiaSoundEnabled =
            !matiaSoundEnabled;

        localStorage.setItem(
            "matia_sound",
            matiaSoundEnabled
                ? "on"
                : "off"
        );

        if (matiaSoundEnabled) {
            initMatiaAudio();
            matiaRing();
        }

        updateSoundButton();
    };


    function updateSoundButton() {

        const buttons =
            document.querySelectorAll(
                "[data-matia-sound]"
            );

        buttons.forEach(
            function (button) {

            button.textContent =
                matiaSoundEnabled
                    ? "🔊 RING ON"
                    : "🔇 RING OFF";

        });
    }


    function updateNotificationButtons() {

        const buttons =
            document.querySelectorAll(
                "[data-matia-notifications]"
            );

        buttons.forEach(
            function (button) {

            if (
                matiaNotificationsEnabled &&
                "Notification" in window &&
                Notification.permission ===
                "granted"
            ) {

                button.textContent =
                    "🔔 NOTIFICATIONS ON";

            } else {

                button.textContent =
                    "🔔 ENABLE NOTIFICATIONS";
            }

        });
    }


    document.addEventListener(
        "click",
        function () {
            initMatiaAudio();
        },
        {
            once: true
        }
    );


    document.addEventListener(
        "DOMContentLoaded",
        function () {

            updateSoundButton();
            updateNotificationButtons();

        }
    );

})();
</script>
"""


# =========================================================
# STYLE
# =========================================================

STYLE = r"""
<style>

:root {
    --bg: #05070b;
    --panel: #0b1018;
    --panel2: #0f1622;
    --border: #1c2a3b;
    --text: #edf5ff;
    --muted: #7f91a8;
    --blue: #38a8ff;
    --cyan: #42e8ff;
    --green: #32e875;
    --yellow: #ffd166;
    --red: #ff5577;
}

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    background:
        radial-gradient(
            circle at top right,
            rgba(56,168,255,.10),
            transparent 32%
        ),
        radial-gradient(
            circle at bottom left,
            rgba(66,232,255,.05),
            transparent 30%
        ),
        var(--bg);
    color: var(--text);
    font-family:
        Inter,
        ui-sans-serif,
        system-ui,
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        sans-serif;
}

a {
    color: inherit;
    text-decoration: none;
}

.nav {
    position: sticky;
    top: 0;
    z-index: 20;

    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 14px;

    padding: 15px 22px;

    background: rgba(5,7,11,.88);

    backdrop-filter: blur(16px);

    border-bottom: 1px solid var(--border);
}

.logo {
    font-weight: 900;
    letter-spacing: .08em;
}

.logo span {
    color: var(--cyan);
}

.nav-right {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
}

.online {
    color: var(--green);
    font-size: 12px;
    font-weight: 800;
}

.btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 7px;

    border: 1px solid var(--border);
    border-radius: 10px;

    background: var(--panel2);
    color: var(--text);

    padding: 10px 14px;

    cursor: pointer;

    font-weight: 750;

    transition:
        transform .15s ease,
        border-color .15s ease,
        background .15s ease;
}

.btn:hover {
    transform: translateY(-1px);
    border-color: var(--blue);
    background: #111c2b;
}

.btn.primary {
    background:
        linear-gradient(
            135deg,
            #1678c9,
            #16a8c9
        );

    border-color: #29b9ff;
}

.btn.danger {
    border-color:
        rgba(255,85,119,.4);

    color: #ff8da4;
}

.container {
    width: min(
        1120px,
        calc(100% - 30px)
    );

    margin: 0 auto;

    padding: 35px 0 70px;
}

.hero {
    padding: 45px 0;
}

.hero h1 {
    font-size:
        clamp(
            38px,
            7vw,
            78px
        );

    line-height: .95;

    margin:
        0 0 20px;

    letter-spacing: -.06em;
}

.hero h1 span {
    color: var(--cyan);
}

.hero p {
    color: var(--muted);
    max-width: 700px;
    font-size: 17px;
    line-height: 1.7;
}

.grid {
    display: grid;

    grid-template-columns:
        repeat(
            auto-fit,
            minmax(260px, 1fr)
        );

    gap: 16px;
}

.card {
    background:
        linear-gradient(
            180deg,
            rgba(255,255,255,.025),
            transparent
        ),
        var(--panel);

    border:
        1px solid var(--border);

    border-radius: 17px;

    padding: 22px;

    box-shadow:
        0 15px 45px rgba(0,0,0,.22);
}

.card h2,
.card h3 {
    margin-top: 0;
}

.muted {
    color: var(--muted);
}

label {
    display: block;

    margin:
        14px 0 7px;

    color: #a9b9cb;

    font-size: 13px;

    font-weight: 700;
}

input,
textarea,
select {
    width: 100%;

    background: #070b11;

    color: var(--text);

    border:
        1px solid var(--border);

    border-radius: 10px;

    padding: 12px 13px;

    outline: none;
}

input:focus,
textarea:focus,
select:focus {

    border-color:
        var(--blue);

    box-shadow:
        0 0 0 3px
        rgba(56,168,255,.08);
}

textarea {
    min-height: 120px;
    resize: vertical;
}

.actions {
    display: flex;
    gap: 9px;
    flex-wrap: wrap;
    margin-top: 16px;
}

.badge {
    display: inline-flex;
    padding: 6px 10px;
    border-radius: 999px;
    font-size: 11px;
    font-weight: 900;
    letter-spacing: .04em;
}

.badge.pending {
    background:
        rgba(255,209,102,.10);
    color: var(--yellow);
}

.badge.accepted {
    background:
        rgba(50,232,117,.10);
    color: var(--green);
}

.badge.declined {
    background:
        rgba(255,85,119,.10);
    color: var(--red);
}

.badge.completed {
    background:
        rgba(66,232,255,.10);
    color: var(--cyan);
}

.message-list {
    display: flex;
    flex-direction: column;
    gap: 10px;
    max-height: 450px;
    overflow-y: auto;
}

.message {
    border:
        1px solid var(--border);

    background: #080d14;

    border-radius: 12px;

    padding: 12px;
}

.message.admin {
    border-color:
        rgba(66,232,255,.22);
}

.message.client {
    border-color:
        rgba(56,168,255,.22);
}

.message-meta {
    display: flex;

    justify-content: space-between;

    gap: 10px;

    color: var(--muted);

    font-size: 11px;

    margin-bottom: 7px;
}

.finding {
    border:
        1px solid var(--border);

    border-radius: 14px;

    padding: 17px;

    margin-bottom: 12px;

    background: #080d14;
}

.severity {
    font-weight: 900;
    font-size: 12px;
}

.severity.CRITICAL,
.severity.HIGH {
    color: var(--red);
}

.severity.MEDIUM {
    color: var(--yellow);
}

.severity.LOW,
.severity.INFO {
    color: var(--cyan);
}

.table-wrap {
    overflow-x: auto;
}

table {
    width: 100%;
    border-collapse: collapse;
}

th,
td {
    padding: 13px;
    border-bottom:
        1px solid var(--border);
    text-align: left;
    white-space: nowrap;
}

th {
    color: var(--muted);
    font-size: 12px;
}

.alert {
    border:
        1px solid var(--border);

    background: var(--panel2);

    padding:
        13px 15px;

    border-radius: 10px;

    margin-bottom: 15px;
}

.alert.error {
    border-color:
        rgba(255,85,119,.35);

    color: #ff9bb0;
}

.stat {
    font-size: 34px;
    font-weight: 900;
}

.footer {
    text-align: center;
    color: #516276;
    font-size: 12px;
    padding: 30px 0;
}

@media (max-width: 700px) {

    .nav {
        align-items: flex-start;
        flex-direction: column;
    }

    .hero {
        padding-top: 25px;
    }
}

</style>
"""


# =========================================================
# PAGE
# =========================================================

def page(
    title,
    body,
    scripts="",
):

    admin_nav = ""

    if is_admin():

        admin_nav = """
<a
    class="btn"
    href="/admin"
>
    ADMIN CONSOLE
</a>

<a
    class="btn danger"
    href="/admin/logout"
>
    LOGOUT
</a>
"""

    template = """
<!doctype html>

<html lang="en">

<head>

<meta charset="utf-8">

<meta
    name="viewport"
    content="width=device-width,
    initial-scale=1"
>

<title>
{{ title }}
|
MATIA // SECURITY CHECK
</title>

{{ style|safe }}

</head>

<body>

<nav class="nav">

<a
    href="/"
    class="logo"
>
    MATIA <span>//</span> SECURITY CHECK
</a>

<div class="nav-right">

{{ admin_nav|safe }}

<button
    class="btn"
    data-matia-sound
    onclick="toggleMatiaSound()"
>
    🔊 RING ON
</button>

<button
    class="btn"
    data-matia-notifications
    onclick="enableMatiaNotifications()"
>
    🔔 ENABLE NOTIFICATIONS
</button>

<span class="online">
    ● SYSTEM ONLINE
</span>

</div>

</nav>

<main class="container">

{{ body|safe }}

</main>

<footer class="footer">

MATIA // SECURITY CHECK
· Authorized Security Assessment Platform

</footer>

{{ scripts|safe }}

{{ notification_script|safe }}

</body>

</html>
"""

    return render_template_string(
        template,
        title=title,
        style=STYLE,
        admin_nav=admin_nav,
        body=body,
        scripts=scripts,
        notification_script=NOTIFICATION_SCRIPT,
    )


# =========================================================
# HOME
# =========================================================

@app.route("/")
def home():

    admin_button = ""

    if is_admin():

        admin_button = """
<a
    class="btn"
    href="/admin"
>
    ADMIN CONSOLE
</a>
"""

    body = """
<section class="hero">

<div class="badge completed">
    AUTHORIZED SECURITY PLATFORM
</div>

<h1>
    MATIA <span>//</span><br>
    SECURITY CHECK
</h1>

<p>
    Professional security assessment request platform
    for authorized environments. Submit a target,
    define scope, communicate securely and track
    assessment status.
</p>

<div class="actions">

<a
    class="btn primary"
    href="/request"
>
    + NEW SECURITY REQUEST
</a>

""" + admin_button + """

</div>

</section>


<div class="grid">

<div class="card">

<h3>01 · REQUEST</h3>

<p class="muted">
Submit an authorized security assessment request
with a defined scope.
</p>

</div>


<div class="card">

<h3>02 · REVIEW</h3>

<p class="muted">
The administrator reviews and accepts or declines
the request.
</p>

</div>


<div class="card">

<h3>03 · ASSESS</h3>

<p class="muted">
Findings and evidence can be documented inside
the assessment workspace.
</p>

</div>


<div class="card">

<h3>04 · REPORT</h3>

<p class="muted">
Completed findings can be exported as a
professional security report.
</p>

</div>

</div>
"""

    return page(
        "Home",
        body,
    )


# =========================================================
# CREATE REQUEST
# =========================================================

@app.route(
    "/request",
    methods=["GET", "POST"],
)
def create_request():

    error = ""

    if request.method == "POST":

        name = request.form.get(
            "name",
            "",
        ).strip()

        email = request.form.get(
            "email",
            "",
        ).strip()

        target = request.form.get(
            "target",
            "",
        ).strip()

        scope = request.form.get(
            "scope",
            "",
        ).strip()

        authorized = request.form.get(
            "authorized"
        )

        if (
            not name
            or not email
            or not target
            or not scope
        ):

            error = (
                "All fields are required."
            )

        elif authorized != "yes":

            error = (
                "You must confirm authorization."
            )

        else:

            target_ip = resolve_target_ip(
                target
            )

            conn = db()

            cur = conn.execute(
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
                    request.remote_addr,
                    now(),
                ),
            )

            request_id = cur.lastrowid

            conn.commit()
            conn.close()

            return redirect(
                url_for(
                    "client_status",
                    request_id=request_id,
                )
            )


    error_html = ""

    if error:

        error_html = """
<div class="alert error">
%s
</div>
""" % esc(error)


    body = """
<h1>New Security Request</h1>

<p class="muted">
Submit only systems you own or have explicit permission
to assess.
</p>

%s

<div class="card">

<form method="post">

<label>Name</label>

<input
    name="name"
    required
    autocomplete="name"
>

<label>Email</label>

<input
    name="email"
    type="email"
    required
    autocomplete="email"
>

<label>Target</label>

<input
    name="target"
    placeholder="example.com"
    required
>

<label>Authorized Scope</label>

<textarea
    name="scope"
    placeholder="Example: web application, port 443, authenticated test account..."
    required
></textarea>

<label>

<input
    type="checkbox"
    name="authorized"
    value="yes"
    required
    style="width:auto"
>

I confirm that I am authorized to request this assessment.

</label>

<div class="actions">

<button
    class="btn primary"
    type="submit"
>
    SUBMIT REQUEST
</button>

<a
    class="btn"
    href="/"
>
    CANCEL
</a>

</div>

</form>

</div>
""" % error_html

    return page(
        "New Request",
        body,
    )


# =========================================================
# CLIENT STATUS
# =========================================================

@app.route(
    "/status/<int:request_id>"
)
def client_status(request_id):

    req = get_request(request_id)

    if not req:
        return (
            "Request not found",
            404,
        )

    status, description, css = status_info(
        req["status"]
    )

    conn = db()

    messages = conn.execute(
        """
        SELECT *
        FROM messages
        WHERE request_id = ?
        ORDER BY id ASC
        """,
        (request_id,),
    ).fetchall()

    findings = conn.execute(
        """
        SELECT *
        FROM findings
        WHERE request_id = ?
        ORDER BY id ASC
        """,
        (request_id,),
    ).fetchall()

    conn.close()

    message_html = ""

    for msg in messages:

        cls = (
            "admin"
            if msg["sender"] == "matia"
            else "client"
        )

        message_html += """
<div class="message %s">

<div class="message-meta">

<span>
%s
</span>

<span>
%s
</span>

</div>

<div>
%s
</div>

</div>
""" % (
            cls,
            esc(msg["sender"].upper()),
            esc(msg["created"]),
            nl2br(msg["message"]),
        )

    if not message_html:

        message_html = """
<div class="muted">
No messages yet.
</div>
"""

    findings_html = ""

    for finding in findings:

        severity = esc(
            finding["severity"].upper()
        )

        findings_html += """
<div class="finding">

<div class="message-meta">

<strong>
%s
</strong>

<span class="severity %s">
%s
</span>

</div>

<h3>
%s
</h3>

<p>
<strong>Evidence</strong><br>
%s
</p>

<p>
<strong>Impact</strong><br>
%s
</p>

<p>
<strong>Recommendation</strong><br>
%s
</p>

</div>
""" % (
            esc(finding["code"]),
            severity,
            severity,
            esc(finding["title"]),
            nl2br(finding["evidence"]),
            nl2br(finding["impact"]),
            nl2br(finding["recommendation"]),
        )

    if not findings_html:

        findings_html = """
<div class="muted">
No findings published yet.
</div>
"""

    scripts = """
<script>

let lastMessageId = 0;
let firstClientPoll = true;
let lastStatus = %r;

async function checkClientNotifications() {

    try {

        const response =
            await fetch(
                "/api/client/%s/notifications",
                {
                    cache: "no-store"
                }
            );

        const data =
            await response.json();

        if (firstClientPoll) {

            lastMessageId =
                data.latest_id || 0;

            lastStatus =
                data.status ||
                lastStatus;

            firstClientPoll = false;

            return;
        }

        if (
            data.latest_id &&
            data.latest_id >
            lastMessageId &&
            data.latest_sender ===
            "matia"
        ) {

            lastMessageId =
                data.latest_id;

            matiaRing();

            matiaDesktopNotification(
                "🔔 MATIA // SECURITY CHECK",
                data.latest_message ||
                "You received a new message."
            );

            location.reload();
        }

        if (
            data.status &&
            data.status !== lastStatus
        ) {

            lastStatus =
                data.status;

            matiaRing();

            matiaDesktopNotification(
                "⚡ Assessment Status Updated",
                "Status changed to " +
                data.status
            );

            location.reload();
        }

    } catch (e) {

        console.log(e);

    }
}

setInterval(
    checkClientNotifications,
    2500
);

checkClientNotifications();

</script>
""" % (
        req["status"],
        request_id,
    )

    body = """
<div
    class="actions"
    style="justify-content:space-between"
>

<div>

<div class="muted">
SECURITY REQUEST #%s
</div>

<h1 style="margin:5px 0">
Client Workspace
</h1>

</div>

<span class="badge %s">
%s
</span>

</div>


<div class="grid">

<div class="card">

<div class="muted">
TARGET
</div>

<h3>
%s
</h3>

<div class="muted">
Resolved IP
</div>

<div>
%s
</div>

</div>


<div class="card">

<div class="muted">
STATUS
</div>

<div class="stat">
%s
</div>

<p class="muted">
%s
</p>

</div>


<div class="card">

<div class="muted">
CREATED
</div>

<h3>
%s
</h3>

<div class="muted">
Request ID
</div>

<strong>
#%s
</strong>

</div>

</div>


<br>


<div class="card">

<h2>
Authorized Scope
</h2>

<p class="muted">
%s
</p>

</div>


<br>


<div class="grid">

<div class="card">

<h2>
Secure Chat
</h2>

<div class="message-list">

%s

</div>

<form
    method="post"
    action="/status/%s/message"
>

<textarea
    name="message"
    placeholder="Write a message to MATIA..."
    required
></textarea>

<div class="actions">

<button
    class="btn primary"
    type="submit"
>
SEND MESSAGE
</button>

</div>

</form>

</div>


<div class="card">

<h2>
Security Findings
</h2>

%s

</div>

</div>
""" % (
        req["id"],
        css,
        esc(status),
        esc(req["target"]),
        esc(
            req["target_ip"]
            or "Not resolved"
        ),
        esc(status),
        esc(description),
        esc(req["created"]),
        req["id"],
        nl2br(req["scope"]),
        message_html,
        request_id,
        findings_html,
    )

    return page(
        "Request #%s" % request_id,
        body,
        scripts,
    )


# =========================================================
# CLIENT MESSAGE
# =========================================================

@app.route(
    "/status/<int:request_id>/message",
    methods=["POST"],
)
def client_message(request_id):

    req = get_request(
        request_id
    )

    if not req:
        return (
            "Request not found",
            404,
        )

    message = request.form.get(
        "message",
        "",
    ).strip()

    if message:

        conn = db()

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
                0,
            ),
        )

        conn.commit()
        conn.close()

    return redirect(
        url_for(
            "client_status",
            request_id=request_id,
        )
    )


# =========================================================
# CLIENT APIS
# =========================================================

@app.route(
    "/api/client/<int:request_id>/status"
)
def client_status_api(request_id):

    req = get_request(request_id)

    if not req:

        return jsonify({
            "ok": False,
            "error": "not_found",
        }), 404

    return jsonify({
        "ok": True,
        "id": req["id"],
        "status": req["status"],
        "target": req["target"],
        "target_ip": req["target_ip"],
    })


@app.route(
    "/api/client/<int:request_id>/messages"
)
def client_messages_api(request_id):

    conn = db()

    rows = conn.execute(
        """
        SELECT
            id,
            sender,
            message,
            created
        FROM messages
        WHERE request_id = ?
        ORDER BY id ASC
        """,
        (request_id,),
    ).fetchall()

    conn.execute(
        """
        UPDATE messages
        SET read_by_client = 1
        WHERE request_id = ?
        AND sender = 'matia'
        """,
        (request_id,),
    )

    conn.commit()
    conn.close()

    return jsonify({
        "messages": [
            dict(row)
            for row in rows
        ]
    })


@app.route(
    "/api/client/<int:request_id>/notifications"
)
def client_notifications(request_id):

    conn = db()

    req = conn.execute(
        """
        SELECT *
        FROM requests
        WHERE id = ?
        """,
        (request_id,),
    ).fetchone()

    latest = conn.execute(
        """
        SELECT *
        FROM messages
        WHERE request_id = ?
        ORDER BY id DESC
        LIMIT 1
        """,
        (request_id,),
    ).fetchone()

    conn.close()

    if not req:

        return jsonify({
            "ok": False
        }), 404

    return jsonify({
        "ok": True,
        "status": req["status"],
        "latest_id":
            latest["id"]
            if latest
            else 0,
        "latest_sender":
            latest["sender"]
            if latest
            else None,
        "latest_message":
            latest["message"]
            if latest
            else "",
    })


# =========================================================
# GOOGLE LOGIN
# =========================================================

@app.route("/auth/google")
def google_login():

    if (
        not GOOGLE_CLIENT_ID
        or not GOOGLE_CLIENT_SECRET
    ):

        body = """
<div
    style="
        max-width:650px;
        margin:60px auto
    "
>

<div class="card">

<div class="badge declined">
CONFIGURATION ERROR
</div>

<h1>
Google Authentication Not Configured
</h1>

<p class="muted">
Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET
in the server environment.
</p>

<a
    class="btn"
    href="/"
>
RETURN HOME
</a>

</div>

</div>
"""

        return page(
            "OAuth Configuration",
            body,
        ), 500

    redirect_uri = url_for(
        "google_callback",
        _external=True,
    )

    return google.authorize_redirect(
        redirect_uri
    )


# =========================================================
# GOOGLE CALLBACK
# =========================================================

@app.route(
    "/auth/google/callback"
)
def google_callback():

    try:

        token = google.authorize_access_token()

        user = google.userinfo(
            token=token
        )

        email = (
            user.get("email")
            or ""
        ).strip().lower()

        email_verified = user.get(
            "email_verified",
            True,
        )

        if isinstance(
            email_verified,
            str,
        ):
            email_verified = (
                email_verified.lower()
                == "true"
            )

        print(
            "GOOGLE LOGIN EMAIL:",
            email,
        )

        print(
            "EMAIL VERIFIED:",
            email_verified,
        )

        print(
            "EMAIL ALLOWED:",
            email in ALLOWED_ADMIN_EMAILS,
        )

        if (
            email not in ALLOWED_ADMIN_EMAILS
            or not email_verified
        ):

            session.clear()

            return page(
                "Access Denied",
                """
<div class="card">

<div class="badge declined">
ACCESS DENIED
</div>

<h1>
Administrator Access Denied
</h1>

<p class="muted">
This Google account is not authorized
to access the MATIA administrator console.
</p>

<a
    class="btn"
    href="/"
>
RETURN HOME
</a>

</div>
""",
            ), 403

        session.clear()

        session["admin_logged_in"] = True
        session["admin_email"] = email
        session["admin_name"] = (
            user.get("name")
            or user.get("given_name")
            or email
        )

        session.permanent = True

        print(
            "ADMIN LOGIN SUCCESS:",
            email,
        )

        return redirect(
            url_for(
                "admin_dashboard"
            )
        )

    except Exception as e:

        print(
            "GOOGLE AUTH ERROR:",
            repr(e),
        )

        session.clear()

        return page(
            "Authentication Error",
            """
<div class="card">

<div class="badge declined">
AUTHENTICATION ERROR
</div>

<h1>
Google Authentication Failed
</h1>

<p class="muted">
The Google authentication process could not
be completed.
</p>

<a
    class="btn"
    href="/"
>
RETURN HOME
</a>

</div>
""",
        ), 500


# =========================================================
# ADMIN NOTIFICATIONS
# =========================================================

@app.route(
    "/api/admin/notifications"
)
@admin_required
def admin_notifications():

    conn = db()

    latest = conn.execute(
        """
        SELECT
            m.*,
            r.name,
            r.target
        FROM messages m
        JOIN requests r
            ON r.id = m.request_id
        WHERE m.sender = 'client'
        ORDER BY m.id DESC
        LIMIT 1
        """
    ).fetchone()

    unread = conn.execute(
        """
        SELECT COUNT(*)
        FROM messages
        WHERE sender = 'client'
        AND read_by_admin = 0
        """
    ).fetchone()[0]

    conn.close()

    return jsonify({
        "ok": True,
        "unread": unread,
        "latest_id":
            latest["id"]
            if latest
            else 0,
        "latest_sender":
            latest["sender"]
            if latest
            else None,
        "latest_message":
            latest["message"]
            if latest
            else "",
        "client_name":
            latest["name"]
            if latest
            else "",
        "target":
            latest["target"]
            if latest
            else "",
    })


# =========================================================
# ADMIN DASHBOARD
# =========================================================

@app.route("/admin")
@admin_required
def admin_dashboard():

    conn = db()

    requests_rows = conn.execute(
        """
        SELECT *
        FROM requests
        ORDER BY id DESC
        """
    ).fetchall()

    stats = {}

    for status in (
        "PENDING",
        "ACCEPTED",
        "DECLINED",
        "COMPLETED",
    ):

        stats[status] = conn.execute(
            """
            SELECT COUNT(*)
            FROM requests
            WHERE status = ?
            """,
            (status,),
        ).fetchone()[0]

    conn.close()

    rows_html = ""

    for req in requests_rows:

        _, _, css = status_info(
            req["status"]
        )

        rows_html += """
<tr>

<td>
#%s
</td>

<td>

<strong>
%s
</strong>

<br>

<span class="muted">
%s
</span>

</td>

<td>

%s

<br>

<span class="muted">
%s
</span>

</td>

<td>

<span class="badge %s">
%s
</span>

</td>

<td>
%s
</td>

<td>

<a
    class="btn"
    href="/admin/request/%s"
>
    OPEN
</a>

</td>

</tr>
""" % (
            req["id"],
            esc(req["name"]),
            esc(req["email"]),
            esc(req["target"]),
            esc(
                req["target_ip"]
                or "unresolved"
            ),
            css,
            esc(req["status"]),
            esc(req["created"]),
            req["id"],
        )

    if not rows_html:

        rows_html = """
<tr>

<td
    colspan="6"
    class="muted"
>
No requests yet.
</td>

</tr>
"""

    scripts = r"""
<script>

let adminLastMessageId = 0;
let adminFirstPoll = true;

async function adminNotificationPoll() {

    try {

        const response =
            await fetch(
                "/api/admin/notifications",
                {
                    cache: "no-store"
                }
            );

        const data =
            await response.json();

        if (adminFirstPoll) {

            adminLastMessageId =
                data.latest_id || 0;

            adminFirstPoll = false;

            return;
        }

        if (
            data.latest_id &&
            data.latest_id >
            adminLastMessageId
        ) {

            adminLastMessageId =
                data.latest_id;

            matiaRing();

            matiaDesktopNotification(
                "🔔 MATIA // SECURITY CHECK",
                (
                    data.client_name ||
                    "Client"
                ) +
                " sent a new message."
            );

            location.reload();
        }

    } catch (e) {

        console.log(e);

    }
}

setInterval(
    adminNotificationPoll,
    2500
);

adminNotificationPoll();

</script>
"""

    admin_name = (
        session.get(
            "admin_name"
        )
        or
        session.get(
            "admin_email"
        )
        or
        "Administrator"
    )

    body = """
<div
    class="actions"
    style="justify-content:space-between"
>

<div>

<div class="badge completed">
ADMIN CONSOLE
</div>

<h1>
Security Requests
</h1>

<p class="muted">
Welcome, %s.
</p>

</div>

<div class="actions">

<a
    class="btn"
    href="/admin/logout"
>
LOGOUT
</a>

</div>

</div>


<div class="grid">

<div class="card">

<div class="muted">
PENDING
</div>

<div class="stat">
%s
</div>

</div>


<div class="card">

<div class="muted">
ACCEPTED
</div>

<div class="stat">
%s
</div>

</div>


<div class="card">

<div class="muted">
COMPLETED
</div>

<div class="stat">
%s
</div>

</div>


<div class="card">

<div class="muted">
DECLINED
</div>

<div class="stat">
%s
</div>

</div>

</div>


<br>


<div class="card">

<div class="table-wrap">

<table>

<thead>

<tr>

<th>ID</th>
<th>CLIENT</th>
<th>TARGET</th>
<th>STATUS</th>
<th>CREATED</th>
<th>ACTION</th>

</tr>

</thead>


<tbody>

%s

</tbody>

</table>

</div>

</div>
""" % (
        esc(admin_name),
        stats["PENDING"],
        stats["ACCEPTED"],
        stats["COMPLETED"],
        stats["DECLINED"],
        rows_html,
    )

    return page(
        "Admin",
        body,
        scripts,
    )


# =========================================================
# ADMIN REQUEST
# =========================================================

@app.route(
    "/admin/request/<int:request_id>",
    methods=["GET", "POST"],
)
@admin_required
def admin_request(request_id):

    req = get_request(
        request_id
    )

    if not req:
        return (
            "Request not found",
            404,
        )

    if request.method == "POST":

        action = request.form.get(
            "action"
        )

        allowed = {
            "ACCEPTED",
            "DECLINED",
            "COMPLETED",
        }

        if action in allowed:

            conn = db()

            conn.execute(
                """
                UPDATE requests
                SET status = ?
                WHERE id = ?
                """,
                (
                    action,
                    request_id,
                ),
            )

            conn.commit()
            conn.close()

            req = get_request(
                request_id
            )

    conn = db()

    messages = conn.execute(
        """
        SELECT *
        FROM messages
        WHERE request_id = ?
        ORDER BY id ASC
        """,
        (request_id,),
    ).fetchall()

    findings = conn.execute(
        """
        SELECT *
        FROM findings
        WHERE request_id = ?
        ORDER BY id DESC
        """,
        (request_id,),
    ).fetchall()

    conn.execute(
        """
        UPDATE messages
        SET read_by_admin = 1
        WHERE request_id = ?
        AND sender = 'client'
        """,
        (request_id,),
    )

    conn.commit()
    conn.close()

    status, description, css = status_info(
        req["status"]
    )

    message_html = ""

    for msg in messages:

        cls = (
            "client"
            if msg["sender"] == "client"
            else "admin"
        )

        message_html += """
<div class="message %s">

<div class="message-meta">

<span>
%s
</span>

<span>
%s
</span>

</div>

<div>
%s
</div>

</div>
""" % (
            cls,
            esc(msg["sender"].upper()),
            esc(msg["created"]),
            nl2br(msg["message"]),
        )

    if not message_html:

        message_html = """
<div class="muted">
No messages.
</div>
"""

    findings_html = ""

    for finding in findings:

        severity = esc(
            finding["severity"].upper()
        )

        findings_html += """
<div class="finding">

<div class="message-meta">

<strong>
%s
</strong>

<span class="severity %s">
%s
</span>

</div>

<h3>
%s
</h3>

<p>
<strong>
Evidence
</strong>
<br>
%s
</p>

<p>
<strong>
Impact
</strong>
<br>
%s
</p>

<p>
<strong>
Recommendation
</strong>
<br>
%s
</p>

</div>
""" % (
            esc(finding["code"]),
            severity,
            severity,
            esc(finding["title"]),
            nl2br(finding["evidence"]),
            nl2br(finding["impact"]),
            nl2br(finding["recommendation"]),
        )

    if not findings_html:

        findings_html = """
<div class="muted">
No findings added yet.
</div>
"""

    body = """
<div
    class="actions"
    style="justify-content:space-between"
>

<div>

<div class="muted">
REQUEST #%s
</div>

<h1>
%s
</h1>

</div>


<span class="badge %s">
%s
</span>

</div>


<div class="grid">

<div class="card">

<h3>
Client
</h3>

<p>

<strong>
%s
</strong>

<br>

%s

</p>

</div>


<div class="card">

<h3>
Target
</h3>

<p>

<strong>
%s
</strong>

<br>

IP:
%s

</p>

</div>


<div class="card">

<h3>
Created
</h3>

<p>
%s
</p>

</div>

</div>


<br>


<div class="card">

<h2>
Assessment Status
</h2>

<p class="muted">
%s
</p>


<form method="post">

<div class="actions">

<button
    class="btn primary"
    name="action"
    value="ACCEPTED"
    type="submit"
>
ACCEPT
</button>


<button
    class="btn danger"
    name="action"
    value="DECLINED"
    type="submit"
>
DECLINE
</button>


<button
    class="btn"
    name="action"
    value="COMPLETED"
    type="submit"
>
MARK COMPLETED
</button>

</div>

</form>

</div>


<br>


<div class="grid">


<div class="card">

<h2>
Client Chat
</h2>

<div class="message-list">

%s

</div>


<form
    method="post"
    action="/admin/request/%s/message"
>

<textarea
    name="message"
    placeholder="Message the client..."
    required
></textarea>


<button
    class="btn primary"
    type="submit"
>
SEND MESSAGE
</button>

</form>

</div>


<div class="card">

<h2>
Add Finding
</h2>


<form
    method="post"
    action="/admin/request/%s/finding"
>


<label>
Finding Code
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

<option>INFO</option>
<option>LOW</option>
<option>MEDIUM</option>
<option>HIGH</option>
<option>CRITICAL</option>

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


<button
    class="btn primary"
    type="submit"
>
ADD FINDING
</button>

</form>

</div>

</div>


<br>


<div class="card">

<div
    class="actions"
    style="justify-content:space-between"
>

<h2>
Findings
</h2>


<a
    class="btn"
    href="/admin/request/%s/report"
>
GENERATE REPORT
</a>

</div>


%s

</div>


<br>


<a
    class="btn"
    href="/admin"
>
← BACK TO ADMIN
</a>
""" % (
        req["id"],
        esc(req["name"]),
        css,
        esc(status),
        esc(req["name"]),
        esc(req["email"]),
        esc(req["target"]),
        esc(
            req["target_ip"]
            or
            "unresolved"
        ),
        esc(req["created"]),
        esc(description),
        message_html,
        request_id,
        request_id,
        request_id,
        findings_html,
    )

    return page(
        "Request #%s" % request_id,
        body,
    )


# =========================================================
# ADMIN MESSAGE
# =========================================================

@app.route(
    "/admin/request/<int:request_id>/message",
    methods=["POST"],
)
@admin_required
def admin_message(request_id):

    req = get_request(
        request_id
    )

    if not req:
        return (
            "Request not found",
            404,
        )

    message = request.form.get(
        "message",
        "",
    ).strip()

    if message:

        conn = db()

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
                1,
            ),
        )

        conn.commit()
        conn.close()

    return redirect(
        url_for(
            "admin_request",
            request_id=request_id,
        )
    )


# =========================================================
# ADMIN MESSAGES API
# =========================================================

@app.route(
    "/api/admin/request/<int:request_id>/messages"
)
@admin_required
def admin_messages_api(request_id):

    conn = db()

    rows = conn.execute(
        """
        SELECT
            id,
            sender,
            message,
            created
        FROM messages
        WHERE request_id = ?
        ORDER BY id ASC
        """,
        (request_id,),
    ).fetchall()

    conn.execute(
        """
        UPDATE messages
        SET read_by_admin = 1
        WHERE request_id = ?
        AND sender = 'client'
        """,
        (request_id,),
    )

    conn.commit()
    conn.close()

    return jsonify({
        "messages": [
            dict(row)
            for row in rows
        ]
    })


# =========================================================
# ADD FINDING
# =========================================================

@app.route(
    "/admin/request/<int:request_id>/finding",
    methods=["POST"],
)
@admin_required
def add_finding(request_id):

    req = get_request(
        request_id
    )

    if not req:
        return (
            "Request not found",
            404,
        )

    code = request.form.get(
        "code",
        "",
    ).strip()

    title = request.form.get(
        "title",
        "",
    ).strip()

    severity = request.form.get(
        "severity",
        "INFO",
    ).strip().upper()

    evidence = request.form.get(
        "evidence",
        "",
    ).strip()

    impact = request.form.get(
        "impact",
        "",
    ).strip()

    recommendation = request.form.get(
        "recommendation",
        "",
    ).strip()

    allowed_severity = {
        "INFO",
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    }

    if severity not in allowed_severity:
        severity = "INFO"

    if (
        code
        and title
        and evidence
        and impact
        and recommendation
    ):

        conn = db()

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
                code,
                title,
                severity,
                evidence,
                impact,
                recommendation,
            ),
        )

        conn.commit()
        conn.close()

    return redirect(
        url_for(
            "admin_request",
            request_id=request_id,
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

    req = get_request(
        request_id
    )

    if not req:
        return (
            "Request not found",
            404,
        )

    conn = db()

    findings = conn.execute(
        """
        SELECT *
        FROM findings
        WHERE request_id = ?
        ORDER BY id ASC
        """,
        (request_id,),
    ).fetchall()

    conn.close()

    findings_html = ""

    for finding in findings:

        findings_html += """
<section style="
    border:1px solid #d7dde5;
    border-radius:12px;
    padding:20px;
    margin:18px 0;
">

<h3>
%s — %s
</h3>

<p>
<strong>Severity:</strong>
%s
</p>

<p>
<strong>Evidence</strong>
<br>
%s
</p>

<p>
<strong>Impact</strong>
<br>
%s
</p>

<p>
<strong>Recommendation</strong>
<br>
%s
</p>

</section>
""" % (
            esc(finding["code"]),
            esc(finding["title"]),
            esc(finding["severity"]),
            nl2br(finding["evidence"]),
            nl2br(finding["impact"]),
            nl2br(finding["recommendation"]),
        )

    if not findings_html:

        findings_html = """
<p>
No findings have been documented.
</p>
"""

    report_html = """
<!doctype html>

<html>

<head>

<meta charset="utf-8">

<title>
Security Assessment Report #%s
</title>

<style>

body {
    font-family:
        Arial,
        Helvetica,
        sans-serif;

    max-width:
        900px;

    margin:
        50px auto;

    padding:
        20px;

    color:
        #17202a;

    line-height:
        1.6;
}

h1 {
    margin-bottom:5px;
}

.meta {
    color:#5d6d7e;
    margin-bottom:35px;
}

@media print {

    body {
        margin:20px;
    }

    .print {
        display:none;
    }
}

</style>

</head>

<body>

<button
    class="print"
    onclick="window.print()"
>
PRINT / SAVE PDF
</button>

<h1>
MATIA // SECURITY CHECK
</h1>

<h2>
Authorized Security Assessment Report
</h2>

<div class="meta">

<strong>
Request:
</strong>

#%s

<br>

<strong>
Client:
</strong>

%s

<br>

<strong>
Email:
</strong>

%s

<br>

<strong>
Target:
</strong>

%s

<br>

<strong>
Resolved IP:
</strong>

%s

<br>

<strong>
Status:
</strong>

%s

<br>

<strong>
Created:
</strong>

%s

</div>

<h2>
Authorized Scope
</h2>

<p>
%s
</p>

<h2>
Findings
</h2>

%s

<hr>

<p class="meta">
Generated by MATIA // SECURITY CHECK
</p>

</body>

</html>
""" % (
        req["id"],
        req["id"],
        esc(req["name"]),
        esc(req["email"]),
        esc(req["target"]),
        esc(
            req["target_ip"]
            or "Not resolved"
        ),
        esc(req["status"]),
        esc(req["created"]),
        nl2br(req["scope"]),
        findings_html,
    )

    return report_html


# =========================================================
# LOGOUT
# =========================================================

@app.route(
    "/admin/logout"
)
def admin_logout():

    session.clear()

    return redirect(
        url_for("home")
    )


# =========================================================
# FAVICON
# =========================================================

@app.route("/favicon.ico")
def favicon():
    return "", 204


# =========================================================
# ERROR HANDLERS
# =========================================================

@app.errorhandler(404)
def not_found(error):

    body = """
<div class="card">

<div class="badge declined">
404
</div>

<h1>
Page Not Found
</h1>

<p class="muted">
The requested resource does not exist.
</p>

<a
    class="btn"
    href="/"
>
RETURN HOME
</a>

</div>
"""

    return page(
        "404",
        body,
    ), 404


@app.errorhandler(500)
def server_error(error):

    body = """
<div class="card">

<div class="badge declined">
500
</div>

<h1>
Server Error
</h1>

<p class="muted">
An internal application error occurred.
</p>

<a
    class="btn"
    href="/"
>
RETURN HOME
</a>

</div>
"""

    return page(
        "500",
        body,
    ), 500


# =========================================================
# START
# =========================================================

if __name__ == "__main__":

    port = int(
        os.environ.get(
            "PORT",
            "5000",
        )
    )

    print()
    print("=" * 62)
    print("        MATIA // SECURITY CHECK")
    print("=" * 62)
    print(" Status : ONLINE")
    print(" Host   : 0.0.0.0")
    print(" Port   :", port)
    print(" DB     :", DB_FILE)
    print(" Admin  : Google OAuth")
    print(" Access : Restricted")
    print(
        " Admins : "
        "kleimatia1@gmail.com + "
        "vantyx199@gmail.com"
    )
    print("=" * 62)
    print()

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False,
    )

