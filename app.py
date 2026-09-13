
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
# NO GOOGLE OAUTH
# PRIVATE ADMIN LOGIN
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


# Only these two email addresses are allowed to use
# the administrator login.
ALLOWED_ADMIN_EMAILS = {
    "kleimatia1@gmail.com",
    "vantyx199@gmail.com",
}


# Both approved admin accounts use the password stored
# in Render as MATIA_ADMIN_PASSWORD.
ADMIN_PASSWORD = os.environ.get(
    "MATIA_ADMIN_PASSWORD",
    "",
)


app.config["SECRET_KEY"] = SECRET_KEY

app.config["SESSION_COOKIE_HTTPONLY"] = True

app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

app.config["SESSION_COOKIE_SECURE"] = (
    os.environ.get(
        "SESSION_COOKIE_SECURE",
        "1",
    ) == "1"
)

app.config["SESSION_COOKIE_NAME"] = (
    "matia_admin_session"
)


# =========================================================
# DATABASE
# =========================================================

def db():
    conn = sqlite3.connect(
        DB_FILE
    )

    conn.row_factory = sqlite3.Row

    return conn


def init_db():

    conn = db()

    conn.execute(
        """
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
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id INTEGER NOT NULL,
            sender TEXT NOT NULL,
            message TEXT NOT NULL,
            created TEXT NOT NULL,
            read_by_client INTEGER NOT NULL DEFAULT 0,
            read_by_admin INTEGER NOT NULL DEFAULT 0
        )
        """
    )

    conn.execute(
        """
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
        """
    )

    columns = {
        row["name"]
        for row in conn.execute(
            "PRAGMA table_info(messages)"
        ).fetchall()
    }

    if "read_by_client" not in columns:
        conn.execute(
            """
            ALTER TABLE messages
            ADD COLUMN read_by_client
            INTEGER NOT NULL DEFAULT 0
            """
        )

    if "read_by_admin" not in columns:
        conn.execute(
            """
            ALTER TABLE messages
            ADD COLUMN read_by_admin
            INTEGER NOT NULL DEFAULT 0
            """
        )

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
    return escape(
        str(value or "")
    )


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
        or ""
    ).strip().lower()


def is_admin():

    email = current_admin_email()

    return (
        session.get(
            "admin_logged_in"
        ) is True
        and
        email in ALLOWED_ADMIN_EMAILS
    )


def admin_required(fn):

    @wraps(fn)
    def wrapper(*args, **kwargs):

        if not is_admin():

            return redirect(
                url_for(
                    "admin_login",
                    next=request.path,
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
# CSS
# =========================================================

STYLE = r"""
<style>

:root {
    --bg: #03060a;
    --bg2: #071019;
    --panel: rgba(10, 18, 29, .92);
    --panel2: rgba(15, 27, 42, .92);
    --border: rgba(80, 150, 210, .18);
    --border2: rgba(66, 232, 255, .24);

    --text: #edf7ff;
    --muted: #7d93aa;

    --blue: #31a8ff;
    --cyan: #45edff;
    --green: #39e57d;
    --yellow: #ffd166;
    --red: #ff597a;

    --shadow:
        0 22px 65px rgba(0,0,0,.34);
}

* {
    box-sizing: border-box;
}

html {
    scroll-behavior: smooth;
}

body {
    margin: 0;

    min-height: 100vh;

    background:
        radial-gradient(
            circle at 10% 5%,
            rgba(49,168,255,.12),
            transparent 28%
        ),
        radial-gradient(
            circle at 88% 20%,
            rgba(69,237,255,.07),
            transparent 28%
        ),
        radial-gradient(
            circle at 50% 100%,
            rgba(49,168,255,.05),
            transparent 35%
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

body::before {
    content: "";

    position: fixed;

    inset: 0;

    pointer-events: none;

    background-image:
        linear-gradient(
            rgba(255,255,255,.012) 1px,
            transparent 1px
        ),
        linear-gradient(
            90deg,
            rgba(255,255,255,.012) 1px,
            transparent 1px
        );

    background-size: 42px 42px;

    mask-image:
        linear-gradient(
            to bottom,
            black,
            transparent 88%
        );
}

a {
    color: inherit;
    text-decoration: none;
}

.nav {
    position: sticky;

    top: 0;

    z-index: 50;

    display: flex;

    align-items: center;

    justify-content: space-between;

    gap: 16px;

    padding: 15px 24px;

    background:
        rgba(3,6,10,.76);

    backdrop-filter: blur(22px);

    border-bottom:
        1px solid var(--border);
}

.logo {
    display: inline-flex;

    align-items: center;

    gap: 8px;

    font-size: 14px;

    font-weight: 950;

    letter-spacing: .09em;
}

.logo span {
    color: var(--cyan);
}

.nav-right {
    display: flex;

    align-items: center;

    justify-content: flex-end;

    gap: 8px;

    flex-wrap: wrap;
}

.online {
    color: var(--green);

    font-size: 11px;

    font-weight: 850;

    letter-spacing: .04em;
}

.container {
    width: min(
        1180px,
        calc(100% - 30px)
    );

    margin: 0 auto;

    padding: 38px 0 80px;
}

.hero {
    position: relative;

    padding: 72px 0 58px;
}

.hero::after {
    content: "";

    position: absolute;

    width: 250px;
    height: 250px;

    right: 2%;

    top: 25px;

    border-radius: 50%;

    background:
        radial-gradient(
            circle,
            rgba(69,237,255,.11),
            transparent 68%
        );

    pointer-events: none;
}

.hero h1 {
    position: relative;

    z-index: 1;

    max-width: 900px;

    margin:
        12px 0 22px;

    font-size:
        clamp(
            46px,
            8vw,
            94px
        );

    line-height: .91;

    letter-spacing: -.07em;
}

.hero h1 span {
    color: var(--cyan);

    text-shadow:
        0 0 32px rgba(69,237,255,.18);
}

.hero p {
    max-width: 760px;

    color: var(--muted);

    font-size: 17px;

    line-height: 1.75;
}

.container h1 {
    letter-spacing: -.045em;
}

.grid {
    display: grid;

    grid-template-columns:
        repeat(
            auto-fit,
            minmax(270px, 1fr)
        );

    gap: 16px;
}

.card {
    position: relative;

    overflow: hidden;

    background:
        linear-gradient(
            180deg,
            rgba(255,255,255,.028),
            transparent 45%
        ),
        var(--panel);

    border:
        1px solid var(--border);

    border-radius: 20px;

    padding: 22px;

    box-shadow:
        var(--shadow);
}

.card::before {
    content: "";

    position: absolute;

    top: 0;
    left: 0;
    right: 0;

    height: 1px;

    background:
        linear-gradient(
            90deg,
            transparent,
            rgba(69,237,255,.22),
            transparent
        );
}

.card h2,
.card h3 {
    margin-top: 0;
}

.muted {
    color: var(--muted);
}

.btn {
    display: inline-flex;

    align-items: center;

    justify-content: center;

    gap: 8px;

    min-height: 42px;

    border:
        1px solid var(--border);

    border-radius: 12px;

    background:
        linear-gradient(
            180deg,
            rgba(255,255,255,.035),
            rgba(255,255,255,.012)
        ),
        var(--panel2);

    color: var(--text);

    padding: 10px 15px;

    cursor: pointer;

    font-weight: 800;

    transition:
        transform .16s ease,
        border-color .16s ease,
        box-shadow .16s ease,
        background .16s ease;
}

.btn:hover {
    transform:
        translateY(-1px);

    border-color:
        var(--blue);

    box-shadow:
        0 8px 26px
        rgba(49,168,255,.10);
}

.btn.primary {
    background:
        linear-gradient(
            135deg,
            #087dd7,
            #12b9d2
        );

    border-color:
        rgba(69,237,255,.66);

    box-shadow:
        0 10px 30px
        rgba(49,168,255,.16);
}

.btn.danger {
    color: #ff9ab0;

    border-color:
        rgba(255,89,122,.35);
}

.actions {
    display: flex;

    align-items: center;

    gap: 9px;

    flex-wrap: wrap;

    margin-top: 16px;
}

.badge {
    display: inline-flex;

    align-items: center;

    gap: 6px;

    padding: 7px 11px;

    border-radius: 999px;

    font-size: 10px;

    font-weight: 950;

    letter-spacing: .07em;
}

.badge.pending {
    color: var(--yellow);

    background:
        rgba(255,209,102,.10);

    border:
        1px solid rgba(255,209,102,.14);
}

.badge.accepted {
    color: var(--green);

    background:
        rgba(57,229,125,.10);

    border:
        1px solid rgba(57,229,125,.15);
}

.badge.declined {
    color: var(--red);

    background:
        rgba(255,89,122,.10);

    border:
        1px solid rgba(255,89,122,.15);
}

.badge.completed {
    color: var(--cyan);

    background:
        rgba(69,237,255,.09);

    border:
        1px solid rgba(69,237,255,.14);
}

.stat {
    margin-top: 8px;

    font-size: 38px;

    line-height: 1;

    font-weight: 950;

    letter-spacing: -.04em;
}

input,
textarea,
select {
    width: 100%;

    border:
        1px solid var(--border);

    border-radius: 12px;

    background:
        rgba(3,8,14,.88);

    color: var(--text);

    padding: 12px 13px;

    outline: none;

    transition:
        border-color .15s ease,
        box-shadow .15s ease;
}

input:focus,
textarea:focus,
select:focus {
    border-color:
        rgba(49,168,255,.65);

    box-shadow:
        0 0 0 3px
        rgba(49,168,255,.08);
}

textarea {
    min-height: 125px;

    resize: vertical;
}

label {
    display: block;

    margin: 14px 0 7px;

    color: #a8b9ca;

    font-size: 12px;

    font-weight: 800;
}

.alert {
    margin-bottom: 16px;

    padding: 13px 15px;

    border-radius: 12px;

    border:
        1px solid var(--border);

    background:
        var(--panel2);
}

.alert.error {
    color: #ff9daf;

    border-color:
        rgba(255,89,122,.35);
}

.table-wrap {
    width: 100%;

    overflow-x: auto;
}

table {
    width: 100%;

    border-collapse: collapse;
}

th,
td {
    padding: 13px 11px;

    border-bottom:
        1px solid var(--border);

    text-align: left;

    white-space: nowrap;
}

th {
    color: var(--muted);

    font-size: 10px;

    text-transform: uppercase;

    letter-spacing: .08em;
}

.finding {
    margin-bottom: 12px;

    padding: 17px;

    border:
        1px solid var(--border);

    border-radius: 15px;

    background:
        rgba(5,11,18,.74);
}

.severity {
    font-size: 11px;

    font-weight: 950;
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

.message-list {
    display: flex;

    flex-direction: column;

    gap: 12px;

    max-height: 490px;

    overflow-y: auto;

    padding-right: 4px;
}

.message {
    max-width: 90%;

    padding: 13px 15px;

    border-radius: 15px;

    background:
        #09111b;

    border:
        1px solid var(--border);

    box-shadow:
        0 7px 28px
        rgba(0,0,0,.15);
}

.message.admin {
    align-self: flex-end;

    border-color:
        rgba(69,237,255,.22);

    background:
        linear-gradient(
            145deg,
            rgba(20,73,88,.38),
            rgba(7,15,23,.95)
        );

    border-bottom-right-radius: 5px;
}

.message.client {
    align-self: flex-start;

    border-color:
        rgba(49,168,255,.18);

    background:
        linear-gradient(
            145deg,
            rgba(12,46,72,.32),
            rgba(7,13,21,.95)
        );

    border-bottom-left-radius: 5px;
}

.message-meta {
    display: flex;

    align-items: center;

    justify-content: space-between;

    gap: 10px;

    margin-bottom: 8px;

    color: var(--muted);

    font-size: 10px;

    font-weight: 750;
}

.chat-compose {
    margin-top: 18px;

    padding-top: 16px;

    border-top:
        1px solid var(--border);
}

.chat-title {
    display: flex;

    align-items: center;

    justify-content: space-between;

    gap: 10px;

    margin-bottom: 14px;
}

.chat-status {
    display: inline-flex;

    align-items: center;

    gap: 6px;

    color: var(--green);

    font-size: 10px;

    font-weight: 850;
}

.chat-dot {
    width: 7px;
    height: 7px;

    border-radius: 50%;

    background:
        var(--green);

    box-shadow:
        0 0 11px
        rgba(57,229,125,.7);
}

.login-box {
    width: min(
        470px,
        100%
    );

    margin: 50px auto;
}

.login-brand {
    text-align: center;

    margin-bottom: 20px;
}

.login-brand .mark {
    width: 66px;
    height: 66px;

    margin: 0 auto 15px;

    display: grid;

    place-items: center;

    border-radius: 18px;

    color: var(--cyan);

    font-size: 24px;

    font-weight: 950;

    background:
        linear-gradient(
            145deg,
            rgba(69,237,255,.10),
            rgba(49,168,255,.06)
        );

    border:
        1px solid
        rgba(69,237,255,.18);

    box-shadow:
        0 0 45px
        rgba(69,237,255,.08);
}

.login-brand h1 {
    margin: 0;
}

.login-brand p {
    color: var(--muted);
}

.footer {
    text-align: center;

    padding: 28px 0 35px;

    color: #506175;

    font-size: 10px;

    letter-spacing: .04em;
}

@media (max-width: 760px) {

    .nav {
        align-items: flex-start;

        flex-direction: column;
    }

    .nav-right {
        justify-content: flex-start;
    }

    .hero {
        padding-top: 42px;
    }

    .message {
        max-width: 96%;
    }
}

</style>
"""


# =========================================================
# NOTIFICATIONS / SOUND
# =========================================================

NOTIFICATION_SCRIPT = r"""
<script>

(function () {

    let audioContext = null;

    let soundEnabled =
        localStorage.getItem("matia_sound") !== "off";

    let notificationsEnabled =
        localStorage.getItem("matia_notifications") === "on";


    function initAudio() {

        try {

            if (!audioContext) {

                const AudioContext =
                    window.AudioContext ||
                    window.webkitAudioContext;

                if (AudioContext) {
                    audioContext =
                        new AudioContext();
                }
            }

            if (
                audioContext &&
                audioContext.state === "suspended"
            ) {

                audioContext.resume();

            }

        } catch (error) {

            console.log(error);

        }
    }


    window.matiaRing = function () {

        if (!soundEnabled) {
            return;
        }

        try {

            initAudio();

            if (!audioContext) {
                return;
            }

            const ctx = audioContext;
            const start = ctx.currentTime;


            function tone(
                frequency,
                offset,
                duration
            ) {

                const oscillator =
                    ctx.createOscillator();

                const gain =
                    ctx.createGain();

                oscillator.type =
                    "sine";

                oscillator.frequency.setValueAtTime(
                    frequency,
                    start + offset
                );

                gain.gain.setValueAtTime(
                    0.0001,
                    start + offset
                );

                gain.gain.exponentialRampToValueAtTime(
                    0.17,
                    start + offset + 0.02
                );

                gain.gain.exponentialRampToValueAtTime(
                    0.0001,
                    start + offset + duration
                );

                oscillator.connect(gain);
                gain.connect(ctx.destination);

                oscillator.start(
                    start + offset
                );

                oscillator.stop(
                    start +
                    offset +
                    duration +
                    0.03
                );
            }


            tone(880, 0, 0.17);
            tone(660, 0.22, 0.21);

        } catch (error) {

            console.log(error);

        }
    };


    window.enableMatiaNotifications =
        async function () {

            try {

                initAudio();

                if (
                    !("Notification" in window)
                ) {

                    alert(
                        "Browser notifications are not supported."
                    );

                    return;
                }

                const permission =
                    await Notification.requestPermission();

                if (
                    permission ===
                    "granted"
                ) {

                    notificationsEnabled =
                        true;

                    localStorage.setItem(
                        "matia_notifications",
                        "on"
                    );

                }

                updateButtons();

            } catch (error) {

                console.log(error);

            }
        };


    window.matiaDesktopNotification =
        function (
            title,
            body
        ) {

            if (!notificationsEnabled) {
                return;
            }

            if (
                !("Notification" in window)
            ) {
                return;
            }

            if (
                Notification.permission !==
                "granted"
            ) {
                return;
            }

            try {

                new Notification(
                    title,
                    {
                        body: body,
                        icon: "/favicon.ico"
                    }
                );

            } catch (error) {

                console.log(error);

            }
        };


    window.toggleMatiaSound =
        function () {

            soundEnabled =
                !soundEnabled;

            localStorage.setItem(
                "matia_sound",
                soundEnabled
                    ? "on"
                    : "off"
            );

            if (
                soundEnabled
            ) {

                initAudio();
                matiaRing();

            }

            updateButtons();

        };


    function updateButtons() {

        document
            .querySelectorAll(
                "[data-matia-sound]"
            )
            .forEach(
                function (button) {

                    button.textContent =
                        soundEnabled
                            ? "🔊 RING ON"
                            : "🔇 RING OFF";

                }
            );


        document
            .querySelectorAll(
                "[data-matia-notifications]"
            )
            .forEach(
                function (button) {

                    button.textContent =
                        notificationsEnabled
                            ? "🔔 NOTIFICATIONS ON"
                            : "🔔 ENABLE NOTIFICATIONS";

                }
            );

    }


    document.addEventListener(
        "click",
        function () {

            initAudio();

        },
        {
            once: true
        }
    );


    document.addEventListener(
        "DOMContentLoaded",
        function () {

            updateButtons();

        }
    );

})();

</script>
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
<a class="btn" href="/admin">
    ADMIN CONSOLE
</a>

<a class="btn danger" href="/admin/logout">
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
    content="width=device-width, initial-scale=1"
>

<title>
{{ title }} |
MATIA // SECURITY CHECK
</title>

{{ style|safe }}

</head>


<body>


<nav class="nav">

<a href="/" class="logo">
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

    if is_admin():

        admin_controls = """
<a
    class="btn primary"
    href="/admin"
>
    🛡 ADMIN CONSOLE
</a>

<a
    class="btn danger"
    href="/admin/logout"
>
    LOGOUT
</a>
"""

    else:

        admin_controls = """
<a
    class="btn"
    href="/admin/login"
>
    🔐 ADMIN LOGIN
</a>
"""


    body = """
<section class="hero">

<div class="badge completed">
● AUTHORIZED SECURITY PLATFORM
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

%s

</div>

</section>


<div class="grid">

<div class="card">

<h3>
01 · REQUEST
</h3>

<p class="muted">
Submit an authorized security assessment request
with a defined scope.
</p>

</div>


<div class="card">

<h3>
02 · REVIEW
</h3>

<p class="muted">
The administrator reviews and accepts or declines
the request.
</p>

</div>


<div class="card">

<h3>
03 · ASSESS
</h3>

<p class="muted">
Findings and evidence can be documented inside
the assessment workspace.
</p>

</div>


<div class="card">

<h3>
04 · REPORT
</h3>

<p class="muted">
Completed findings can be exported as a
professional security report.
</p>

</div>

</div>
""" % admin_controls


    return page(
        "Home",
        body,
    )


# =========================================================
# ADMIN LOGIN
# =========================================================

@app.route(
    "/admin/login",
    methods=["GET", "POST"],
)
def admin_login():

    error = ""


    if request.method == "POST":

        email = (
            request.form.get(
                "email",
                "",
            )
            .strip()
            .lower()
        )


        password = request.form.get(
            "password",
            "",
        )


        if (
            not ADMIN_PASSWORD
        ):

            error = (
                "Admin password is not configured "
                "on the server."
            )


        elif (
            email not in
            ALLOWED_ADMIN_EMAILS
        ):

            error = (
                "This account is not authorized."
            )


        elif (
            password !=
            ADMIN_PASSWORD
        ):

            error = (
                "Invalid admin password."
            )


        else:

            session.clear()

            session["admin_logged_in"] = True

            session["admin_email"] = email

            session["admin_name"] = email

            next_url = (
                request.form.get(
                    "next",
                    "/admin",
                )
                or
                "/admin"
            )

            if not next_url.startswith("/"):
                next_url = "/admin"

            return redirect(
                next_url
            )


    body = """
<div class="login-box">

<div class="login-brand">

<div class="mark">
M
</div>

<h1>
MATIA <span style="color:var(--cyan)">
//
</span> ADMIN
</h1>

<p>
Restricted administrator access
</p>

</div>


<div class="card">

<div class="badge completed">
SECURE ADMIN AUTHENTICATION
</div>


<h2 style="margin-top:14px">
Sign in
</h2>


%s


<form
    method="post"
>


<input
    type="hidden"
    name="next"
    value="%s"
>


<label>
Admin Email
</label>


<input
    name="email"
    type="email"
    placeholder="your-admin-email@gmail.com"
    autocomplete="username"
    required
>


<label>
Admin Password
</label>


<input
    name="password"
    type="password"
    placeholder="••••••••••••"
    autocomplete="current-password"
    required
>


<div class="actions">


<button
    class="btn primary"
    type="submit"
>
🔓 ENTER ADMIN CONSOLE
</button>


<a
    class="btn"
    href="/"
>
CANCEL
</a>


</div>


</form>


<p class="muted" style="margin-top:18px">
Only the two authorized administrator email
addresses can access this panel.
</p>


</div>


</div>
""" % (
        (
            '<div class="alert error">'
            + esc(error)
            + "</div>"
        )
        if error
        else "",
        esc(
            request.args.get(
                "next",
                "/admin",
            )
        ),
    )


    return page(
        "Admin Login",
        body,
    )


# =========================================================
# ADMIN LOGOUT
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
# CLIENT REQUEST
# =========================================================

@app.route(
    "/request",
    methods=["GET", "POST"],
)
def create_request():

    error = ""


    if request.method == "POST":

        name = (
            request.form.get(
                "name",
                "",
            )
            .strip()
        )


        email = (
            request.form.get(
                "email",
                "",
            )
            .strip()
        )


        target = (
            request.form.get(
                "target",
                "",
            )
            .strip()
        )


        scope = (
            request.form.get(
                "scope",
                "",
            )
            .strip()
        )


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

            target_ip =
                resolve_hostname(
                    target
                )


            conn = db()


            cursor = conn.execute(
                """
                INSERT INTO requests (
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


            request_id =
                cursor.lastrowid


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
<h1>
New Security Request
</h1>


<p class="muted">
Submit only systems you own or have explicit permission
to assess.
</p>


%s


<div class="card">

<form method="post">


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
Target
</label>


<input
    name="target"
    placeholder="example.com"
    required
>


<label>
Authorized Scope
</label>


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

    req =
        get_request(
            request_id
        )


    if not req:
        return "Request not found", 404


    status, description, css =
        status_info(
            req["status"]
        )


    conn = db()


    messages =
        conn.execute(
            """
            SELECT *
            FROM messages
            WHERE request_id = ?
            ORDER BY id ASC
            """,
            (request_id,),
        ).fetchall()


    findings =
        conn.execute(
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


        sender_label = (
            "MATIA"
            if msg["sender"] == "matia"
            else "CLIENT"
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
            sender_label,
            esc(msg["created"]),
            nl2br(msg["message"]),
        )


    if not message_html:

        message_html = """
<div class="muted">
No messages yet. Your conversation will appear here.
</div>
"""


    findings_html = ""


    for finding in findings:

        severity =
            esc(
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
No findings published yet.
</div>
"""


    scripts = """
<script>

let clientFirstPoll = true;

let clientLastMessageId = 0;

let clientLastStatus = %r;


async function pollClient() {

    try {

        const response =
            await fetch(
                "/api/client/%s/notifications",
                {
                    cache:
                        "no-store"
                }
            );


        const data =
            await response.json();


        if (
            clientFirstPoll
        ) {

            clientLastMessageId =
                data.latest_id || 0;

            clientLastStatus =
                data.status ||
                clientLastStatus;

            clientFirstPoll =
                false;

            return;
        }


        if (
            data.latest_id &&
            data.latest_id >
            clientLastMessageId &&
            data.latest_sender ===
            "matia"
        ) {

            clientLastMessageId =
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
            data.status !==
            clientLastStatus
        ) {

            clientLastStatus =
                data.status;


            matiaRing();


            matiaDesktopNotification(
                "⚡ Status Updated",
                "Assessment status changed to " +
                data.status
            );


            location.reload();
        }


    } catch (error) {

        console.log(error);

    }
}


setInterval(
    pollClient,
    2500
);


pollClient();

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

<strong>
%s
</strong>

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


<div class="chat-title">

<div>

<h2 style="margin:0">
💬 Secure Chat
</h2>

<p class="muted" style="margin:6px 0 0">
Direct communication with MATIA
</p>

</div>

<div class="chat-status">
<span class="chat-dot"></span>
LIVE
</div>

</div>


<div class="message-list">

%s

</div>


<div class="chat-compose">


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
➤ SEND MESSAGE
</button>


</div>


</form>


</div>


</div>


<div class="card">


<h2>
🛡 Security Findings
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

    req =
        get_request(
            request_id
        )


    if not req:
        return "Request not found", 404


    message =
        request.form.get(
            "message",
            "",
        ).strip()


    if message:

        conn = db()


        conn.execute(
            """
            INSERT INTO messages (
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
            )
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
# CLIENT NOTIFICATION API
# =========================================================

@app.route(
    "/api/client/<int:request_id>/notifications"
)
def client_notifications(request_id):

    conn = db()


    req =
        conn.execute(
            """
            SELECT *
            FROM requests
            WHERE id = ?
            """,
            (request_id,),
        ).fetchone()


    latest =
        conn.execute(
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

        "status":
            req["status"],

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
# ADMIN DASHBOARD
# =========================================================

@app.route("/admin")
@admin_required
def admin_dashboard():

    conn = db()


    requests_rows =
        conn.execute(
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

        stats[status] =
            conn.execute(
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

        _, _, css =
            status_info(
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


    admin_name =
        session.get(
            "admin_name"
        ) or current_admin_email()


    scripts = r"""
<script>

let adminFirstPoll = true;

let adminLastMessageId = 0;


async function pollAdmin() {

    try {

        const response =
            await fetch(
                "/api/admin/notifications",
                {
                    cache:
                        "no-store"
                }
            );


        const data =
            await response.json();


        if (
            adminFirstPoll
        ) {

            adminLastMessageId =
                data.latest_id || 0;

            adminFirstPoll =
                false;

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


    } catch (error) {

        console.log(error);

    }

}


setInterval(
    pollAdmin,
    2500
);


pollAdmin();

</script>
"""


    body = """
<div
    class="actions"
    style="justify-content:space-between"
>


<div>

<div class="badge completed">
🛡 ADMIN CONSOLE
</div>


<h1>
Security Command Center
</h1>


<p class="muted">
Welcome back,
<strong>
%s
</strong>
</p>


<p class="muted">
Signed in as:
%s
</p>


</div>


<div class="actions">


<a
    class="btn"
    href="/"
>
HOME
</a>


<a
    class="btn danger"
    href="/admin/logout"
>
LOGOUT
</a>


</div>


</div>


<div class="grid">


<div class="card">

<div class="muted">
PENDING REQUESTS
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


<div
    class="actions"
    style="justify-content:space-between"
>


<div>

<h2 style="margin:0">
Security Requests
</h2>

<p class="muted" style="margin:6px 0 0">
Authorized assessment workspace
</p>

</div>


<div class="chat-status">
<span class="chat-dot"></span>
LIVE
</div>


</div>


<br>


<div class="table-wrap">


<table>


<thead>


<tr>

<th>
ID
</th>

<th>
CLIENT
</th>

<th>
TARGET
</th>

<th>
STATUS
</th>

<th>
CREATED
</th>

<th>
ACTION
</th>

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
        esc(current_admin_email()),
        stats["PENDING"],
        stats["ACCEPTED"],
        stats["COMPLETED"],
        stats["DECLINED"],
        rows_html,
    )


    return page(
        "Admin Console",
        body,
        scripts,
    )


# =========================================================
# ADMIN NOTIFICATIONS
# =========================================================

@app.route(
    "/api/admin/notifications"
)
@admin_required
def admin_notifications():

    conn = db()


    latest =
        conn.execute(
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


    unread =
        conn.execute(
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

        "unread":
            unread,

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
# ADMIN REQUEST DETAIL
# =========================================================

@app.route(
    "/admin/request/<int:request_id>",
    methods=["GET", "POST"],
)
@admin_required
def admin_request(request_id):

    req =
        get_request(
            request_id
        )


    if not req:

        return "Request not found", 404


    if request.method == "POST":

        action =
            request.form.get(
                "action"
            )


        if action in {
            "ACCEPTED",
            "DECLINED",
            "COMPLETED",
        }:

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


            req =
                get_request(
                    request_id
                )


    conn = db()


    messages =
        conn.execute(
            """
            SELECT *
            FROM messages
            WHERE request_id = ?
            ORDER BY id ASC
            """,
            (request_id,),
        ).fetchall()


    findings =
        conn.execute(
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


    status, description, css =
        status_info(
            req["status"]
        )


    message_html = ""


    for msg in messages:

        cls = (
            "client"
            if msg["sender"] == "client"
            else "admin"
        )


        sender_label = (
            "CLIENT"
            if msg["sender"] == "client"
            else "MATIA"
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
            sender_label,
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

        severity =
            esc(
                finding["severity"].upper()
            )


        findings_html += """
<div class="finding">

<div class="message-meta">

<strong>
%s
</strong>

<span
    class="severity %s"
>
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

<p class="muted">
%s
</p>

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
Assessment Control
</h2>


<p class="muted">
%s
</p>


<form
    method="post"
>


<div class="actions">


<button
    class="btn primary"
    name="action"
    value="ACCEPTED"
    type="submit"
>
✓ ACCEPT
</button>


<button
    class="btn danger"
    name="action"
    value="DECLINED"
    type="submit"
>
✕ DECLINE
</button>


<button
    class="btn"
    name="action"
    value="COMPLETED"
    type="submit"
>
✓ MARK COMPLETED
</button>


</div>


</form>


</div>


<br>


<div class="grid">


<div class="card">


<div class="chat-title">


<div>

<h2 style="margin:0">
💬 Client Chat
</h2>

<p class="muted" style="margin:6px 0 0">
Live conversation
</p>

</div>


<div class="chat-status">
<span class="chat-dot"></span>
LIVE
</div>


</div>


<div class="message-list">

%s

</div>


<div class="chat-compose">


<form
    method="post"
    action="/admin/request/%s/message"
>


<textarea
    name="message"
    placeholder="Type a professional message to the client..."
    required
></textarea>


<div class="actions">


<button
    class="btn primary"
    type="submit"
>
➤ SEND MESSAGE
</button>


</div>


</form>


</div>


</div>


<div class="card">


<h2>
🛡 Add Finding
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


<select
    name="severity"
>


<option>
INFO
</option>

<option>
LOW
</option>

<option>
MEDIUM
</option>

<option>
HIGH
</option>

<option>
CRITICAL
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


<div class="actions">


<button
    class="btn primary"
    type="submit"
>
+ ADD FINDING
</button>


</div>


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
Security Findings
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
        esc(req["email"]),
        css,
        esc(status),
        esc(req["name"]),
        esc(req["email"]),
        esc(req["target"]),
        esc(
            req["target_ip"]
            or "unresolved"
        ),
        esc(req["created"]),
        esc(description),
        message_html,
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

    req =
        get_request(
            request_id
        )


    if not req:
        return "Request not found", 404


    message =
        request.form.get(
            "message",
            "",
        ).strip()


    if message:

        conn = db()


        conn.execute(
            """
            INSERT INTO messages (
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
# ADD FINDING
# =========================================================

@app.route(
    "/admin/request/<int:request_id>/finding",
    methods=["POST"],
)
@admin_required
def add_finding(request_id):

    req =
        get_request(
            request_id
        )


    if not req:
        return "Request not found", 404


    code =
        request.form.get(
            "code",
            "",
        ).strip()


    title =
        request.form.get(
            "title",
            "",
        ).strip()


    severity =
        request.form.get(
            "severity",
            "INFO",
        ).strip().upper()


    evidence =
        request.form.get(
            "evidence",
            "",
        ).strip()


    impact =
        request.form.get(
            "impact",
            "",
        ).strip()


    recommendation =
        request.form.get(
            "recommendation",
            "",
        ).strip()


    if severity not in {
        "INFO",
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    }:

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
            INSERT INTO findings (
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

    req =
        get_request(
            request_id
        )


    if not req:
        return "Request not found", 404


    conn = db()


    findings =
        conn.execute(
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

<strong>Request:</strong>
#%s
<br>

<strong>Client:</strong>
%s
<br>

<strong>Email:</strong>
%s
<br>

<strong>Target:</strong>
%s
<br>

<strong>Resolved IP:</strong>
%s
<br>

<strong>Status:</strong>
%s
<br>

<strong>Created:</strong>
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
# CLIENT MESSAGE API
# =========================================================

@app.route(
    "/api/client/<int:request_id>/messages"
)
def client_messages_api(request_id):

    conn = db()


    rows =
        conn.execute(
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
        "messages":
            [
                dict(row)
                for row in rows
            ]
    })


# =========================================================
# ADMIN MESSAGE API
# =========================================================

@app.route(
    "/api/admin/request/<int:request_id>/messages"
)
@admin_required
def admin_messages_api(request_id):

    conn = db()


    rows =
        conn.execute(
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
        "messages":
            [
                dict(row)
                for row in rows
            ]
    })


# =========================================================
# FAVICON
# =========================================================

@app.route(
    "/favicon.ico"
)
def favicon():

    return "", 204


# =========================================================
# ERROR HANDLERS
# =========================================================

@app.errorhandler(404)
def not_found(error):

    return page(
        "404",
        """
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
""",
    ), 404


@app.errorhandler(500)
def server_error(error):

    return page(
        "500",
        """
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
""",
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


    print("=" * 62)

    print(
        "        MATIA // SECURITY CHECK"
    )

    print("=" * 62)

    print(
        " Status : ONLINE"
    )

    print(
        " Host   : 0.0.0.0"
    )

    print(
        " Port   :",
        port,
    )

    print(
        " Admin  : Private Login"
    )

    print(
        " Admins :"
    )

    print(
        "   - kleimatia1@gmail.com"
    )

    print(
        "   - vantyx199@gmail.com"
    )

    print("=" * 62)


    app.run(
        host="0.0.0.0",
        port=port,
        debug=False,
    )

