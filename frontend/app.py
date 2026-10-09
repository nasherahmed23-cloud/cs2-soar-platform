# ==========================================
# INNOVATECH SOAR - FLASK FRONTEND
# ==========================================

import os
import time

from datetime import timedelta
from functools import wraps

from dotenv import load_dotenv

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session
)

from flask_session import Session
from flask_wtf.csrf import CSRFProtect
from cachelib import FileSystemCache


# ==========================================
# ENVIRONMENT CONFIGURATION
# ==========================================

load_dotenv()

from services.api_client import (
    login_user,
    get_events,
    get_incidents,
    get_notifications,
    APIClientError
)


app = Flask(__name__)

secret_key = os.environ.get("FLASK_SECRET_KEY")

if not secret_key:
    raise RuntimeError("FLASK_SECRET_KEY is not configured.")

app.config["SECRET_KEY"] = secret_key


# ==========================================
# SESSION CONFIGURATION
# ==========================================

app.config.update(
    SESSION_TYPE="cachelib",

    SESSION_CACHELIB=FileSystemCache(
        cache_dir=os.path.join(
            app.instance_path,
            "sessions"
        ),
        threshold=500
    ),

    SESSION_PERMANENT=False,
    SESSION_USE_SIGNER=True,

    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",

    # False for local HTTP development
    # Set to True when deploying with HTTPS
    SESSION_COOKIE_SECURE=False,

    PERMANENT_SESSION_LIFETIME=timedelta(hours=1)
)

Session(app)

csrf = CSRFProtect(app)


# ==========================================
# AUTHENTICATION DECORATOR
# ==========================================

def login_required(role=None):

    def decorator(function):

        @wraps(function)
        def wrapper(*args, **kwargs):

            user = session.get("user")
            token = session.get("token")
            expires_at = session.get("expires_at", 0)

            # Check authentication session
            if not user or not token:

                session.clear()

                return redirect(url_for("login"))

            # Check session expiration
            if time.time() >= expires_at:

                session.clear()

                return redirect(url_for("login"))

            # Check role-based access permissions
            if role and user.get("role") != role:

                return render_template(
                    "403.html"
                ), 403

            return function(*args, **kwargs)

        return wrapper

    return decorator


# ==========================================
# LOGIN PAGE
# ==========================================

@app.route("/", methods=["GET"])
@app.route("/login", methods=["GET", "POST"])
def login():

    # Redirect authenticated users
    if request.method == "GET" and session.get("user"):

        if (
            session.get("token")
            and time.time() < session.get("expires_at", 0)
        ):

            role = session["user"].get("role")

            if role == "admin":

                return redirect(
                    url_for("admin_dashboard")
                )

            if role == "employee":

                return redirect(
                    url_for("employee_dashboard")
                )

        session.clear()

    error = None

    # Process login form
    if request.method == "POST":

        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        # Validate login fields
        if not email or not password:

            error = "Email and password are required."

        else:

            try:

                # Authenticate through AWS API Gateway
                result = login_user(
                    email,
                    password
                )

                user = result["user"]
                token = result["token"]

                role = user.get("role")

                # Validate returned role
                if role not in ("admin", "employee"):

                    raise APIClientError(
                        "Unauthorized user role."
                    )

                # Clear previous session
                session.clear()

                # Store authentication data
                # in server-side session storage
                session["user"] = user
                session["token"] = token

                # Lambda JWT validity: 3600 seconds
                session["expires_at"] = time.time() + 3600

                # Administrator redirection
                if role == "admin":

                    return redirect(
                        url_for("admin_dashboard")
                    )

                # Employee redirection
                if role == "employee":

                    return redirect(
                        url_for("employee_dashboard")
                    )

            except APIClientError as error_message:

                error = str(error_message)

    return render_template(
        "login.html",
        error=error
    )


# ==========================================
# ADMINISTRATOR DASHBOARD
# ==========================================

@app.route("/admin/dashboard")
@login_required(role="admin")
def admin_dashboard():

    # JWT stored during authentication
    token = session["token"]

    # Initialize API datasets
    events = []
    incidents = []
    notifications = []

    # Store API errors for display
    api_errors = []

    # ======================================
    # RETRIEVE SECURITY EVENTS
    # ======================================

    try:

        events = get_events(token)

    except APIClientError as error:

        api_errors.append(
            f"Events: {error}"
        )

    # ======================================
    # RETRIEVE SECURITY INCIDENTS
    # ======================================

    try:

        incidents = get_incidents(token)

    except APIClientError as error:

        api_errors.append(
            f"Incidents: {error}"
        )

    # ======================================
    # RETRIEVE NOTIFICATIONS
    # ======================================

    try:

        notifications = get_notifications(token)

    except APIClientError as error:

        api_errors.append(
            f"Notifications: {error}"
        )

    # ======================================
    # CALCULATE DASHBOARD STATISTICS
    # ======================================

    # Total retrieved security events
    total_events = len(events)

    # Events classified as high or critical
    high_severity_events = sum(
        1
        for event in events
        if str(
            event.get("severity", "")
        ).lower() in ("high", "critical")
    )

    # Total retrieved incidents
    total_incidents = len(incidents)

    # Incidents with open status
    open_incidents = sum(
        1
        for incident in incidents
        if str(
            incident.get("status", "")
        ).lower() == "open"
    )

    # Total retrieved notifications
    total_notifications = len(notifications)

    # ======================================
    # DASHBOARD STATISTICS
    # ======================================

    dashboard_stats = {
        "total_events": total_events,
        "high_severity_events": high_severity_events,
        "total_incidents": total_incidents,
        "open_incidents": open_incidents,
        "total_notifications": total_notifications
    }

    # ======================================
    # RENDER ADMINISTRATOR DASHBOARD
    # ======================================

    return render_template(
        "admin/dashboard.html",

        user=session["user"],
        active_page="dashboard",

        stats=dashboard_stats,

        # Recent security events
        events=events[:10],

        # Recent security incidents
        incidents=incidents[:10],

        # Recent notifications
        notifications=notifications[:5],

        # API error messages
        api_errors=api_errors
    )

# ==========================================
# ADMINISTRATOR - SECURITY EVENTS
# ==========================================

@app.route("/admin/events")
@login_required(role="admin")
def admin_events():

    token = session["token"]

    events = []
    api_error = None

    # Retrieve security events from AWS API Gateway
    try:
        events = get_events(token)

    except APIClientError as error:
        api_error = str(error)

    return render_template(
        "admin/events.html",
        user=session["user"],
        active_page="events",
        events=events,
        api_error=api_error
    )

# ==========================================
# ADMINISTRATOR - SECURITY INCIDENTS
# ==========================================

@app.route("/admin/incidents")
@login_required(role="admin")
def admin_incidents():

    token = session["token"]

    incidents = []
    api_error = None

    # Retrieve incidents from AWS API Gateway
    try:
        incidents = get_incidents(token)

    except APIClientError as error:
        api_error = str(error)

    return render_template(
        "admin/incidents.html",
        user=session["user"],
        active_page="incidents",
        incidents=incidents,
        api_error=api_error
    )

# ==========================================
# ADMINISTRATOR - SECURITY NOTIFICATIONS
# ==========================================

@app.route("/admin/notifications")
@login_required(role="admin")
def admin_notifications():

    token = session["token"]

    notifications = []
    api_error = None

    # Retrieve notifications from AWS API Gateway
    try:
        notifications = get_notifications(token)

    except APIClientError as error:
        api_error = str(error)

    return render_template(
        "admin/notifications.html",
        user=session["user"],
        active_page="notifications",
        notifications=notifications,
        api_error=api_error
    )

# ==========================================
# EMPLOYEE DASHBOARD
# ==========================================

@app.route("/employee/dashboard")
@login_required(role="employee")
def employee_dashboard():

    return render_template(
        "employee/dashboard.html",
        user=session["user"]
    )


# ==========================================
# LOGOUT
# ==========================================

@app.route("/logout", methods=["POST"])
@login_required()
def logout():

    # Clear server-side authentication session
    session.clear()

    return redirect(
        url_for("login")
    )


# ==========================================
# RUN FLASK APPLICATION
# ==========================================

if __name__ == "__main__":

    app.run(
        debug=True,
        port=5000
    )