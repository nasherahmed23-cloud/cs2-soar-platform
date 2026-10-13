# ==========================================
# INNOVATECH SOAR - FLASK FRONTEND
# ==========================================

# ==========================================
# DEPENDENCIES
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


# ==========================================
# FLASK APPLICATION
# ==========================================

app = Flask(__name__)

secret_key = os.environ.get("FLASK_SECRET_KEY")

if not secret_key:
    raise RuntimeError(
        "FLASK_SECRET_KEY is not configured."
    )

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

    # Local development uses HTTP.
    # Enable this when deploying behind HTTPS.
    SESSION_COOKIE_SECURE=False,

    PERMANENT_SESSION_LIFETIME=timedelta(hours=1)
)

# Initialize server-side sessions
Session(app)

# Enable CSRF protection for form submissions
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

            # Check authentication
            if not user or not token:

                session.clear()

                return redirect(
                    url_for("login")
                )

            # Check session expiration
            if time.time() >= expires_at:

                session.clear()

                return redirect(
                    url_for("login")
                )

            # Check role-based permissions
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

# FIX:
# Both / and /login now accept GET and POST.
# This prevents the 405 Method Not Allowed error.

@app.route("/", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def login():

    # Redirect users with an existing valid session
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

        # Remove expired or invalid sessions
        session.clear()

    error = None

    # Process login submission
    if request.method == "POST":

        email = request.form.get(
            "email", ""
        ).strip()

        password = request.form.get(
            "password", ""
        )

        if not email or not password:

            error = (
                "Email and password are required."
            )

        else:

            try:

                # Authenticate against the SOAR API
                result = login_user(
                    email,
                    password
                )

                user = result["user"]
                token = result["token"]

                role = user.get("role")

                # Validate supported roles
                if role not in ("admin", "employee"):

                    raise APIClientError(
                        "Unauthorized user role."
                    )

                # Clear any previous session
                session.clear()

                # Store authenticated account information
                session["user"] = user
                session["token"] = token

                # JWT currently expires after one hour
                session["expires_at"] = (
                    time.time() + 3600
                )

                # Administrator redirect
                if role == "admin":

                    return redirect(
                        url_for("admin_dashboard")
                    )

                # Employee redirect
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
# ADMINISTRATOR - DASHBOARD
# ==========================================

@app.route("/admin/dashboard")
@login_required(role="admin")
def admin_dashboard():

    token = session["token"]

    events = []
    incidents = []
    notifications = []

    api_errors = []

    # Retrieve security events
    try:

        events = get_events(token)

    except APIClientError as error:

        api_errors.append(
            f"Events: {error}"
        )

    # Retrieve security incidents
    try:

        incidents = get_incidents(token)

    except APIClientError as error:

        api_errors.append(
            f"Incidents: {error}"
        )

    # Retrieve security notifications
    try:

        notifications = get_notifications(token)

    except APIClientError as error:

        api_errors.append(
            f"Notifications: {error}"
        )

    # Calculate statistics from retrieved records
    dashboard_stats = {

        "total_events": len(events),

        "high_severity_events": sum(
            1
            for event in events
            if str(
                event.get("severity", "")
            ).lower() in ("high", "critical")
        ),

        "total_incidents": len(incidents),

        "open_incidents": sum(
            1
            for incident in incidents
            if str(
                incident.get("status", "")
            ).lower() == "open"
        ),

        "total_notifications": len(notifications)
    }

    return render_template(

        "admin/dashboard.html",

        user=session["user"],
        active_page="dashboard",

        stats=dashboard_stats,

        events=events[:10],
        incidents=incidents[:10],
        notifications=notifications[:5],

        api_errors=api_errors
    )


# ==========================================
# ADMINISTRATOR - SECURITY EVENTS
# ==========================================

@app.route("/admin/events")
@login_required(role="admin")
def admin_events():

    events = []
    api_error = None

    try:

        events = get_events(
            session["token"]
        )

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

    incidents = []
    api_error = None

    try:

        incidents = get_incidents(
            session["token"]
        )

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

    notifications = []
    api_error = None

    try:

        notifications = get_notifications(
            session["token"]
        )

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
# EMPLOYEE - DASHBOARD
# ==========================================

@app.route("/employee/dashboard")
@login_required(role="employee")
def employee_dashboard():

    token = session["token"]

    events = []
    notifications = []

    api_errors = []

    # Retrieve employee-authorized events
    try:

        events = get_events(token)

    except APIClientError as error:

        api_errors.append(
            f"Events: {error}"
        )

    # Retrieve employee-authorized notifications
    try:

        notifications = get_notifications(token)

    except APIClientError as error:

        api_errors.append(
            f"Notifications: {error}"
        )

    # Calculate employee dashboard statistics
    stats = {

        "total_events": len(events),

        "high_severity_events": sum(
            1
            for event in events
            if str(
                event.get("severity", "")
            ).lower() in ("high", "critical")
        ),

        "total_notifications": len(notifications),

        "unread_notifications": sum(
            1
            for notification in notifications
            if str(
                notification.get("status", "")
            ).lower() == "unread"
        )
    }

    return render_template(

        "employee/dashboard.html",

        user=session["user"],
        active_page="dashboard",

        events=events[:10],
        notifications=notifications[:10],

        stats=stats,
        api_errors=api_errors
    )


# ==========================================
# EMPLOYEE - MY SECURITY ALERTS
# ==========================================

@app.route("/employee/alerts")
@login_required(role="employee")
def employee_alerts():

    notifications = []
    api_error = None

    try:

        notifications = get_notifications(
            session["token"]
        )

    except APIClientError as error:

        api_error = str(error)

    return render_template(

        "employee/alerts.html",

        user=session["user"],
        active_page="alerts",

        notifications=notifications,
        api_error=api_error
    )


# ==========================================
# EMPLOYEE - PROFILE
# ==========================================

@app.route("/employee/profile")
@login_required(role="employee")
def employee_profile():

    return render_template(

        "employee/profile.html",

        user=session["user"],
        active_page="profile"
    )


# ==========================================
# LOGOUT
# ==========================================

@app.route("/logout", methods=["POST"])
@login_required()
def logout():

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