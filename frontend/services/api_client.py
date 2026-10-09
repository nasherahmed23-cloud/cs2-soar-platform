import os
import requests


SOAR_API_URL = os.environ.get("SOAR_API_URL", "").rstrip("/")


class APIClientError(Exception):
    """Raised when communication with the SOAR API fails."""
    pass


def login_user(email, password):
    """
    Authenticate a user through the existing SOAR API.

    Endpoint: POST /login

    Returns:
        {
            "status": "success",
            "token": "...",
            "user": {
                "user_id": 1,
                "email": "...",
                "role": "admin",
                "employee_identifier": "..."
            }
        }
    """

    if not SOAR_API_URL:
        raise APIClientError("SOAR API URL is not configured.")

    url = f"{SOAR_API_URL}/login"

    payload = {
        "email": email,
        "password": password
    }

    try:
        response = requests.post(
            url,
            json=payload,
            timeout=10
        )

    except requests.exceptions.RequestException:
        raise APIClientError(
            "Unable to connect to the SOAR authentication service."
        )

    # Incorrect credentials
    if response.status_code == 401:
        raise APIClientError("Invalid email or password.")

    # Invalid request
    if response.status_code == 400:
        raise APIClientError(
            "Please provide a valid email and password."
        )

    # Unexpected API response
    if not response.ok:
        raise APIClientError(
            "Authentication service is temporarily unavailable."
        )

    try:
        data = response.json()

    except ValueError:
        raise APIClientError(
            "Authentication service returned an invalid response."
        )

    if (
        data.get("status") != "success"
        or not data.get("token")
        or not isinstance(data.get("user"), dict)
        or data["user"].get("role") not in ("admin", "employee")
    ):
        raise APIClientError(
            "Authentication service returned incomplete user information."
        )

    return data
# ==========================================
# AUTHENTICATED API REQUESTS
# ==========================================

def get_protected_data(endpoint, token):
    """
    Retrieve data from a protected SOAR API endpoint
    using the JWT obtained during login.
    """

    if not SOAR_API_URL:
        raise APIClientError("SOAR API URL is not configured.")

    if not token:
        raise APIClientError("Authentication token is missing.")

    url = f"{SOAR_API_URL}/{endpoint.lstrip('/')}"

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json"
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=10
        )

    except requests.exceptions.RequestException:
        raise APIClientError(
            "Unable to connect to the SOAR API."
        )

    # Authentication failure
    if response.status_code == 401:
        raise APIClientError(
            "Authentication expired or invalid."
        )

    # Insufficient permissions
    if response.status_code == 403:
        raise APIClientError(
            "You do not have permission to access this resource."
        )

    # Other API errors
    if not response.ok:
        raise APIClientError(
            "Unable to retrieve security information."
        )

    try:
        return response.json()

    except ValueError:
        raise APIClientError(
            "The SOAR API returned an invalid response."
        )


# ==========================================
# SECURITY EVENTS
# ==========================================

def get_events(token):
    """
    Retrieve security events.

    Admin: All available events.
    Employee: Events belonging to their workstation.
    """

    data = get_protected_data("events", token)

    return data.get("events", [])


# ==========================================
# INCIDENTS
# ==========================================

def get_incidents(token):
    """
    Retrieve security incidents.

    Administrator access only.
    """

    data = get_protected_data("incidents", token)

    return data.get("incidents", [])


# ==========================================
# NOTIFICATIONS
# ==========================================

def get_notifications(token):
    """
    Retrieve security notifications.

    Admin: All available notifications.
    Employee: Notifications related to their workstation.
    """

    data = get_protected_data("notifications", token)

    return data.get("notifications", [])