# =========================================================
# INNOVATECH SOAR - EVENT COLLECTOR
# =========================================================

import json
import boto3
import pymysql
import hashlib
import hmac
import time
import jwt
from datetime import datetime, timezone


# =========================================================
# AWS CONFIGURATION
# =========================================================

ssm = boto3.client("ssm")

JWT_SECRET_PARAMETER = "/innovatech/soar/auth/jwt_secret"

DB_PARAMETER_NAMES = [
    "/innovatech/soar/db/host",
    "/innovatech/soar/db/name",
    "/innovatech/soar/db/password",
    "/innovatech/soar/db/port",
    "/innovatech/soar/db/user"
]


# =========================================================
# SECURITY EVENT CONFIGURATION
# =========================================================

REQUIRED_FIELDS = [
    "event_type",
    "source",
    "source_ip",
    "severity",
    "timestamp",
    "message"
]


# =========================================================
# CENTRALIZED DETECTION RULES
# =========================================================

DETECTION_RULES = [
    {
        "name": "suspicious_failed_login",
        "event_type": "failed_login",
        "severity": "high",
        "title": "Suspicious Failed Login"
    },
    {
        "name" : "unauthorized_access",
        "event_type" : "access_denied",
        "severity" : "high",
        "title" : "Unauthorized Access Detected"
    }
]


# =========================================================
# API RESPONSE HELPER
# =========================================================

def api_response(status_code, data):
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json"
        },
        "body": json.dumps(data)
    }


# =========================================================
# DETECTION ENGINE
# =========================================================

def evaluate_rules(event_data):

    matched_rules = []

    for rule in DETECTION_RULES:

        if (
            event_data["event_type"] == rule["event_type"]
            and event_data["severity"].lower() == rule["severity"]
        ):

            matched_rules.append(rule["name"])

    return {
        "matched": len(matched_rules) > 0,
        "matched_rules": matched_rules
    }


# =========================================================
# INCIDENT MANAGEMENT
# =========================================================

def create_incident(
    connection,
    event_id,
    event_data,
    matched_rules
):

    if not matched_rules:
        raise ValueError(
            "Cannot create incident without matched rules"
        )

    primary_rule = matched_rules[0]

    with connection.cursor() as cursor:

        # Create ONE consolidated incident

        sql = """
            INSERT INTO incidents
            (
                event_id,
                rule_name,
                severity
            )
            VALUES (%s, %s, %s)
        """

        cursor.execute(
            sql,
            (
                event_id,
                primary_rule,
                event_data["severity"]
            )
        )

        incident_id = cursor.lastrowid

        # Associate ALL matched rules with the incident

        sql_rules = """
            INSERT INTO incident_rules
            (
                incident_id,
                rule_name
            )
            VALUES (%s, %s)
        """

        for rule_name in matched_rules:

            cursor.execute(
                sql_rules,
                (
                    incident_id,
                    rule_name
                )
            )

    return incident_id


# =========================================================
# NOTIFICATION MANAGEMENT
# =========================================================

def create_notification(
    connection,
    event_id,
    incident_id,
    event_data,
    matched_rules
):

    if not matched_rules:
        raise ValueError(
            "Cannot create notification without matched rules"
        )

    with connection.cursor() as cursor:

        sql = """
            INSERT INTO notifications
            (
                event_id,
                incident_id,
                title,
                message,
                severity
            )
            VALUES (%s, %s, %s, %s, %s)
        """

        # Identify the primary detection rule

        primary_rule = matched_rules[0]

        rule_config = next(
            (
                rule
                for rule in DETECTION_RULES
                if rule["name"] == primary_rule
            ),
            None
        )

        # Generate notification title dynamically

        if len(matched_rules) > 1:

            title = "Multiple Security Rules Triggered"

        elif rule_config:

            title = rule_config["title"]

        else:

            title = "Security Incident Detected"

        # Generate consolidated notification message

        rule_names = ", ".join(matched_rules)

        message = (
            f"Security incident detected for "
            f"{event_data['source']} "
            f"from IP {event_data['source_ip']}. "
            f"Matched rules: {rule_names}."
        )

        cursor.execute(
            sql,
            (
                event_id,
                incident_id,
                title,
                message,
                event_data["severity"]
            )
        )

        notification_id = cursor.lastrowid

    return notification_id


# =========================================================
# SECURITY EVENT STORAGE
# =========================================================

def store_security_event(connection, event_data):

    with connection.cursor() as cursor:

        sql = """
            INSERT INTO security_events
            (
                event_type,
                source,
                source_ip,
                severity,
                event_timestamp,
                message
            )
            VALUES (%s, %s, %s, %s, %s, %s)
        """

        cursor.execute(
            sql,
            (
                event_data["event_type"],
                event_data["source"],
                event_data["source_ip"],
                event_data["severity"],
                event_data["timestamp"],
                event_data["message"]
            )
        )

        event_id = cursor.lastrowid

    return event_id


# =========================================================
# CENTRALIZED EVENT PROCESSOR
# =========================================================

def process_security_event(connection, event_data):

    incident_id = None
    notification_id = None

    try:

        # Validate and normalize the timestamp

        timestamp_value = event_data["timestamp"]

        parsed_timestamp = datetime.fromisoformat(
            timestamp_value.replace("Z", "+00:00")
        )

        if parsed_timestamp.tzinfo is not None:
            parsed_timestamp = parsed_timestamp.astimezone(
                timezone.utc
            )

        normalized_event = event_data.copy()

        normalized_event["timestamp"] = (
            parsed_timestamp.strftime("%Y-%m-%d %H:%M:%S")
        )

        # Start one database transaction for the event

        connection.begin()

        # Step 1: Store incoming security event

        event_id = store_security_event(
            connection,
            normalized_event
        )

        print(
            f"Security event stored. "
            f"Event ID: {event_id}"
        )

        # Step 2: Evaluate ALL detection rules

        rule_result = evaluate_rules(
            event_data
        )

        matched_rules = rule_result["matched_rules"]

        # Step 3: Execute automated responses

        if matched_rules:

            print(
                f"Detection rules matched: "
                f"{matched_rules}"
            )

            # Create ONE consolidated incident

            incident_id = create_incident(
                connection,
                event_id,
                event_data,
                matched_rules
            )

            # Create ONE consolidated notification

            notification_id = create_notification(
                connection,
                event_id,
                incident_id,
                event_data,
                matched_rules
            )

            print(
                f"Incident {incident_id} created. "
                f"Notification {notification_id} created."
            )

        else:

            print(
                f"No detection rules matched "
                f"event ID: {event_id}"
            )

        # Step 4: Commit all changes together

        connection.commit()

        print(
            f"Security event {event_id} "
            f"processed successfully."
        )

        return {
            "status": "processed",
            "message": "Security event processed successfully",
            "event_id": event_id,
            "rule_matched": rule_result["matched"],
            "rule_name": (
                matched_rules[0]
                if matched_rules
                else None
            ),
            "matched_rules": matched_rules,
            "incident_id": incident_id,
            "notification_id": notification_id
        }

    except Exception:

        # Roll back event, incident, rules and notification
        # if any database operation fails

        connection.rollback()

        print(
            "Security event processing failed. "
            "Database transaction rolled back."
        )

        raise


# =========================================================
# SECURITY EVENT RETRIEVAL
# =========================================================

def get_events(connection):

    with connection.cursor(
        pymysql.cursors.DictCursor
    ) as cursor:

        sql = """
            SELECT
                event_id,
                event_type,
                source,
                source_ip,
                severity,
                event_timestamp,
                message,
                status,
                created_at
            FROM security_events
            ORDER BY created_at DESC
            LIMIT 100
        """

        cursor.execute(sql)

        return cursor.fetchall()


def get_employee_events(
    connection,
    employee_identifier
):

    with connection.cursor(
        pymysql.cursors.DictCursor
    ) as cursor:

        sql = """
            SELECT
                event_id,
                event_type,
                source,
                source_ip,
                severity,
                event_timestamp,
                message,
                status,
                created_at
            FROM security_events
            WHERE source = %s
            ORDER BY created_at DESC
            LIMIT 100
        """

        cursor.execute(
            sql,
            (employee_identifier,)
        )

        return cursor.fetchall()


# =========================================================
# INCIDENT RETRIEVAL
# =========================================================

def get_incidents(connection):

    with connection.cursor(
        pymysql.cursors.DictCursor
    ) as cursor:

        sql = """
            SELECT
                incident_id,
                event_id,
                rule_name,
                severity,
                status,
                action_taken,
                created_at
            FROM incidents
            ORDER BY created_at DESC
            LIMIT 100
        """

        cursor.execute(sql)

        return cursor.fetchall()


# =========================================================
# NOTIFICATION RETRIEVAL
# =========================================================

def get_notifications(connection):

    with connection.cursor(
        pymysql.cursors.DictCursor
    ) as cursor:

        sql = """
            SELECT
                notification_id,
                event_id,
                incident_id,
                title,
                message,
                severity,
                status,
                created_at
            FROM notifications
            ORDER BY created_at DESC
            LIMIT 100
        """

        cursor.execute(sql)

        return cursor.fetchall()


def get_employee_notifications(
    connection,
    employee_identifier
):

    with connection.cursor(
        pymysql.cursors.DictCursor
    ) as cursor:

        sql = """
            SELECT
                n.notification_id,
                n.event_id,
                n.incident_id,
                n.title,
                n.message,
                n.severity,
                n.status,
                n.created_at
            FROM notifications n
            INNER JOIN security_events e
                ON n.event_id = e.event_id
            WHERE e.source = %s
            ORDER BY n.created_at DESC
            LIMIT 100
        """

        cursor.execute(
            sql,
            (employee_identifier,)
        )

        return cursor.fetchall()


# =========================================================
# DATABASE SERIALIZATION
# =========================================================

def serialize_rows(rows):

    for row in rows:

        for key, value in row.items():

            if hasattr(value, "isoformat"):

                row[key] = value.isoformat()

    return rows


# =========================================================
# PASSWORD VERIFICATION
# =========================================================

def verify_password(password, stored_hash):

    try:

        algorithm, iterations, salt, expected_hash = (
            stored_hash.split("$")
        )

        if algorithm != "pbkdf2_sha256":
            return False

        calculated_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            salt.encode(),
            int(iterations)
        ).hex()

        return hmac.compare_digest(
            calculated_hash,
            expected_hash
        )

    except (ValueError, TypeError, AttributeError):
        return False


# =========================================================
# USER MANAGEMENT
# =========================================================

def get_user_by_email(connection, email):

    with connection.cursor(
        pymysql.cursors.DictCursor
    ) as cursor:

        sql = """
            SELECT
                user_id,
                email,
                password_hash,
                role,
                employee_identifier
            FROM users
            WHERE email = %s
            LIMIT 1
        """

        cursor.execute(
            sql,
            (email,)
        )

        return cursor.fetchone()


# =========================================================
# JWT AUTHENTICATION
# =========================================================

def create_jwt(user, jwt_secret):

    current_time = int(time.time())

    payload = {
        "sub": str(user["user_id"]),
        "email": user["email"],
        "role": user["role"],
        "employee_identifier": user["employee_identifier"],
        "iat": current_time,
        "exp": current_time + 3600
    }

    return jwt.encode(
        payload,
        jwt_secret,
        algorithm="HS256"
    )


def get_authenticated_user(event):

    headers = event.get("headers") or {}

    authorization_header = (
        headers.get("authorization")
        or headers.get("Authorization")
    )

    if not authorization_header:

        return None, api_response(
            401,
            {
                "status": "error",
                "message": "Authorization token required"
            }
        )

    if not authorization_header.startswith("Bearer "):

        return None, api_response(
            401,
            {
                "status": "error",
                "message": "Invalid authorization header"
            }
        )

    token = authorization_header.split(
        " ", 1
    )[1].strip()

    if not token:

        return None, api_response(
            401,
            {
                "status": "error",
                "message": "Authorization token required"
            }
        )

    try:

        secret_response = ssm.get_parameter(
            Name=JWT_SECRET_PARAMETER,
            WithDecryption=True
        )

        jwt_secret = secret_response["Parameter"]["Value"]

        decoded_token = jwt.decode(
            token,
            jwt_secret,
            algorithms=["HS256"]
        )

        return decoded_token, None

    except jwt.ExpiredSignatureError:

        return None, api_response(
            401,
            {
                "status": "error",
                "message": "Token expired"
            }
        )

    except jwt.InvalidTokenError:

        return None, api_response(
            401,
            {
                "status": "error",
                "message": "Invalid token"
            }
        )

    except Exception as error:

        print(
            f"Failed to validate JWT: {error}"
        )

        return None, api_response(
            500,
            {
                "status": "error",
                "message": "Authentication service error"
            }
        )


# =========================================================
# MAIN AWS LAMBDA HANDLER
# =========================================================

def lambda_handler(event, context):

    route_key = event.get("routeKey")

    # -----------------------------------------------------
    # Retrieve database configuration
    # -----------------------------------------------------

    try:

        response = ssm.get_parameters(
            Names=DB_PARAMETER_NAMES,
            WithDecryption=True
        )

        parameters = {
            parameter["Name"]: parameter["Value"]
            for parameter in response["Parameters"]
        }

        db_host = parameters[
            "/innovatech/soar/db/host"
        ]

        db_port = int(
            parameters[
                "/innovatech/soar/db/port"
            ]
        )

        db_name = parameters[
            "/innovatech/soar/db/name"
        ]

        db_user = parameters[
            "/innovatech/soar/db/user"
        ]

        db_password = parameters[
            "/innovatech/soar/db/password"
        ]

    except Exception as error:

        print(
            f"Database configuration error: {error}"
        )

        return api_response(
            500,
            {
                "status": "error",
                "message": "Failed to retrieve database configuration"
            }
        )

    connection = None

    try:

        # -------------------------------------------------
        # Connect to RDS
        # -------------------------------------------------

        connection = pymysql.connect(
            host=db_host,
            port=db_port,
            user=db_user,
            password=db_password,
            database=db_name,
            connect_timeout=5,
            autocommit=False
        )

        # =================================================
        # POST /login
        # =================================================

        if route_key == "POST /login":

            try:

                login_body = json.loads(
                    event["body"]
                )

            except (
                KeyError,
                TypeError,
                json.JSONDecodeError
            ):

                return api_response(
                    400,
                    {
                        "status": "error",
                        "message": "Invalid login request"
                    }
                )

            if not isinstance(login_body, dict):

                return api_response(
                    400,
                    {
                        "status": "error",
                        "message": "Invalid login request"
                    }
                )

            email = login_body.get("email")
            password = login_body.get("password")

            if not email or not password:

                return api_response(
                    400,
                    {
                        "status": "error",
                        "message": "Email and password are required"
                    }
                )

            user = get_user_by_email(
                connection,
                email
            )

            if (
                not user
                or not verify_password(
                    password,
                    user["password_hash"]
                )
            ):

                return api_response(
                    401,
                    {
                        "status": "error",
                        "message": "Invalid email or password"
                    }
                )

            secret_response = ssm.get_parameter(
                Name=JWT_SECRET_PARAMETER,
                WithDecryption=True
            )

            jwt_secret = secret_response[
                "Parameter"
            ]["Value"]

            token = create_jwt(
                user,
                jwt_secret
            )

            print(
                f"Successful login for user ID: "
                f"{user['user_id']}"
            )

            return api_response(
                200,
                {
                    "status": "success",
                    "token": token,
                    "user": {
                        "user_id": user["user_id"],
                        "email": user["email"],
                        "role": user["role"],
                        "employee_identifier": (
                            user["employee_identifier"]
                        )
                    }
                }
            )

        # =================================================
        # JWT PROTECTION
        # =================================================

        protected_routes = [
            "GET /events",
            "GET /incidents",
            "GET /notifications"
        ]

        authenticated_user = None

        if route_key in protected_routes:

            authenticated_user, auth_error = (
                get_authenticated_user(event)
            )

            if auth_error:
                return auth_error

            print(
                f"Authenticated request from "
                f"user ID: {authenticated_user['sub']} "
                f"with role: {authenticated_user['role']}"
            )

        # =================================================
        # GET /events
        # =================================================

        if route_key == "GET /events":

            role = authenticated_user.get("role")

            if role == "admin":

                events = get_events(connection)

            elif role == "employee":

                employee_identifier = (
                    authenticated_user.get(
                        "employee_identifier"
                    )
                )

                if not employee_identifier:

                    return api_response(
                        403,
                        {
                            "status": "error",
                            "message": "Employee identifier not assigned"
                        }
                    )

                events = get_employee_events(
                    connection,
                    employee_identifier
                )

            else:

                return api_response(
                    403,
                    {
                        "status": "error",
                        "message": "Access denied"
                    }
                )

            events = serialize_rows(events)

            return api_response(
                200,
                {
                    "events": events
                }
            )

        # =================================================
        # GET /incidents
        # =================================================

        if route_key == "GET /incidents":

            if authenticated_user.get("role") != "admin":

                return api_response(
                    403,
                    {
                        "status": "error",
                        "message": "Administrator access required"
                    }
                )

            incidents = get_incidents(
                connection
            )

            incidents = serialize_rows(
                incidents
            )

            return api_response(
                200,
                {
                    "incidents": incidents
                }
            )

        # =================================================
        # GET /notifications
        # =================================================

        if route_key == "GET /notifications":

            role = authenticated_user.get("role")

            if role == "admin":

                notifications = get_notifications(
                    connection
                )

            elif role == "employee":

                employee_identifier = (
                    authenticated_user.get(
                        "employee_identifier"
                    )
                )

                if not employee_identifier:

                    return api_response(
                        403,
                        {
                            "status": "error",
                            "message": "Employee identifier not assigned"
                        }
                    )

                notifications = get_employee_notifications(
                    connection,
                    employee_identifier
                )

            else:

                return api_response(
                    403,
                    {
                        "status": "error",
                        "message": "Access denied"
                    }
                )

            notifications = serialize_rows(
                notifications
            )

            return api_response(
                200,
                {
                    "notifications": notifications
                }
            )

        # =================================================
        # POST /events
        # =================================================

        if route_key == "POST /events":

            try:

                body = json.loads(
                    event["body"]
                )

            except (
                KeyError,
                TypeError,
                json.JSONDecodeError
            ):

                return api_response(
                    400,
                    {
                        "status": "error",
                        "message": "Invalid JSON request body"
                    }
                )

            if not isinstance(body, dict):

                return api_response(
                    400,
                    {
                        "status": "error",
                        "message": "JSON body must be an object"
                    }
                )

            # ---------------------------------------------
            # Validate required event fields
            # ---------------------------------------------

            missing_fields = [
                field
                for field in REQUIRED_FIELDS
                if field not in body
            ]

            if missing_fields:

                return api_response(
                    400,
                    {
                        "status": "error",
                        "message": "Missing required fields",
                        "missing_fields": missing_fields
                    }
                )

            # Validate field values

            for field in REQUIRED_FIELDS:

                if (
                    not isinstance(body[field], str)
                    or not body[field].strip()
                ):

                    return api_response(
                        400,
                        {
                            "status": "error",
                            "message": (
                                f"Invalid value for field: {field}"
                            )
                        }
                    )

            # Normalize severity for rule evaluation

            body["severity"] = (
                body["severity"].strip().lower()
            )

            # Validate timestamp before processing

            try:

                datetime.fromisoformat(
                    body["timestamp"].replace(
                        "Z",
                        "+00:00"
                    )
                )

            except ValueError:

                return api_response(
                    400,
                    {
                        "status": "error",
                        "message": "Invalid event timestamp"
                    }
                )

            # ---------------------------------------------
            # Centralized SOAR processing
            # ---------------------------------------------

            result = process_security_event(
                connection,
                body
            )

            return api_response(
                200,
                result
            )

        # =================================================
        # UNKNOWN ROUTE
        # =================================================

        return api_response(
            404,
            {
                "status": "error",
                "message": "Route not found"
            }
        )

    except Exception as error:

        print(
            f"Failed to process request: {error}"
        )

        if connection:

            try:
                connection.rollback()
            except Exception:
                pass

        return api_response(
            500,
            {
                "status": "error",
                "message": "Failed to process request"
            }
        )

    finally:

        if connection:
            connection.close()
