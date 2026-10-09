import json
import boto3
import pymysql
import hashlib
import hmac
import time
import jwt


ssm = boto3.client("ssm")

JWT_SECRET_PARAMETER = "/innovatech/soar/auth/jwt_secret"

DB_PARAMETER_NAMES = [
    "/innovatech/soar/db/host",
    "/innovatech/soar/db/name",
    "/innovatech/soar/db/password",
    "/innovatech/soar/db/port",
    "/innovatech/soar/db/user"
]

REQUIRED_FIELDS = [
    "event_type",
    "source",
    "source_ip",
    "severity",
    "timestamp",
    "message"
]


def create_notification(
    connection,
    event_id,
    incident_id,
    event_data,
    rule_name
):
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

        title = "Suspicious Failed Login"

        message = (
            f"Rule {rule_name} matched for "
            f"{event_data['source']} "
            f"from IP {event_data['source_ip']}."
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


def create_incident(connection, event_id, event_data, rule_name):
    with connection.cursor() as cursor:
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
                rule_name,
                event_data["severity"]
            )
        )

        incident_id = cursor.lastrowid

    return incident_id


def evaluate_rules(event_data):
    if (
        event_data["event_type"] == "failed_login"
        and event_data["severity"].lower() == "high"
    ):
        return {
            "matched": True,
            "rule_name": "suspicious_failed_login"
        }

    return {
        "matched": False,
        "rule_name": None
    }


def get_events(connection):
    with connection.cursor(pymysql.cursors.DictCursor) as cursor:
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


def get_employee_events(connection, employee_identifier):
    with connection.cursor(pymysql.cursors.DictCursor) as cursor:
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


def get_incidents(connection):
    with connection.cursor(pymysql.cursors.DictCursor) as cursor:
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


def get_notifications(connection):
    with connection.cursor(pymysql.cursors.DictCursor) as cursor:
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
    with connection.cursor(pymysql.cursors.DictCursor) as cursor:
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


def serialize_rows(rows):
    for row in rows:
        for key, value in row.items():
            if hasattr(value, "isoformat"):
                row[key] = value.isoformat()

    return rows


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

    except (ValueError, TypeError):
        return False


def get_user_by_email(connection, email):
    with connection.cursor(pymysql.cursors.DictCursor) as cursor:
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
        return None, {
            "statusCode": 401,
            "headers": {
                "Content-Type": "application/json"
            },
            "body": json.dumps({
                "status": "error",
                "message": "Authorization token required"
            })
        }

    if not authorization_header.startswith("Bearer "):
        return None, {
            "statusCode": 401,
            "headers": {
                "Content-Type": "application/json"
            },
            "body": json.dumps({
                "status": "error",
                "message": "Invalid authorization header"
            })
        }

    token = authorization_header.split(" ", 1)[1].strip()

    if not token:
        return None, {
            "statusCode": 401,
            "headers": {
                "Content-Type": "application/json"
            },
            "body": json.dumps({
                "status": "error",
                "message": "Authorization token required"
            })
        }

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
        return None, {
            "statusCode": 401,
            "headers": {
                "Content-Type": "application/json"
            },
            "body": json.dumps({
                "status": "error",
                "message": "Token expired"
            })
        }

    except jwt.InvalidTokenError:
        return None, {
            "statusCode": 401,
            "headers": {
                "Content-Type": "application/json"
            },
            "body": json.dumps({
                "status": "error",
                "message": "Invalid token"
            })
        }

    except Exception as error:
        print(f"Failed to validate JWT: {error}")

        return None, {
            "statusCode": 500,
            "headers": {
                "Content-Type": "application/json"
            },
            "body": json.dumps({
                "status": "error",
                "message": "Authentication service error"
            })
        }


def lambda_handler(event, context):

    route_key = event.get("routeKey")

    # -------------------------------------------------
    # Retrieve database configuration
    # -------------------------------------------------

    try:
        response = ssm.get_parameters(
            Names=DB_PARAMETER_NAMES,
            WithDecryption=True
        )

        parameters = {
            parameter["Name"]: parameter["Value"]
            for parameter in response["Parameters"]
        }

        print(
            f"Database parameters retrieved: "
            f"{len(parameters)}"
        )

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
            f"Failed to retrieve database parameters: "
            f"{error}"
        )

        return {
            "statusCode": 500,
            "headers": {
                "Content-Type": "application/json"
            },
            "body": json.dumps({
                "status": "error",
                "message": (
                    "Failed to retrieve "
                    "database configuration"
                )
            })
        }

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
            connect_timeout=5
        )

        # -------------------------------------------------
        # POST /login
        # Public route
        # -------------------------------------------------

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
                return {
                    "statusCode": 400,
                    "headers": {
                        "Content-Type":
                            "application/json"
                    },
                    "body": json.dumps({
                        "status": "error",
                        "message":
                            "Invalid login request"
                    })
                }

            email = login_body.get("email")
            password = login_body.get("password")

            if not email or not password:
                return {
                    "statusCode": 400,
                    "headers": {
                        "Content-Type":
                            "application/json"
                    },
                    "body": json.dumps({
                        "status": "error",
                        "message": (
                            "Email and password "
                            "are required"
                        )
                    })
                }

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
                return {
                    "statusCode": 401,
                    "headers": {
                        "Content-Type":
                            "application/json"
                    },
                    "body": json.dumps({
                        "status": "error",
                        "message": (
                            "Invalid email or password"
                        )
                    })
                }

            secret_response = ssm.get_parameter(
                Name=JWT_SECRET_PARAMETER,
                WithDecryption=True
            )

            jwt_secret = (
                secret_response[
                    "Parameter"
                ]["Value"]
            )

            token = create_jwt(
                user,
                jwt_secret
            )

            print(
                f"Successful login for user ID: "
                f"{user['user_id']}"
            )

            return {
                "statusCode": 200,
                "headers": {
                    "Content-Type":
                        "application/json"
                },
                "body": json.dumps({
                    "status": "success",
                    "token": token,
                    "user": {
                        "user_id":
                            user["user_id"],
                        "email":
                            user["email"],
                        "role":
                            user["role"],
                        "employee_identifier":
                            user[
                                "employee_identifier"
                            ]
                    }
                })
            }

        # -------------------------------------------------
        # JWT protection
        # -------------------------------------------------

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
                f"user ID: "
                f"{authenticated_user['sub']} "
                f"with role: "
                f"{authenticated_user['role']}"
            )

        # -------------------------------------------------
        # GET /events
        # Admin: all events
        # Employee: own workstation only
        # -------------------------------------------------

        if route_key == "GET /events":

            role = authenticated_user.get("role")

            if role == "admin":
                events = get_events(
                    connection
                )

            elif role == "employee":
                employee_identifier = (
                    authenticated_user.get(
                        "employee_identifier"
                    )
                )

                if not employee_identifier:
                    return {
                        "statusCode": 403,
                        "headers": {
                            "Content-Type":
                                "application/json"
                        },
                        "body": json.dumps({
                            "status": "error",
                            "message": (
                                "Employee identifier "
                                "not assigned"
                            )
                        })
                    }

                events = get_employee_events(
                    connection,
                    employee_identifier
                )

            else:
                return {
                    "statusCode": 403,
                    "headers": {
                        "Content-Type":
                            "application/json"
                    },
                    "body": json.dumps({
                        "status": "error",
                        "message": "Access denied"
                    })
                }

            events = serialize_rows(events)

            return {
                "statusCode": 200,
                "headers": {
                    "Content-Type":
                        "application/json"
                },
                "body": json.dumps({
                    "events": events
                })
            }

        # -------------------------------------------------
        # GET /incidents
        # Admin only
        # -------------------------------------------------

        if route_key == "GET /incidents":

            if (
                authenticated_user.get("role")
                != "admin"
            ):
                return {
                    "statusCode": 403,
                    "headers": {
                        "Content-Type":
                            "application/json"
                    },
                    "body": json.dumps({
                        "status": "error",
                        "message": (
                            "Administrator "
                            "access required"
                        )
                    })
                }

            incidents = get_incidents(
                connection
            )

            incidents = serialize_rows(
                incidents
            )

            return {
                "statusCode": 200,
                "headers": {
                    "Content-Type":
                        "application/json"
                },
                "body": json.dumps({
                    "incidents": incidents
                })
            }

        # -------------------------------------------------
        # GET /notifications
        # Admin: all notifications
        # Employee: own workstation only
        # -------------------------------------------------

        if route_key == "GET /notifications":

            role = authenticated_user.get("role")

            if role == "admin":
                notifications = (
                    get_notifications(
                        connection
                    )
                )

            elif role == "employee":
                employee_identifier = (
                    authenticated_user.get(
                        "employee_identifier"
                    )
                )

                if not employee_identifier:
                    return {
                        "statusCode": 403,
                        "headers": {
                            "Content-Type":
                                "application/json"
                        },
                        "body": json.dumps({
                            "status": "error",
                            "message": (
                                "Employee identifier "
                                "not assigned"
                            )
                        })
                    }

                notifications = (
                    get_employee_notifications(
                        connection,
                        employee_identifier
                    )
                )

            else:
                return {
                    "statusCode": 403,
                    "headers": {
                        "Content-Type":
                            "application/json"
                    },
                    "body": json.dumps({
                        "status": "error",
                        "message": "Access denied"
                    })
                }

            notifications = serialize_rows(
                notifications
            )

            return {
                "statusCode": 200,
                "headers": {
                    "Content-Type":
                        "application/json"
                },
                "body": json.dumps({
                    "notifications":
                        notifications
                })
            }

        # -------------------------------------------------
        # POST /events
        # Public ingestion route for now
        # -------------------------------------------------

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
                return {
                    "statusCode": 400,
                    "headers": {
                        "Content-Type":
                            "application/json"
                    },
                    "body": json.dumps({
                        "status": "error",
                        "message": (
                            "Invalid JSON "
                            "request body"
                        )
                    })
                }

            missing_fields = [
                field
                for field in REQUIRED_FIELDS
                if field not in body
            ]

            if missing_fields:
                return {
                    "statusCode": 400,
                    "headers": {
                        "Content-Type":
                            "application/json"
                    },
                    "body": json.dumps({
                        "status": "error",
                        "message": (
                            "Missing required fields"
                        ),
                        "missing_fields":
                            missing_fields
                    })
                }

            incident_id = None
            notification_id = None

            # Store security event
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
                    VALUES (
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s
                    )
                """

                cursor.execute(
                    sql,
                    (
                        body["event_type"],
                        body["source"],
                        body["source_ip"],
                        body["severity"],
                        body["timestamp"]
                        .replace("T", " ")
                        .replace("Z", ""),
                        body["message"]
                    )
                )

                event_id = (
                    cursor.lastrowid
                )

            connection.commit()

            print(
                f"Security event stored "
                f"successfully. "
                f"Event ID: {event_id}"
            )

            # -------------------------------------------------
            # Evaluate SOAR rules
            # -------------------------------------------------

            rule_result = evaluate_rules(
                body
            )

            if rule_result["matched"]:

                print(
                    f"Rule matched: "
                    f"{rule_result['rule_name']} "
                    f"for event ID: "
                    f"{event_id}"
                )

                # Automated response 1:
                # Create incident
                incident_id = (
                    create_incident(
                        connection,
                        event_id,
                        body,
                        rule_result[
                            "rule_name"
                        ]
                    )
                )

                # Automated response 2:
                # Create notification
                notification_id = (
                    create_notification(
                        connection,
                        event_id,
                        incident_id,
                        body,
                        rule_result[
                            "rule_name"
                        ]
                    )
                )

                connection.commit()

                print(
                    f"Automated responses "
                    f"executed: "
                    f"Incident {incident_id} "
                    f"created, "
                    f"Notification "
                    f"{notification_id} created"
                )

            else:
                print(
                    f"No rule matched for "
                    f"event ID: {event_id}"
                )

            print(
                "Validated security event:"
            )

            print(
                json.dumps(body)
            )

            return {
                "statusCode": 200,
                "headers": {
                    "Content-Type":
                        "application/json"
                },
                "body": json.dumps({
                    "status": "processed",
                    "message": (
                        "Security event "
                        "processed successfully"
                    ),
                    "event_id":
                        event_id,
                    "rule_matched":
                        rule_result["matched"],
                    "rule_name":
                        rule_result["rule_name"],
                    "incident_id":
                        incident_id,
                    "notification_id":
                        notification_id
                })
            }

        # -------------------------------------------------
        # Unknown route
        # -------------------------------------------------

        return {
            "statusCode": 404,
            "headers": {
                "Content-Type":
                    "application/json"
            },
            "body": json.dumps({
                "status": "error",
                "message": "Route not found"
            })
        }

    except Exception as error:
        print(
            f"Failed to process request: "
            f"{error}"
        )

        return {
            "statusCode": 500,
            "headers": {
                "Content-Type":
                    "application/json"
            },
            "body": json.dumps({
                "status": "error",
                "message":
                    "Failed to process request"
            })
        }

    finally:
        if connection:
            connection.close()