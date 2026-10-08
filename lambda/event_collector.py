import json
import boto3
import pymysql


ssm = boto3.client("ssm")

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


def serialize_rows(rows):
    for row in rows:
        for key, value in row.items():
            if hasattr(value, "isoformat"):
                row[key] = value.isoformat()

    return rows


def lambda_handler(event, context):

    route_key = event.get("routeKey")

    # Retrieve database configuration from Parameter Store
    try:
        response = ssm.get_parameters(
            Names=DB_PARAMETER_NAMES,
            WithDecryption=True
        )

        parameters = {
            parameter["Name"]: parameter["Value"]
            for parameter in response["Parameters"]
        }

        print(f"Database parameters retrieved: {len(parameters)}")

        db_host = parameters["/innovatech/soar/db/host"]
        db_port = int(parameters["/innovatech/soar/db/port"])
        db_name = parameters["/innovatech/soar/db/name"]
        db_user = parameters["/innovatech/soar/db/user"]
        db_password = parameters["/innovatech/soar/db/password"]

    except Exception as error:
        print(f"Failed to retrieve database parameters: {error}")

        return {
            "statusCode": 500,
            "headers": {
                "Content-Type": "application/json"
            },
            "body": json.dumps({
                "status": "error",
                "message": "Failed to retrieve database configuration"
            })
        }

    connection = None

    try:
        # Connect to RDS
        connection = pymysql.connect(
            host=db_host,
            port=db_port,
            user=db_user,
            password=db_password,
            database=db_name,
            connect_timeout=5
        )

        # GET /events
        if route_key == "GET /events":
            events = get_events(connection)
            events = serialize_rows(events)

            return {
                "statusCode": 200,
                "headers": {
                    "Content-Type": "application/json"
                },
                "body": json.dumps({
                    "events": events
                })
            }

        # GET /incidents
        if route_key == "GET /incidents":
            incidents = get_incidents(connection)
            incidents = serialize_rows(incidents)

            return {
                "statusCode": 200,
                "headers": {
                    "Content-Type": "application/json"
                },
                "body": json.dumps({
                    "incidents": incidents
                })
            }

        # GET /notifications
        if route_key == "GET /notifications":
            notifications = get_notifications(connection)
            notifications = serialize_rows(notifications)

            return {
                "statusCode": 200,
                "headers": {
                    "Content-Type": "application/json"
                },
                "body": json.dumps({
                    "notifications": notifications
                })
            }

        # Only POST /events should continue below
        if route_key != "POST /events":
            return {
                "statusCode": 404,
                "headers": {
                    "Content-Type": "application/json"
                },
                "body": json.dumps({
                    "status": "error",
                    "message": "Route not found"
                })
            }

        # Parse POST request body
        try:
            body = json.loads(event["body"])

        except (KeyError, TypeError, json.JSONDecodeError):
            return {
                "statusCode": 400,
                "headers": {
                    "Content-Type": "application/json"
                },
                "body": json.dumps({
                    "status": "error",
                    "message": "Invalid JSON request body"
                })
            }

        # Validate required fields
        missing_fields = [
            field for field in REQUIRED_FIELDS
            if field not in body
        ]

        if missing_fields:
            return {
                "statusCode": 400,
                "headers": {
                    "Content-Type": "application/json"
                },
                "body": json.dumps({
                    "status": "error",
                    "message": "Missing required fields",
                    "missing_fields": missing_fields
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
                VALUES (%s, %s, %s, %s, %s, %s)
            """

            cursor.execute(
                sql,
                (
                    body["event_type"],
                    body["source"],
                    body["source_ip"],
                    body["severity"],
                    body["timestamp"].replace("T", " ").replace("Z", ""),
                    body["message"]
                )
            )

            event_id = cursor.lastrowid

        connection.commit()

        print(f"Security event stored successfully. Event ID: {event_id}")

        # Evaluate SOAR rules
        rule_result = evaluate_rules(body)

        if rule_result["matched"]:
            print(
                f"Rule matched: {rule_result['rule_name']} "
                f"for event ID: {event_id}"
            )

            # Automated response 1: create incident
            incident_id = create_incident(
                connection,
                event_id,
                body,
                rule_result["rule_name"]
            )

            # Automated response 2: create dashboard notification
            notification_id = create_notification(
                connection,
                event_id,
                incident_id,
                body,
                rule_result["rule_name"]
            )

            connection.commit()

            print(
                f"Automated responses executed: "
                f"Incident {incident_id} created, "
                f"Notification {notification_id} created"
            )

        else:
            print(f"No rule matched for event ID: {event_id}")

        print("Validated security event:")
        print(json.dumps(body))

        return {
            "statusCode": 200,
            "headers": {
                "Content-Type": "application/json"
            },
            "body": json.dumps({
                "status": "processed",
                "message": "Security event processed successfully",
                "event_id": event_id,
                "rule_matched": rule_result["matched"],
                "rule_name": rule_result["rule_name"],
                "incident_id": incident_id,
                "notification_id": notification_id
            })
        }

    except Exception as error:
        print(f"Failed to process request: {error}")

        return {
            "statusCode": 500,
            "headers": {
                "Content-Type": "application/json"
            },
            "body": json.dumps({
                "status": "error",
                "message": "Failed to process request"
            })
        }

    finally:
        if connection:
            connection.close()