from uuid import uuid4

from fastapi import APIRouter, HTTPException

from models.telemetry import TelemetryCreate
from services.commands import create_command
from services.database import (
    supabase,
    get_device,
    insert_alert,
    insert_audit_log,
    insert_incident,
    insert_telemetry,
    update_device_risk,
    update_device_seen,
)
from services.detector import detect_threat


router = APIRouter()

ALERT_RISK_SCORE = 40
INCIDENT_RISK_SCORE = 70
AUTO_QUARANTINE_RISK_SCORE = 85


# ==================================================
# COMMON HELPERS
# ==================================================

def get_first_record(result):
    """
    Safely extract the first database record from
    a list, dictionary, or Supabase response.
    """

    if result is None:
        return None

    if isinstance(result, list):
        return result[0] if result else None

    if isinstance(result, dict):
        return result

    data = getattr(result, "data", None)

    if isinstance(data, list):
        return data[0] if data else None

    if isinstance(data, dict):
        return data

    return None


# ==================================================
# INCIDENT HELPERS
# ==================================================

def get_existing_open_incident(
    device_id: str,
    mitre_id: str,
):
    """
    Prevent duplicate open incidents for the same
    device and MITRE ATT&CK technique.
    """

    response = (
        supabase
        .table("incidents")
        .select("*")
        .eq("device_id", device_id)
        .eq("mitre_id", mitre_id)
        .eq("status", "open")
        .limit(1)
        .execute()
    )

    return get_first_record(response)


def create_or_get_incident(
    device_id: str,
    detection: dict,
    primary_threat: dict,
):
    """
    Create an incident when risk score is 70 or above.
    Return an existing open incident when one already exists.
    """

    risk_score = int(detection.get("risk_score", 0))

    if risk_score < INCIDENT_RISK_SCORE:
        return None

    mitre_id = primary_threat.get("mitre_id")

    if not mitre_id:
        return None

    existing_incident = get_existing_open_incident(
        device_id=device_id,
        mitre_id=mitre_id,
    )

    if existing_incident:
        return existing_incident

    severity = str(
        detection.get("severity", "high")
    ).lower()

    attack_type = primary_threat.get(
        "attack_type",
        "Unknown Threat",
    )

    incident_data = {
        "incident_number": (
            f"INC-{uuid4().hex[:8].upper()}"
        ),
        "device_id": device_id,
        "title": "Security Incident",
        "summary": (
            f"{severity.title()} attack detected: "
            f"{attack_type}"
        ),
        "severity": severity,
        "status": "open",
        "mitre_id": mitre_id,
    }

    incident_result = insert_incident(
        incident_data
    )

    created_incident = get_first_record(
        incident_result
    )

    if created_incident:
        incident_id = (
            created_incident.get("incident_id")
            or created_incident.get("id")
        )

        insert_audit_log({
            "device_id": device_id,
            "action": "incident_auto_created",
            "performed_by": "TRINETRA_AI_ENGINE",
            "result": "success",
            "details": {
                "incident_id": incident_id,
                "incident_number": (
                    created_incident.get(
                        "incident_number"
                    )
                ),
                "attack_type": attack_type,
                "mitre_id": mitre_id,
                "risk_score": risk_score,
                "severity": severity,
            },
        })

    return created_incident


# ==================================================
# QUARANTINE COMMAND HELPERS
# ==================================================

def get_quarantine_command_by_status(
    device_id: str,
    status: str,
):
    """
    Find one quarantine command with the given status.

    Separate status queries are used instead of .in_()
    for better Supabase client compatibility.
    """

    response = (
        supabase
        .table("device_commands")
        .select("*")
        .eq("device_id", device_id)
        .eq("command", "QUARANTINE")
        .eq("status", status)
        .limit(1)
        .execute()
    )

    return get_first_record(response)


def get_active_quarantine_command(
    device_id: str,
):
    """
    Prevent duplicate quarantine commands while one
    is pending or processing.
    """

    pending_command = (
        get_quarantine_command_by_status(
            device_id=device_id,
            status="pending",
        )
    )

    if pending_command:
        return pending_command

    processing_command = (
        get_quarantine_command_by_status(
            device_id=device_id,
            status="processing",
        )
    )

    return processing_command


def trigger_auto_quarantine(
    device_id: str,
    detection: dict,
    primary_threat: dict,
):
    """
    Automatically create a QUARANTINE command when
    severity is critical and risk score is 85 or above.
    """

    risk_score = int(
        detection.get("risk_score", 0)
    )

    severity = str(
        detection.get("severity", "")
    ).lower()

    if risk_score < AUTO_QUARANTINE_RISK_SCORE:
        return None

    if severity != "critical":
        return None

    device = get_device(device_id)

    if not device:
        return {
            "status": "device_not_found",
            "command": None,
        }

    if device.get("is_quarantined"):
        return {
            "status": "already_quarantined",
            "command": None,
        }

    existing_command = (
        get_active_quarantine_command(
            device_id
        )
    )

    if existing_command:
        return {
            "status": "command_already_active",
            "command": existing_command,
        }

    command_result = create_command({
        "device_id": device_id,
        "command": "QUARANTINE",
        "status": "pending",
        "issued_by": "TRINETRA_AI_ENGINE",
    })

    created_command = get_first_record(
        command_result
    )

    command_id = None

    if created_command:
        command_id = created_command.get("id")

    insert_audit_log({
        "device_id": device_id,
        "action": "auto_quarantine_triggered",
        "performed_by": "TRINETRA_AI_ENGINE",
        "result": (
            "pending"
            if created_command
            else "failed"
        ),
        "details": {
            "command_id": command_id,
            "command": "QUARANTINE",
            "reason": (
                "Critical cyber attack automatically "
                "detected by TRINETRA"
            ),
            "attack_type": (
                primary_threat.get("attack_type")
            ),
            "mitre_id": (
                primary_threat.get("mitre_id")
            ),
            "risk_score": risk_score,
            "severity": severity,
            "response_mode": "autonomous",
        },
    })

    if created_command:
        status = "auto_quarantine_pending"
    else:
        status = "auto_quarantine_failed"

    return {
        "status": status,
        "command": created_command,
    }


# ==================================================
# ALERT HELPERS
# ==================================================

def create_alerts(
    payload: TelemetryCreate,
    detection: dict,
    detections: list,
):
    """
    Create security alerts when risk score is 40 or above.
    """

    risk_score = int(
        detection.get("risk_score", 0)
    )

    severity = str(
        detection.get("severity", "medium")
    ).lower()

    if risk_score < ALERT_RISK_SCORE:
        return []

    created_alerts = []

    for threat in detections:
        attack_type = threat.get(
            "attack_type",
            "Unknown Threat",
        )

        mitre_id = threat.get("mitre_id")

        alert_data = {
            "device_id": payload.device_id,
            "attack_type": attack_type,
            "severity": severity,
            "risk_score": risk_score,
            "reason": threat.get(
                "reason",
                "Suspicious telemetry detected",
            ),
            "mitre_technique_id": mitre_id,
            "confidence": threat.get(
                "score",
                0,
            ),
            "status": "open",
            "detection_method": "rule_based",
            "evidence": {
                "message_rate": (
                    payload.message_rate
                ),
                "payload_size": (
                    payload.payload_size
                ),
                "failed_auth": (
                    payload.failed_auth
                ),
                "command": payload.command,
                "destination": (
                    payload.destination
                ),
                "cpu_usage": (
                    payload.cpu_usage
                ),
                "memory_usage": (
                    payload.memory_usage
                ),
            },
        }

        alert_result = insert_alert(
            alert_data
        )

        if isinstance(alert_result, list):
            created_alerts.extend(alert_result)

        else:
            alert_record = get_first_record(
                alert_result
            )

            if alert_record:
                created_alerts.append(
                    alert_record
                )

        alert_record = get_first_record(
            alert_result
        )

        alert_id = None

        if alert_record:
            alert_id = (
                alert_record.get("id")
                or alert_record.get("alert_id")
            )

        insert_audit_log({
            "device_id": payload.device_id,
            "alert_id": alert_id,
            "action": "threat_detected",
            "performed_by": (
                "TRINETRA_EDGE_ENGINE"
            ),
            "result": "alert_created",
            "details": {
                "attack_type": attack_type,
                "mitre_technique_id": mitre_id,
                "risk_score": risk_score,
                "severity": severity,
            },
        })

    return created_alerts


# ==================================================
# TELEMETRY ROUTES
# ==================================================

@router.get("/")
def get_telemetry(limit: int = 100):
    try:
        safe_limit = max(
            1,
            min(limit, 500),
        )

        response = (
            supabase
            .table("telemetry")
            .select("*")
            .order(
                "timestamp",
                desc=True,
            )
            .limit(safe_limit)
            .execute()
        )

        telemetry_records = (
            response.data or []
        )

        return {
            "success": True,
            "count": len(
                telemetry_records
            ),
            "telemetry": telemetry_records,
        }

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=(
                f"Unable to load telemetry: "
                f"{error}"
            ),
        ) from error


@router.post("/")
def create_telemetry(
    payload: TelemetryCreate,
):
    device = get_device(
        payload.device_id
    )

    if not device:
        raise HTTPException(
            status_code=404,
            detail="Device not found",
        )

    if device.get("is_quarantined"):
        raise HTTPException(
            status_code=423,
            detail=(
                "Device is quarantined. "
                "Telemetry rejected by "
                "TRINETRA Edge Gateway."
            ),
        )

    telemetry_data = payload.model_dump()

    try:
        # ------------------------------------------
        # 1. Detect threat from raw telemetry
        # ------------------------------------------

        detection = detect_threat(
            telemetry_data
        )

        risk_score = int(
            detection.get("risk_score", 0)
        )

        severity = str(
            detection.get("severity", "low")
        ).lower()

        detections = (
            detection.get("detections")
            or []
        )

        # ------------------------------------------
        # 2. Save calculated anomaly score
        # ------------------------------------------

        telemetry_data["anomaly_score"] = (
            risk_score / 100
        )

        inserted_telemetry = (
            insert_telemetry(
                telemetry_data
            )
        )

        # ------------------------------------------
        # 3. Update device
        # ------------------------------------------

        update_device_seen(
            payload.device_id
        )

        update_device_risk(
            payload.device_id,
            risk_score,
            severity,
        )

        created_alerts = []
        created_incident = None
        auto_response = None

        # ------------------------------------------
        # 4. Risk 40–69: Create alert
        # ------------------------------------------

        if (
            detections
            and risk_score >= ALERT_RISK_SCORE
        ):
            created_alerts = create_alerts(
                payload=payload,
                detection=detection,
                detections=detections,
            )

        # ------------------------------------------
        # 5. Risk 70+: Create incident
        # ------------------------------------------

        if (
            detections
            and risk_score >= INCIDENT_RISK_SCORE
        ):
            primary_threat = detections[0]

            created_incident = (
                create_or_get_incident(
                    device_id=payload.device_id,
                    detection=detection,
                    primary_threat=primary_threat,
                )
            )

        # ------------------------------------------
        # 6. Risk 85+: Auto quarantine
        # ------------------------------------------

        if (
            detections
            and risk_score
            >= AUTO_QUARANTINE_RISK_SCORE
        ):
            primary_threat = detections[0]

            auto_response = (
                trigger_auto_quarantine(
                    device_id=payload.device_id,
                    detection=detection,
                    primary_threat=primary_threat,
                )
            )

        return {
            "success": True,
            "message": (
                "Telemetry received and analysed"
            ),
            "telemetry": inserted_telemetry,
            "detection": detection,
            "alerts": created_alerts,
            "incident": created_incident,
            "auto_response": auto_response,
        }

    except HTTPException:
        raise

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to process telemetry: "
                f"{error}"
            ),
        ) from error
