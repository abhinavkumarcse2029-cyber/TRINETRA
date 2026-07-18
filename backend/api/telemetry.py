from uuid import uuid4

from fastapi import APIRouter, HTTPException

from models.telemetry import TelemetryCreate
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


@router.get("/")
def get_telemetry(limit: int = 100):
    try:
        response = (
            supabase
            .table("telemetry")
            .select("*")
            .order("timestamp", desc=True)
            .limit(limit)
            .execute()
        )

        return {
            "success": True,
            "count": len(response.data),
            "telemetry": response.data
        }

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Unable to load telemetry: {error}"
        )


@router.post("/")
def create_telemetry(payload: TelemetryCreate):
    device = get_device(payload.device_id)

    if not device:
        raise HTTPException(
            status_code=404,
            detail="Device not found"
        )

    if device.get("is_quarantined"):
        raise HTTPException(
            status_code=423,
            detail=(
                "Device is quarantined. "
                "Telemetry rejected by TRINETRA Edge Gateway."
            )
        )

    telemetry_data = payload.model_dump()

    try:
        detection = detect_threat(telemetry_data)

        telemetry_data["anomaly_score"] = (
            detection["risk_score"] / 100
        )

        inserted_telemetry = insert_telemetry(
            telemetry_data
        )

        update_device_seen(
            payload.device_id
        )

        created_alerts = []
        created_incident = None

        if detection["threat_detected"]:
            update_device_risk(
                payload.device_id,
                detection["risk_score"],
                detection["severity"]
            )

            if (
                detection["severity"] == "critical"
                and detection["detections"]
            ):
                primary_threat = detection["detections"][0]

                incident_data = {
                    "incident_number": (
                        f"INC-{uuid4().hex[:8].upper()}"
                    ),
                    "device_id": payload.device_id,
                    "title": "Critical Security Incident",
                    "summary": (
                        f"Critical attack detected: "
                        f"{primary_threat['attack_type']}"
                    ),
                    "severity": detection["severity"],
                    "status": "open",
                    "mitre_id": primary_threat["mitre_id"]
                }

                incident = insert_incident(
                    incident_data
                )

                if incident:
                    created_incident = incident[0]

                    insert_audit_log({
                        "device_id": payload.device_id,
                        "action": "incident_auto_created",
                        "performed_by": "TRINETRA_AI_ENGINE",
                        "result": "success",
                        "details": {
                            "incident_id": created_incident.get(
                                "incident_id"
                            ),
                            "incident_number": created_incident.get(
                                "incident_number"
                            ),
                            "attack_type": primary_threat[
                                "attack_type"
                            ],
                            "mitre_id": primary_threat[
                                "mitre_id"
                            ],
                            "risk_score": detection[
                                "risk_score"
                            ],
                            "severity": detection[
                                "severity"
                            ]
                        }
                    })

            for threat in detection["detections"]:
                alert_data = {
                    "device_id": payload.device_id,
                    "attack_type": threat["attack_type"],
                    "severity": detection["severity"],
                    "risk_score": detection["risk_score"],
                    "reason": threat["reason"],
                    "mitre_technique_id": threat["mitre_id"],
                    "confidence": threat["score"],
                    "status": "open",
                    "detection_method": "rule_based",
                    "evidence": {
                        "message_rate": payload.message_rate,
                        "payload_size": payload.payload_size,
                        "failed_auth": payload.failed_auth,
                        "command": payload.command,
                        "destination": payload.destination,
                        "cpu_usage": payload.cpu_usage,
                        "memory_usage": payload.memory_usage
                    }
                }

                alert = insert_alert(
                    alert_data
                )

                if alert:
                    created_alerts.extend(alert)

                alert_id = (
                    alert[0]["id"]
                    if alert else None
                )

                insert_audit_log({
                    "device_id": payload.device_id,
                    "alert_id": alert_id,
                    "action": "threat_detected",
                    "performed_by": "TRINETRA_EDGE_ENGINE",
                    "result": "alert_created",
                    "details": {
                        "attack_type": threat["attack_type"],
                        "mitre_technique_id": threat["mitre_id"],
                        "risk_score": detection["risk_score"],
                        "severity": detection["severity"]
                    }
                })

        else:
            update_device_risk(
                payload.device_id,
                0,
                "low"
            )

        return {
            "success": True,
            "message": "Telemetry received and analysed",
            "telemetry": inserted_telemetry,
            "detection": detection,
            "alerts": created_alerts,
            "incident": created_incident
        }

    except HTTPException:
        raise

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Unable to process telemetry: {error}"
        )