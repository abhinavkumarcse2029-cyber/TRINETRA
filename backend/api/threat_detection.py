from fastapi import APIRouter, HTTPException

from services.database import supabase

router = APIRouter()


@router.get("/")
def get_threat_detection_summary():
    try:
        alerts = (
            supabase
            .table("alerts")
            .select("*")
            .execute()
            .data
        )

        total_detections = len(alerts)

        critical = sum(
            1 for alert in alerts
            if alert.get("severity") == "critical"
        )

        high = sum(
            1 for alert in alerts
            if alert.get("severity") == "high"
        )

        medium = sum(
            1 for alert in alerts
            if alert.get("severity") == "medium"
        )

        low = sum(
            1 for alert in alerts
            if alert.get("severity") == "low"
        )

        average_confidence = (
            round(
                sum(
                    float(alert.get("confidence") or 0)
                    for alert in alerts
                ) / total_detections,
                2
            )
            if total_detections else 0
        )

        return {
            "success": True,
            "summary": {
                "engine_status": "active",
                "detection_method": "rule_based",
                "total_detections": total_detections,
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
                "average_confidence": average_confidence
            }
        }

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Unable to load detection metrics: {error}"
        )