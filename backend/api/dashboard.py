from fastapi import APIRouter, HTTPException

from services.database import supabase

router = APIRouter()


@router.get("/")
def get_dashboard_summary():
    try:
        devices = (
            supabase.table("devices")
            .select("*")
            .execute()
            .data
        )

        alerts = (
            supabase.table("alerts")
            .select("*")
            .execute()
            .data
        )

        incidents = (
            supabase.table("incidents")
            .select("*")
            .execute()
            .data
        )

        online_devices = sum(
            1
            for device in devices
            if device.get("status") == "online"
        )

        quarantined_devices = sum(
            1
            for device in devices
            if device.get("is_quarantined") is True
        )

        critical_alerts = sum(
            1
            for alert in alerts
            if alert.get("severity") == "critical"
            and alert.get("status") == "open"
        )

        open_incidents = sum(
            1
            for incident in incidents
            if incident.get("status") != "resolved"
        )

        average_risk = (
            round(
                sum(
                    device.get("risk_score", 0)
                    for device in devices
                ) / len(devices),
                2
            )
            if devices
            else 0
        )

        return {
            "success": True,
            "summary": {
                "total_devices": len(devices),
                "online_devices": online_devices,
                "quarantined_devices": quarantined_devices,
                "critical_alerts": critical_alerts,
                "open_incidents": open_incidents,
                "average_risk": average_risk
            }
        }

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Unable to load dashboard summary: {error}"
        )