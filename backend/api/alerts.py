from fastapi import APIRouter, HTTPException

from services.database import supabase, insert_audit_log

router = APIRouter()


@router.get("/")
def get_alerts(
    status: str | None = None,
    severity: str | None = None,
    limit: int = 50
):
    try:
        query = (
            supabase
            .table("alerts")
            .select("*")
            .order("timestamp", desc=True)
            .limit(limit)
        )

        if status:
            query = query.eq("status", status)

        if severity:
            query = query.eq("severity", severity)

        response = query.execute()

        return {
            "success": True,
            "count": len(response.data),
            "alerts": response.data
        }

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Unable to load alerts: {error}"
        )


@router.get("/{alert_id}")
def get_alert(alert_id: str):
    try:
        response = (
            supabase
            .table("alerts")
            .select("*")
            .eq("id", alert_id)
            .limit(1)
            .execute()
        )

        if not response.data:
            raise HTTPException(
                status_code=404,
                detail="Alert not found"
            )

        return {
            "success": True,
            "alert": response.data[0]
        }

    except HTTPException:
        raise

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Unable to load alert: {error}"
        )


@router.post("/{alert_id}/acknowledge")
def acknowledge_alert(alert_id: str):
    try:
        existing = (
            supabase
            .table("alerts")
            .select("*")
            .eq("id", alert_id)
            .limit(1)
            .execute()
        )

        if not existing.data:
            raise HTTPException(
                status_code=404,
                detail="Alert not found"
            )

        response = (
            supabase
            .table("alerts")
            .update({
                "status": "acknowledged"
            })
            .eq("id", alert_id)
            .execute()
        )

        alert = (
            response.data[0]
            if response.data
            else existing.data[0]
        )

        insert_audit_log({
            "device_id": alert.get("device_id"),
            "alert_id": alert_id,
            "action": "alert_acknowledged",
            "performed_by": "SOC_ANALYST",
            "result": "success",
            "details": {
                "attack_type": alert.get("attack_type")
            }
        })

        return {
            "success": True,
            "message": "Alert acknowledged",
            "alert": alert
        }

    except HTTPException:
        raise

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Unable to acknowledge alert: {error}"
        )


@router.post("/{alert_id}/resolve")
def resolve_alert(alert_id: str):
    try:
        existing = (
            supabase
            .table("alerts")
            .select("*")
            .eq("id", alert_id)
            .limit(1)
            .execute()
        )

        if not existing.data:
            raise HTTPException(
                status_code=404,
                detail="Alert not found"
            )

        response = (
            supabase
            .table("alerts")
            .update({
                "status": "resolved"
            })
            .eq("id", alert_id)
            .execute()
        )

        alert = (
            response.data[0]
            if response.data
            else existing.data[0]
        )

        insert_audit_log({
            "device_id": alert.get("device_id"),
            "alert_id": alert_id,
            "action": "alert_resolved",
            "performed_by": "SOC_ANALYST",
            "result": "success",
            "details": {
                "attack_type": alert.get("attack_type"),
                "severity": alert.get("severity")
            }
        })

        return {
            "success": True,
            "message": "Alert resolved",
            "alert": alert
        }

    except HTTPException:
        raise

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Unable to resolve alert: {error}"
        )