from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from services.database import supabase, insert_audit_log

router = APIRouter()


class IncidentCreate(BaseModel):
    device_id: str
    severity: str
    mitre_id: str | None = None
    title: str | None = None
    summary: str
    recommended_action: str | None = None


@router.get("/")
def get_incidents(
    status: str | None = None,
    severity: str | None = None,
    limit: int = 50
):
    try:
        query = (
            supabase
            .table("incidents")
            .select("*")
            .order("created_at", desc=True)
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
            "incidents": response.data
        }

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Unable to load incidents: {error}"
        )


@router.get("/{incident_id}")
def get_incident(incident_id: str):
    try:
        response = (
            supabase
            .table("incidents")
            .select("*")
            .eq("id", incident_id)
            .limit(1)
            .execute()
        )

        if not response.data:
            raise HTTPException(
                status_code=404,
                detail="Incident not found"
            )

        return {
            "success": True,
            "incident": response.data[0]
        }

    except HTTPException:
        raise

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Unable to load incident: {error}"
        )


@router.post("/")
def create_incident(payload: IncidentCreate):
    try:
        incident_number = (
            f"INC-{str(uuid4())[:8].upper()}"
        )

        incident_title = (
            payload.title
            or f"{payload.severity.title()} Security Incident"
        )

        incident_data = {
            "incident_number": incident_number,
            "device_id": payload.device_id,
            "title": incident_title,
            "summary": payload.summary,
            "severity": payload.severity,
            "status": "open",
            "mitre_technique_id": payload.mitre_id,
            "mitre_id": payload.mitre_id,
            "recommended_action": payload.recommended_action,
            "requires_human_approval": True,
            "report_data": {
                "created_by": "TRINETRA_SOC",
                "source": "manual_api"
            }
        }

        response = (
            supabase
            .table("incidents")
            .insert(incident_data)
            .execute()
        )

        if not response.data:
            raise HTTPException(
                status_code=500,
                detail="Incident was not created"
            )

        incident = response.data[0]

        insert_audit_log({
            "device_id": payload.device_id,
            "action": "incident_created",
            "performed_by": "TRINETRA_SOC",
            "result": "success",
            "details": {
                "incident_id": incident.get("id"),
                "incident_number": incident.get(
                    "incident_number"
                ),
                "severity": payload.severity,
                "summary": payload.summary
            }
        })

        return {
            "success": True,
            "message": "Incident created",
            "incident": incident
        }

    except HTTPException:
        raise

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Unable to create incident: {error}"
        )


@router.post("/{incident_id}/resolve")
def resolve_incident(incident_id: str):
    try:
        existing = (
            supabase
            .table("incidents")
            .select("*")
            .eq("id", incident_id)
            .limit(1)
            .execute()
        )

        if not existing.data:
            raise HTTPException(
                status_code=404,
                detail="Incident not found"
            )

        resolved_at = datetime.now(timezone.utc).isoformat()

        response = (
            supabase
            .table("incidents")
            .update({
                "status": "resolved",
                "resolved_at": resolved_at,
                "response_action": "Incident resolved by SOC analyst",
                "approved_by": "SOC_ANALYST"
            })
            .eq("id", incident_id)
            .execute()
        )

        incident = (
            response.data[0]
            if response.data
            else existing.data[0]
        )

        insert_audit_log({
            "device_id": incident.get("device_id"),
            "action": "incident_resolved",
            "performed_by": "SOC_ANALYST",
            "result": "success",
            "details": {
                "incident_id": incident_id,
                "incident_number": incident.get(
                    "incident_number"
                )
            }
        })

        return {
            "success": True,
            "message": "Incident resolved",
            "incident": incident
        }

    except HTTPException:
        raise

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Unable to resolve incident: {error}"
        )