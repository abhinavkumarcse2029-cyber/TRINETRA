from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from services.database import (
    get_device as get_device_record,
    insert_audit_log,
    set_device_quarantine,
    supabase,
)

router = APIRouter()


class QuarantineRequest(BaseModel):
    reason: str = "Critical cyber threat detected"


@router.get("/")
def get_devices():
    try:
        response = (
            supabase
            .table("devices")
            .select("*")
            .order("created_at", desc=True)
            .execute()
        )

        return {
            "success": True,
            "count": len(response.data),
            "devices": response.data
        }

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Unable to fetch devices: {error}"
        )


@router.get("/{device_id}")
def get_device(device_id: str):
    try:
        device = get_device_record(device_id)

        if not device:
            raise HTTPException(
                status_code=404,
                detail="Device not found"
            )

        return {
            "success": True,
            "device": device
        }

    except HTTPException:
        raise

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Unable to fetch device: {error}"
        )


@router.post("/{device_id}/quarantine")
def quarantine_device(
    device_id: str,
    payload: QuarantineRequest
):
    try:
        device = get_device_record(device_id)

        if not device:
            raise HTTPException(
                status_code=404,
                detail="Device not found"
            )

        updated_device = set_device_quarantine(
            device_id=device_id,
            quarantined=True,
            reason=payload.reason
        )

        insert_audit_log({
            "device_id": device_id,
            "action": "device_quarantined",
            "performed_by": "SOC_ADMIN",
            "result": "success",
            "details": {
                "reason": payload.reason
            }
        })

        return {
            "success": True,
            "message": "Device quarantined successfully",
            "device": updated_device
        }

    except HTTPException:
        raise

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Unable to quarantine device: {error}"
        )


@router.post("/{device_id}/restore")
def restore_device(device_id: str):
    try:
        device = get_device_record(device_id)

        if not device:
            raise HTTPException(
                status_code=404,
                detail="Device not found"
            )

        updated_device = set_device_quarantine(
            device_id=device_id,
            quarantined=False,
            reason=None
        )

        insert_audit_log({
            "device_id": device_id,
            "action": "device_restored",
            "performed_by": "SOC_ADMIN",
            "result": "success",
            "details": {}
        })

        return {
            "success": True,
            "message": "Device restored successfully",
            "device": updated_device
        }

    except HTTPException:
        raise

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Unable to restore device: {error}"
        )
