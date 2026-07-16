from fastapi import APIRouter, HTTPException

from services.database import supabase

router = APIRouter()


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
        response = (
            supabase
            .table("devices")
            .select("*")
            .eq("device_id", device_id)
            .limit(1)
            .execute()
        )

        if not response.data:
            raise HTTPException(
                status_code=404,
                detail="Device not found"
            )

        return {
            "success": True,
            "device": response.data[0]
        }

    except HTTPException:
        raise

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Unable to fetch device: {error}"
        )
