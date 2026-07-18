from fastapi import APIRouter, HTTPException

from services.database import supabase

router = APIRouter()


@router.get("/")
def get_audit_logs(limit: int = 100):
    try:
        response = (
            supabase
            .table("audit_logs")
            .select("*")
            .order("timestamp", desc=True)
            .limit(limit)
            .execute()
        )

        return {
            "success": True,
            "count": len(response.data),
            "audit_logs": response.data
        }

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Unable to load audit logs: {error}"
        )