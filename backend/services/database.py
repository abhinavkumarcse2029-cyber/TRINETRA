from supabase import Client, create_client

from config import SUPABASE_SECRET_KEY, SUPABASE_URL


supabase: Client = create_client(
    SUPABASE_URL,
    SUPABASE_SECRET_KEY
)


# -------------------------------
# Device Operations
# -------------------------------

def get_device(device_id: str):
    response = (
        supabase
        .table("devices")
        .select("*")
        .eq("device_id", device_id)
        .limit(1)
        .execute()
    )

    return response.data[0] if response.data else None


def update_device_seen(device_id: str):
    response = (
        supabase
        .table("devices")
        .update({
            "status": "online",
            "last_seen": "now()"
        })
        .eq("device_id", device_id)
        .execute()
    )

    return response.data


def update_device_risk(
    device_id: str,
    risk_score: int,
    severity: str
):
    status = "warning" if risk_score > 0 else "online"

    response = (
        supabase
        .table("devices")
        .update({
            "risk_score": risk_score,
            "status": status
        })
        .eq("device_id", device_id)
        .execute()
    )

    return response.data


def set_device_quarantine(
    device_id: str,
    quarantined: bool,
    reason: str | None = None
):
    status = "quarantined" if quarantined else "online"

    response = (
        supabase
        .table("devices")
        .update({
            "is_quarantined": quarantined,
            "quarantine_reason": reason,
            "status": status
        })
        .eq("device_id", device_id)
        .execute()
    )

    return response.data


# -------------------------------
# Telemetry Operations
# -------------------------------

def insert_telemetry(data: dict):
    response = (
        supabase
        .table("telemetry")
        .insert(data)
        .execute()
    )

    return response.data


# -------------------------------
# Alert Operations
# -------------------------------

def insert_alert(data: dict):
    response = (
        supabase
        .table("alerts")
        .insert(data)
        .execute()
    )

    return response.data


# -------------------------------
# Incident Operations
# -------------------------------

def insert_incident(incident_data: dict):
    response = (
        supabase
        .table("incidents")
        .insert(incident_data)
        .execute()
    )

    return response.data


# -------------------------------
# Audit Operations
# -------------------------------

def insert_audit_log(data: dict):
    response = (
        supabase
        .table("audit_logs")
        .insert(data)
        .execute()
    )

    return response.data