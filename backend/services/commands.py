from datetime import datetime, timezone

from services.database import supabase


def create_command(command_data):
    response = (
        supabase
        .table("device_commands")
        .insert(command_data)
        .execute()
    )

    return response.data


def get_pending_commands(device_id):
    response = (
        supabase
        .table("device_commands")
        .select("*")
        .eq("device_id", device_id)
        .eq("status", "pending")
        .order("created_at")
        .execute()
    )

    return response.data


def mark_command_processing(command_id):
    response = (
        supabase
        .table("device_commands")
        .update({
            "status": "processing"
        })
        .eq("id", command_id)
        .execute()
    )

    return response.data


def complete_command(
    command_id,
    status,
    command_response
):
    response = (
        supabase
        .table("device_commands")
        .update({
            "status": status,
            "executed_at": datetime.now(
                timezone.utc
            ).isoformat(),
            "response": command_response
        })
        .eq("id", command_id)
        .execute()
    )

    return response.data


def list_commands(limit=100):
    response = (
        supabase
        .table("device_commands")
        .select("*")
        .order("created_at", desc=True)
        .limit(limit)
        .execute()
    )

    return response.data