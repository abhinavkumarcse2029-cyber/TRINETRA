from fastapi import APIRouter, HTTPException

from models.command import (
    CommandComplete,
    CommandCreate,
)
from services.commands import (
    complete_command,
    create_command,
    get_pending_commands,
    list_commands,
    mark_command_processing,
)
from services.database import (
    get_device,
    insert_audit_log,
)

router = APIRouter()


@router.get("/")
def get_all_commands(limit: int = 100):
    try:
        commands = list_commands(limit)

        return {
            "success": True,
            "count": len(commands),
            "commands": commands
        }

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Unable to load commands: {error}"
        )


@router.post("/")
def issue_command(payload: CommandCreate):
    device = get_device(payload.device_id)

    if not device:
        raise HTTPException(
            status_code=404,
            detail="Device not found"
        )

    allowed_commands = {
        "QUARANTINE",
        "RESTORE",
        "REQUEST_TELEMETRY",
        "RESTART",
        "SECURITY_SCAN"
    }

    normalized_command = (
        payload.command
        .strip()
        .upper()
    )

    if normalized_command not in allowed_commands:
        raise HTTPException(
            status_code=400,
            detail=(
                "Unsupported command. Allowed commands: "
                "QUARANTINE, RESTORE, REQUEST_TELEMETRY, "
                "RESTART, SECURITY_SCAN"
            )
        )

    try:
        command_data = {
            "device_id": payload.device_id,
            "command": normalized_command,
            "status": "pending",
            "issued_by": payload.issued_by
        }

        created = create_command(
            command_data
        )

        command = (
            created[0]
            if created else None
        )

        insert_audit_log({
            "device_id": payload.device_id,
            "action": "device_command_issued",
            "performed_by": payload.issued_by,
            "result": "pending",
            "details": {
                "command_id": (
                    command.get("id")
                    if command else None
                ),
                "command": normalized_command
            }
        })

        return {
            "success": True,
            "message": "Command issued successfully",
            "command": command
        }

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Unable to issue command: {error}"
        )


@router.get("/{device_id}/pending")
def get_device_pending_commands(
    device_id: str,
    claim: bool = False
):
    try:
        commands = get_pending_commands(
            device_id
        )

        if claim and commands:
            first_command = commands[0]

            claimed = mark_command_processing(
                first_command["id"]
            )

            command = (
                claimed[0]
                if claimed
                else first_command
            )

            return {
                "success": True,
                "count": 1,
                "commands": [command]
            }

        return {
            "success": True,
            "count": len(commands),
            "commands": commands
        }

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=(
                f"Unable to load pending commands: {error}"
            )
        )


@router.post("/{command_id}/complete")
def mark_command_complete(
    command_id: str,
    payload: CommandComplete
):
    try:
        updated = complete_command(
            command_id,
            payload.status,
            payload.response
        )

        if not updated:
            raise HTTPException(
                status_code=404,
                detail="Command not found"
            )

        command = updated[0]

        insert_audit_log({
            "device_id": command.get("device_id"),
            "action": "device_command_completed",
            "performed_by": "TRINETRA_EDGE_GATEWAY",
            "result": payload.status,
            "details": {
                "command_id": command_id,
                "command": command.get("command"),
                "response": payload.response
            }
        })

        return {
            "success": True,
            "message": "Command status updated",
            "command": command
        }

    except HTTPException:
        raise

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=(
                f"Unable to complete command: {error}"
            )
        )