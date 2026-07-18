"""
TRINETRA - Command Handler
--------------------------
Handles communication with the backend for:
1. Getting pending commands
2. Completing commands
"""

import requests

from config import BACKEND_URL, DEVICE_ID


def get_pending_command():
    """
    Fetch one pending command for this device.
    Returns None if no command exists.
    """

    try:
        response = requests.get(
            f"{BACKEND_URL}/commands/{DEVICE_ID}/pending?claim=true",
            timeout=20
        )

        if response.status_code != 200:
            print(
                f"[Command Handler] Fetch failed: "
                f"{response.status_code} - {response.text}"
            )
            return None

        data = response.json()
        commands = data.get("commands", [])

        if not commands:
            return None

        return commands[0]

    except Exception as error:
        print(f"[Command Handler] {error}")
        return None


def complete_command(
    command_id,
    response_message="Executed Successfully"
):
    """
    Mark a command as completed.
    """

    try:
        payload = {
            "status": "completed",
            "response": response_message
        }

        response = requests.post(
            f"{BACKEND_URL}/commands/{command_id}/complete",
            json=payload,
            timeout=20
        )

        if response.status_code in (200, 201):
            print("[Command Handler] Status updated to completed")
            return True

        print(
            f"[Command Handler] Completion failed: "
            f"{response.status_code} - {response.text}"
        )
        return False

    except Exception as error:
        print(f"[Command Handler] {error}")
        return False