"""
TRINETRA - ESP8266 Bridge
-------------------------
Handles communication between the Raspberry Pi
and the ESP8266 device.

For now, commands are simulated.
Later, this file will send real commands using Serial/UART.
"""

import time


SUPPORTED_COMMANDS = {
    "QUARANTINE",
    "RESTORE",
    "REQUEST_TELEMETRY",
    "RESTART",
    "SECURITY_SCAN"
}


def send_command_to_esp(command_name):
    """
    Send a command to the ESP8266.

    Currently this function simulates execution.
    Later we will replace the simulation with Serial/UART communication.
    """

    if command_name not in SUPPORTED_COMMANDS:
        return {
            "success": False,
            "message": f"Unsupported command: {command_name}"
        }

    print(f"[ESP Bridge] Sending command: {command_name}")

    time.sleep(1)

    if command_name == "QUARANTINE":
        message = "ESP8266 network access restricted"

    elif command_name == "RESTORE":
        message = "ESP8266 restored to normal operation"

    elif command_name == "REQUEST_TELEMETRY":
        message = "ESP8266 telemetry requested"

    elif command_name == "RESTART":
        message = "ESP8266 restart command executed"

    elif command_name == "SECURITY_SCAN":
        message = "ESP8266 security scan completed"

    else:
        message = "Command executed"

    print(f"[ESP Bridge] {message}")

    return {
        "success": True,
        "message": message
    }