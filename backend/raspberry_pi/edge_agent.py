"""
TRINETRA - Raspberry Pi Edge Agent
----------------------------------
Main program running on the Raspberry Pi.

Responsibilities:
1. Collect and send telemetry
2. Perform local threat detection
3. Check pending backend commands
4. Send commands to the ESP8266
5. Report command results to the backend
"""

import time

from config import (
    PROJECT_NAME,
    EDGE_NODE,
    TELEMETRY_INTERVAL,
    COMMAND_CHECK_INTERVAL
)
from telemetry_sender import collect_telemetry, send_telemetry
from edge_detector import calculate_risk
from command_handler import get_pending_command, complete_command
from esp_bridge import send_command_to_esp


def process_pending_command():
    """
    Check and execute one pending command.
    """

    command = get_pending_command()

    if command is None:
        return

    command_id = command.get("id")
    command_name = command.get("command")

    print(f"[Command] Received: {command_name}")

    result = send_command_to_esp(command_name)

    if result["success"]:
        complete_command(
            command_id,
            result["message"]
        )
        print("[Command] Completed")
    else:
        complete_command(
            command_id,
            result["message"]
        )
        print("[Command] Failed")


def run_edge_agent():
    """
    Start the continuous Raspberry Pi edge loop.
    """

    print("=" * 50)
    print(f"{PROJECT_NAME} Edge Agent Started")
    print(f"Node: {EDGE_NODE}")
    print("=" * 50)

    last_telemetry_time = 0
    last_command_check_time = 0

    while True:
        current_time = time.time()

        try:
            if current_time - last_telemetry_time >= TELEMETRY_INTERVAL:
                telemetry = collect_telemetry()

                local_result = calculate_risk(telemetry)

                print(
                    f"[Edge Detection] Risk: "
                    f"{local_result['risk_score']} | "
                    f"Severity: {local_result['severity']}"
                )

                send_telemetry()
                last_telemetry_time = current_time

            if (
                current_time - last_command_check_time
                >= COMMAND_CHECK_INTERVAL
            ):
                process_pending_command()
                last_command_check_time = current_time

        except KeyboardInterrupt:
            print("\n[TRINETRA] Edge Agent stopped")
            break

        except Exception as error:
            print(f"[Edge Agent] Error: {error}")

        time.sleep(0.5)


if __name__ == "__main__":
    run_edge_agent()