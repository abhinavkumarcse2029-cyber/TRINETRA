"""
TRINETRA - ESP8266 Bridge
-------------------------
Handles real UART communication between
the Raspberry Pi and ESP8266 device.
"""

import time

import serial


SERIAL_PORT = "/dev/serial0"
BAUD_RATE = 9600
SERIAL_TIMEOUT = 5


SUPPORTED_COMMANDS = {
    "QUARANTINE",
    "RESTORE",
    "REQUEST_TELEMETRY",
    "RESTART",
    "SECURITY_SCAN",
}


def send_command_to_esp(command_name):
    """
    Send a command to the ESP8266 through UART
    and return the ESP8266 response.
    """

    command_name = str(command_name).strip().upper()

    if command_name not in SUPPORTED_COMMANDS:
        return {
            "success": False,
            "message": f"Unsupported command: {command_name}",
        }

    serial_connection = None

    try:
        serial_connection = serial.Serial(
            port=SERIAL_PORT,
            baudrate=BAUD_RATE,
            timeout=SERIAL_TIMEOUT,
            write_timeout=SERIAL_TIMEOUT,
        )

        # Allow serial connection to stabilize
        time.sleep(0.3)

        # Remove old READY/debug messages from the buffer
        serial_connection.reset_input_buffer()
        serial_connection.reset_output_buffer()

        print(f"[ESP Bridge] Sending command: {command_name}")

        command_bytes = f"{command_name}\n".encode("utf-8")

        serial_connection.write(command_bytes)
        serial_connection.flush()

        response = serial_connection.readline().decode(
            "utf-8",
            errors="replace",
        ).strip()

        if not response:
            return {
                "success": False,
                "message": (
                    "ESP8266 did not respond within "
                    f"{SERIAL_TIMEOUT} seconds"
                ),
            }

        print(f"[ESP Bridge] Raw response: {response}")

        response_parts = response.split("|", 2)

        if len(response_parts) < 2:
            return {
                "success": False,
                "message": f"Invalid ESP8266 response: {response}",
            }

        response_status = response_parts[0]

        if len(response_parts) == 3:
            response_message = response_parts[2]
        else:
            response_message = response

        if response_status == "OK":
            return {
                "success": True,
                "message": response_message,
                "raw_response": response,
            }

        return {
            "success": False,
            "message": response_message,
            "raw_response": response,
        }

    except serial.SerialException as error:
        print(f"[ESP Bridge] Serial error: {error}")

        return {
            "success": False,
            "message": f"ESP8266 serial communication failed: {error}",
        }

    except Exception as error:
        print(f"[ESP Bridge] Unexpected error: {error}")

        return {
            "success": False,
            "message": f"ESP8266 communication error: {error}",
        }

    finally:
        if serial_connection is not None and serial_connection.is_open:
            serial_connection.close()