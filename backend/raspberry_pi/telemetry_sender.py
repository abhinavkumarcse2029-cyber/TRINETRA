"""
TRINETRA - Telemetry Sender
---------------------------
Collects Raspberry Pi system information and sends it
to the TRINETRA backend.
"""

import os
import socket
import psutil
import requests

from config import BACKEND_URL, DEVICE_ID


def get_ip_address():
    """
    Returns Raspberry Pi local IP address.
    """

    try:
        hostname = socket.gethostname()
        return socket.gethostbyname(hostname)
    except Exception:
        return "unknown"


def collect_telemetry():
    """
    Collect system telemetry from the Raspberry Pi.
    """

    cpu_usage = psutil.cpu_percent(interval=0.5)
    memory_usage = psutil.virtual_memory().percent

    payload = {
        "device_id": DEVICE_ID,
        "message_rate": 1,
        "payload_size": 0,
        "failed_auth": 0,
        "command": "NORMAL_OPERATION",
        "destination": "TRINETRA_BACKEND",
        "source_type": "raspberry_pi",
        "source_ip": get_ip_address(),
        "cpu_usage": cpu_usage,
        "memory_usage": memory_usage,
        "outbound_data": 0,
        "anomaly_score": 0,
        "raw_data": {
            "hostname": socket.gethostname(),
            "platform": os.name
        }
    }

    return payload


def send_telemetry():
    """
    Send Raspberry Pi telemetry to the backend.
    """

    try:
        telemetry = collect_telemetry()

        response = requests.post(
            f"{BACKEND_URL}/telemetry",
            json=telemetry,
            timeout=5
        )

        if response.status_code in (200, 201):
            print("[Telemetry] Sent successfully")
            return True

        print(
            f"[Telemetry] Failed: "
            f"{response.status_code} - {response.text}"
        )
        return False

    except Exception as error:
        print(f"[Telemetry] Error: {error}")
        return False