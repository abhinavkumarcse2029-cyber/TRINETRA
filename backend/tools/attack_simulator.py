#!/usr/bin/env python3

import json
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


# --------------------------------------------------
# Configuration
# --------------------------------------------------

BACKEND_URL = "http://127.0.0.1:8000/telemetry/"
DEVICE_ID = "ESP-01"


# --------------------------------------------------
# Attack telemetry profiles
# --------------------------------------------------
#
# Low:
# Expected to create a low/medium risk alert.
#
# Medium:
# Expected to create an alert and possibly an incident.
#
# Critical:
# Expected to reach risk >= 85 and trigger auto quarantine.
#
# Final risk score is always calculated by detector.py.
# --------------------------------------------------

ATTACKS = {
    "1": {
        "name": "Brute Force",
        "levels": {
            "1": {
                "name": "Low",
                "payload": {
                    "message_rate": 70,
                    "payload_size": 512,
                    "failed_auth": 12,
                    "command": "LOGIN_ATTEMPT",
                    "destination": "SSH",
                    "cpu_usage": 38,
                    "memory_usage": 35
                }
            },
            "2": {
                "name": "Medium",
                "payload": {
                    "message_rate": 180,
                    "payload_size": 768,
                    "failed_auth": 45,
                    "command": "LOGIN_ATTEMPT",
                    "destination": "SSH",
                    "cpu_usage": 68,
                    "memory_usage": 58
                }
            },
            "3": {
                "name": "Critical",
                "payload": {
                    "message_rate": 500,
                    "payload_size": 1024,
                    "failed_auth": 120,
                    "command": "LOGIN_ATTEMPT",
                    "destination": "SSH",
                    "cpu_usage": 92,
                    "memory_usage": 86
                }
            }
        }
    },

    "2": {
        "name": "DDoS",
        "levels": {
            "1": {
                "name": "Low",
                "payload": {
                    "message_rate": 250,
                    "payload_size": 1024,
                    "failed_auth": 0,
                    "command": "NETWORK_REQUEST",
                    "destination": "WEB_SERVER",
                    "cpu_usage": 48,
                    "memory_usage": 42
                }
            },
            "2": {
                "name": "Medium",
                "payload": {
                    "message_rate": 1200,
                    "payload_size": 2048,
                    "failed_auth": 2,
                    "command": "NETWORK_REQUEST",
                    "destination": "WEB_SERVER",
                    "cpu_usage": 76,
                    "memory_usage": 69
                }
            },
            "3": {
                "name": "Critical",
                "payload": {
                    "message_rate": 6000,
                    "payload_size": 4096,
                    "failed_auth": 5,
                    "command": "NETWORK_REQUEST",
                    "destination": "WEB_SERVER",
                    "cpu_usage": 98,
                    "memory_usage": 94
                }
            }
        }
    },

    "3": {
        "name": "Port Scan",
        "levels": {
            "1": {
                "name": "Low",
                "payload": {
                    "message_rate": 120,
                    "payload_size": 128,
                    "failed_auth": 2,
                    "command": "PORT_SCAN",
                    "destination": "MULTIPLE_PORTS",
                    "cpu_usage": 42,
                    "memory_usage": 36
                }
            },
            "2": {
                "name": "Medium",
                "payload": {
                    "message_rate": 700,
                    "payload_size": 256,
                    "failed_auth": 10,
                    "command": "PORT_SCAN",
                    "destination": "MULTIPLE_PORTS",
                    "cpu_usage": 70,
                    "memory_usage": 60
                }
            },
            "3": {
                "name": "Critical",
                "payload": {
                    "message_rate": 2500,
                    "payload_size": 512,
                    "failed_auth": 35,
                    "command": "PORT_SCAN",
                    "destination": "MULTIPLE_PORTS",
                    "cpu_usage": 94,
                    "memory_usage": 87
                }
            }
        }
    },

    "4": {
        "name": "Malware Command",
        "levels": {
            "1": {
                "name": "Low",
                "payload": {
                    "message_rate": 80,
                    "payload_size": 1024,
                    "failed_auth": 2,
                    "command": "SUSPICIOUS_EXECUTION",
                    "destination": "UNKNOWN_SERVER",
                    "cpu_usage": 52,
                    "memory_usage": 48
                }
            },
            "2": {
                "name": "Medium",
                "payload": {
                    "message_rate": 350,
                    "payload_size": 4096,
                    "failed_auth": 12,
                    "command": "SUSPICIOUS_EXECUTION",
                    "destination": "UNKNOWN_SERVER",
                    "cpu_usage": 79,
                    "memory_usage": 73
                }
            },
            "3": {
                "name": "Critical",
                "payload": {
                    "message_rate": 1000,
                    "payload_size": 8192,
                    "failed_auth": 40,
                    "command": "MALWARE_EXECUTION",
                    "destination": "UNKNOWN_SERVER",
                    "cpu_usage": 99,
                    "memory_usage": 96
                }
            }
        }
    },

    "5": {
        "name": "Deauthentication Attack",
        "levels": {
            "1": {
                "name": "Low",
                "payload": {
                    "message_rate": 180,
                    "payload_size": 256,
                    "failed_auth": 8,
                    "command": "DEAUTH_ATTEMPT",
                    "destination": "WIFI_ACCESS_POINT",
                    "cpu_usage": 46,
                    "memory_usage": 39
                }
            },
            "2": {
                "name": "Medium",
                "payload": {
                    "message_rate": 1000,
                    "payload_size": 512,
                    "failed_auth": 45,
                    "command": "DEAUTH_ATTEMPT",
                    "destination": "WIFI_ACCESS_POINT",
                    "cpu_usage": 75,
                    "memory_usage": 66
                }
            },
            "3": {
                "name": "Critical",
                "payload": {
                    "message_rate": 4000,
                    "payload_size": 1024,
                    "failed_auth": 110,
                    "command": "DEAUTH_ATTACK",
                    "destination": "WIFI_ACCESS_POINT",
                    "cpu_usage": 96,
                    "memory_usage": 90
                }
            }
        }
    }
}


# --------------------------------------------------
# Helper Functions
# --------------------------------------------------

def get_expected_action(risk_score):
    try:
        risk_score = int(risk_score)
    except (TypeError, ValueError):
        return "Unknown"

    if risk_score < 40:
        return "Log only"

    if risk_score < 70:
        return "Alert"

    if risk_score < 85:
        return "Alert + Incident"

    return "Alert + Incident + Auto Quarantine"


def send_attack(attack_choice: str, level_choice: str):
    attack = ATTACKS.get(attack_choice)

    if not attack:
        print("\nInvalid attack option.")
        return

    level = attack["levels"].get(level_choice)

    if not level:
        print("\nInvalid intensity option.")
        return

    payload = {
        "device_id": DEVICE_ID,
        **level["payload"]
    }

    request = Request(
        BACKEND_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json"
        },
        method="POST"
    )

    print("\n--------------------------------------------")
    print(f"Attack: {attack['name']}")
    print(f"Intensity: {level['name']}")
    print(f"Device: {DEVICE_ID}")
    print(f"Backend: {BACKEND_URL}")
    print("--------------------------------------------")

    print("\nTelemetry being sent:")
    print(json.dumps(payload, indent=2))

    try:
        with urlopen(request, timeout=15) as response:
            response_body = response.read().decode("utf-8")
            result = json.loads(response_body)

        print("\nAttack telemetry sent successfully.")

        detection = result.get("detection", {})
        risk_score = detection.get("risk_score")
        severity = detection.get("severity")
        threat_detected = detection.get("threat_detected")

        print("\n========== DETECTION RESULT ==========")
        print(f"Threat detected : {threat_detected}")
        print(f"Risk score      : {risk_score}")
        print(f"Severity        : {severity}")
        print(f"Expected action : {get_expected_action(risk_score)}")

        detections = detection.get("detections", [])

        if detections:
            print("\nDetected attacks:")

            for detected in detections:
                print(
                    f"- {detected.get('attack_type')} "
                    f"| MITRE: {detected.get('mitre_id')} "
                    f"| Score: {detected.get('score')}"
                )
        else:
            print("\nNo attack signature was detected.")

        alerts = result.get("alerts", [])

        print("\n========== ALERT RESULT ==========")

        if alerts:
            print(f"Alerts created: {len(alerts)}")

            for alert in alerts:
                print(
                    f"- {alert.get('attack_type')} "
                    f"| Severity: {alert.get('severity')} "
                    f"| Risk: {alert.get('risk_score')}"
                )
        else:
            print("No alert was created.")

        incident = result.get("incident")

        print("\n========== INCIDENT RESULT ==========")

        if incident:
            print(
                "Incident created/found: "
                f"{incident.get('incident_number', 'Yes')}"
            )
            print(
                f"Incident status: "
                f"{incident.get('status', 'unknown')}"
            )
        else:
            print("No incident was created.")

        auto_response = result.get("auto_response")

        print("\n========== AUTOMATIC RESPONSE ==========")

        if auto_response:
            print(
                f"Automatic response: "
                f"{auto_response.get('status')}"
            )

            command = auto_response.get("command")

            if command:
                print(
                    f"Command: {command.get('command')} "
                    f"| Status: {command.get('status')}"
                )
        else:
            print("Automatic quarantine was not triggered.")

        print("\n========== FULL BACKEND RESPONSE ==========")
        print(json.dumps(result, indent=2))

    except HTTPError as error:
        response_body = error.read().decode(
            "utf-8",
            errors="replace"
        )

        print(f"\nBackend returned HTTP {error.code}")
        print(response_body)

        if error.code == 423:
            print(
                "\nThe device is already quarantined."
                "\nRestore it before running another simulation."
            )

        elif error.code == 404:
            print(
                f"\nDevice '{DEVICE_ID}' was not found."
                "\nUpdate DEVICE_ID in attack_simulator.py."
            )

        elif error.code == 422:
            print(
                "\nTelemetry payload validation failed."
                "\nCheck models/telemetry.py fields."
            )

    except URLError as error:
        print("\nUnable to connect to backend.")
        print(f"Reason: {error.reason}")
        print(
            "\nCheck backend service using:"
            "\nsudo systemctl status trinetra-backend.service"
        )

    except json.JSONDecodeError:
        print("\nBackend returned an invalid JSON response.")

    except Exception as error:
        print(f"\nUnexpected error: {error}")


def display_attack_menu():
    print(
        """
================================================
          TRINETRA ATTACK SIMULATOR
================================================

1. Brute Force
2. DDoS
3. Port Scan
4. Malware Command
5. Deauthentication Attack
0. Exit
"""
    )


def display_intensity_menu(attack_name: str):
    print(
        f"""
------------------------------------------------
Selected Attack: {attack_name}
------------------------------------------------

1. Low
   Expected: Log or Alert

2. Medium
   Expected: Alert or Incident

3. Critical
   Expected: Auto Quarantine

0. Back
"""
    )


def main():
    while True:
        display_attack_menu()

        attack_choice = input(
            "Select attack: "
        ).strip()

        if attack_choice == "0":
            print("\nSimulator closed.")
            sys.exit(0)

        attack = ATTACKS.get(attack_choice)

        if not attack:
            print("\nInvalid attack option.")
            input("\nPress Enter to continue...")
            continue

        while True:
            display_intensity_menu(
                attack["name"]
            )

            level_choice = input(
                "Select intensity: "
            ).strip()

            if level_choice == "0":
                break

            if level_choice not in {"1", "2", "3"}:
                print("\nInvalid intensity option.")
                continue

            send_attack(
                attack_choice,
                level_choice
            )

            input("\nPress Enter to continue...")
            break


if __name__ == "__main__":
    main()
