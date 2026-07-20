ALLOWED_COMMANDS = {
    "HEARTBEAT",
    "STATUS",
    "SYNC",
    "LOGIN",
    "LOGIN_ATTEMPT",
    "NETWORK_REQUEST",
    "PORT_SCAN",
    "DEAUTH_ATTEMPT",
    "DEAUTH_ATTACK",
    "SUSPICIOUS_EXECUTION",
    "MALWARE_EXECUTION"
}


def detect_threat(telemetry: dict) -> dict:
    detections = []
    risk_score = 0

    message_rate = telemetry.get("message_rate", 0)
    payload_size = telemetry.get("payload_size", 0)
    failed_auth = telemetry.get("failed_auth", 0)
    command = telemetry.get("command", "HEARTBEAT").upper()
    outbound_data = telemetry.get("outbound_data", 0)
    cpu_usage = telemetry.get("cpu_usage", 0)
    memory_usage = telemetry.get("memory_usage", 0)

    # ---------------------------------------------------
    # Brute Force (MITRE T1110)
    # ---------------------------------------------------

    if failed_auth >= 10:
        score = 15

        if failed_auth >= 40:
            score = 30

        if failed_auth >= 80:
            score = 55

        risk_score += score

        detections.append({
            "attack_type": "brute_force",
            "mitre_id": "T1110",
            "reason": f"{failed_auth} failed login attempts",
            "score": score
        })

    # ---------------------------------------------------
    # Traffic Flood / DDoS (MITRE T1498)
    # ---------------------------------------------------

    if message_rate >= 100:
        score = 15

        if message_rate >= 1000:
            score = 30

        if message_rate >= 3000:
            score = 45

        risk_score += score

        detections.append({
            "attack_type": "traffic_flood",
            "mitre_id": "T1498",
            "reason": f"Traffic rate {message_rate} msg/min",
            "score": score
        })

    # ---------------------------------------------------
    # Command Execution (MITRE T1059)
    # ---------------------------------------------------

    if command == "SUSPICIOUS_EXECUTION":
        risk_score += 20

        detections.append({
            "attack_type": "suspicious_command",
            "mitre_id": "T1059",
            "reason": "Suspicious command execution",
            "score": 20
        })

    elif command == "MALWARE_EXECUTION":
        risk_score += 40

        detections.append({
            "attack_type": "malware_execution",
            "mitre_id": "T1059",
            "reason": "Malware execution detected",
            "score": 40
        })

    elif command not in ALLOWED_COMMANDS:
        risk_score += 35

        detections.append({
            "attack_type": "unauthorized_command",
            "mitre_id": "T1059",
            "reason": f"Unauthorized command: {command}",
            "score": 35
        })

    # ---------------------------------------------------
    # Data Exfiltration (MITRE T1041)
    # ---------------------------------------------------

    if payload_size >= 5000 or outbound_data >= 10000:

        score = 20

        if payload_size >= 8000 or outbound_data >= 20000:
            score = 35

        risk_score += score

        detections.append({
            "attack_type": "data_exfiltration",
            "mitre_id": "T1041",
            "reason": "Large outbound data transfer",
            "score": score
        })

    # ---------------------------------------------------
    # Resource Exhaustion (MITRE T1496)
    # ---------------------------------------------------

    if cpu_usage >= 70 or memory_usage >= 70:

        score = 10

        if cpu_usage >= 85 or memory_usage >= 85:
            score = 20

        if cpu_usage >= 95 or memory_usage >= 95:
            score = 30

        risk_score += score

        detections.append({
            "attack_type": "resource_exhaustion",
            "mitre_id": "T1498",
            "reason": (
                f"CPU {cpu_usage}% Memory {memory_usage}%"
            ),
            "score": score
        })

    # ---------------------------------------------------
    # Final Risk Score
    # ---------------------------------------------------

    risk_score = min(risk_score, 100)

    if risk_score >= 85:
        severity = "critical"

    elif risk_score >= 70:
        severity = "high"

    elif risk_score >= 40:
        severity = "medium"

    else:
        severity = "low"

    return {
        "threat_detected": len(detections) > 0,
        "risk_score": risk_score,
        "severity": severity,
        "detections": detections
    }
