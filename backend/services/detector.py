ALLOWED_COMMANDS = {
    "HEARTBEAT",
    "STATUS",
    "SYNC",
    "LOGIN"
}


def detect_threat(telemetry: dict) -> dict:
    detections = []
    risk_score = 0

    message_rate = telemetry.get("message_rate", 0)
    payload_size = telemetry.get("payload_size", 0)
    failed_auth = telemetry.get("failed_auth", 0)
    command = telemetry.get("command", "HEARTBEAT")
    outbound_data = telemetry.get("outbound_data", 0)
    cpu_usage = telemetry.get("cpu_usage", 0)
    memory_usage = telemetry.get("memory_usage", 0)

    if failed_auth >= 10:
        detections.append({
            "attack_type": "brute_force",
            "mitre_id": "T1110",
            "reason": f"{failed_auth} failed authentication attempts detected",
            "score": 75
        })
        risk_score += 35

    if message_rate >= 100:
        detections.append({
            "attack_type": "traffic_flood",
            "mitre_id": "T1498",
            "reason": f"Abnormal traffic rate: {message_rate} messages/minute",
            "score": 90
        })
        risk_score += 40

    if command.upper() not in ALLOWED_COMMANDS:
        detections.append({
            "attack_type": "unauthorized_command",
            "mitre_id": "T1059",
            "reason": f"Unauthorized command detected: {command}",
            "score": 85
        })
        risk_score += 40

    if payload_size >= 5000 or outbound_data >= 10000:
        detections.append({
            "attack_type": "data_exfiltration",
            "mitre_id": "T1041",
            "reason": "Unusually large outbound data transfer detected",
            "score": 90
        })
        risk_score += 40

    if cpu_usage >= 90 or memory_usage >= 90:
        detections.append({
            "attack_type": "resource_exhaustion",
            "mitre_id": "T1496",
            "reason": (
                f"High resource usage: CPU {cpu_usage}%, "
                f"Memory {memory_usage}%"
            ),
            "score": 80
        })
        risk_score += 30

    risk_score = min(risk_score, 100)

    if risk_score >= 85:
        severity = "critical"
    elif risk_score >= 60:
        severity = "high"
    elif risk_score >= 30:
        severity = "medium"
    else:
        severity = "low"

    return {
        "threat_detected": len(detections) > 0,
        "risk_score": risk_score,
        "severity": severity,
        "detections": detections
    }
