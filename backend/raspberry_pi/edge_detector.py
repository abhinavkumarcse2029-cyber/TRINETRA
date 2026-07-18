"""
TRINETRA - Edge Threat Detector
-------------------------------
Performs basic threat detection locally on the Raspberry Pi.

This allows the Raspberry Pi to detect dangerous activity
without waiting for the cloud backend.
"""


def calculate_risk(telemetry):
    """
    Analyze telemetry and return a local risk result.
    """

    risk_score = 0
    detections = []

    failed_auth = telemetry.get("failed_auth", 0)
    message_rate = telemetry.get("message_rate", 0)
    outbound_data = telemetry.get("outbound_data", 0)
    cpu_usage = telemetry.get("cpu_usage", 0)
    memory_usage = telemetry.get("memory_usage", 0)
    command = telemetry.get("command", "")

    if failed_auth >= 10:
        risk_score += 35
        detections.append("BRUTE_FORCE")

    if message_rate >= 100:
        risk_score += 25
        detections.append("TRAFFIC_FLOOD")

    if command == "OVERRIDE_CONTROL":
        risk_score += 40
        detections.append("UNAUTHORIZED_COMMAND")

    if outbound_data >= 500:
        risk_score += 30
        detections.append("DATA_EXFILTRATION")

    if cpu_usage >= 90 or memory_usage >= 90:
        risk_score += 20
        detections.append("RESOURCE_EXHAUSTION")

    risk_score = min(risk_score, 100)

    if risk_score >= 80:
        severity = "critical"
    elif risk_score >= 60:
        severity = "high"
    elif risk_score >= 30:
        severity = "medium"
    else:
        severity = "low"

    return {
        "threat_detected": risk_score >= 30,
        "risk_score": risk_score,
        "severity": severity,
        "detections": detections
    }