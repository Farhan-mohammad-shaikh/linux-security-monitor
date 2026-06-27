STANDARD_PORTS = {22, 53, 80, 123, 443}
SUSPICIOUS_PORTS = {4444, 5555, 6666, 31337}


def run_detection(system_status, listening_ports, ssh_status):
    findings = []
    score = 100

    if system_status["cpu_usage_percent"] >= 80:
        findings.append({
            "severity": "medium",
            "title": "High CPU usage",
            "description": f"CPU usage is {system_status['cpu_usage_percent']}%."
        })
        score -= 10

    if system_status["memory_usage_percent"] >= 80:
        findings.append({
            "severity": "medium",
            "title": "High memory usage",
            "description": f"Memory usage is {system_status['memory_usage_percent']}%."
        })
        score -= 10

    if system_status["disk_usage_percent"] >= 85:
        findings.append({
            "severity": "high",
            "title": "High disk usage",
            "description": f"Disk usage is {system_status['disk_usage_percent']}%."
        })
        score -= 15

    for ip, count in ssh_status["failed_logins"].items():
        if count >= 10:
            findings.append({
                "severity": "high",
                "title": "Possible SSH brute-force attack",
                "description": f"{count} failed SSH login attempts from {ip}."
            })
            score -= 25
        elif count >= 5:
            findings.append({
                "severity": "medium",
                "title": "Repeated SSH login failures",
                "description": f"{count} failed SSH login attempts from {ip}."
            })
            score -= 10

    for port in listening_ports:
        port_number = port["port"]

        if not isinstance(port_number, int):
            continue

        if port_number in SUSPICIOUS_PORTS:
            findings.append({
                "severity": "high",
                "title": "Suspicious listening port",
                "description": f"Port {port_number} is listening on {port['ip']}."
            })
            score -= 20

        elif port_number not in STANDARD_PORTS and port["ip"] in ["0.0.0.0", "::"]:
            findings.append({
                "severity": "medium",
                "title": "Non-standard exposed service",
                "description": f"Port {port_number} is exposed on {port['ip']} by process {port['process']}."
            })
            score -= 8

    score = max(score, 0)

    if score >= 85:
        risk_level = "LOW"
    elif score >= 60:
        risk_level = "MEDIUM"
    else:
        risk_level = "HIGH"

    return {
        "score": score,
        "risk_level": risk_level,
        "findings": findings,
    }