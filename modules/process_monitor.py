import psutil


SUSPICIOUS_PROCESS_NAMES = {
    "nc",
    "netcat",
    "ncat",
    "hydra",
    "john",
    "hashcat",
    "aircrack-ng",
}


def get_process_status(limit=5):
    processes = []
    suspicious_processes = []
    alerts = []

    for process in psutil.process_iter(
        ["pid", "name", "username", "cpu_percent", "memory_percent", "status"]
    ):
        try:
            info = process.info

            process_data = {
                "pid": info["pid"],
                "name": info["name"] or "unknown",
                "username": info["username"] or "unknown",
                "cpu_percent": info["cpu_percent"] or 0.0,
                "memory_percent": round(info["memory_percent"] or 0.0, 2),
                "status": info["status"] or "unknown",
            }

            processes.append(process_data)

            if process_data["name"].lower() in SUSPICIOUS_PROCESS_NAMES:
                suspicious_processes.append(process_data)
                alerts.append(
                    f"Suspicious process detected: {process_data['name']} "
                    f"(PID {process_data['pid']})"
                )

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    top_cpu_processes = sorted(
        processes,
        key=lambda item: item["cpu_percent"],
        reverse=True
    )[:limit]

    top_memory_processes = sorted(
        processes,
        key=lambda item: item["memory_percent"],
        reverse=True
    )[:limit]

    return {
        "top_cpu_processes": top_cpu_processes,
        "top_memory_processes": top_memory_processes,
        "suspicious_processes": suspicious_processes,
        "alerts": alerts,
    }