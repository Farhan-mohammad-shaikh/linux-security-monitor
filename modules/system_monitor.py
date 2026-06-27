import psutil
import time
from config import CPU_ALERT_THRESHOLD, MEMORY_ALERT_THRESHOLD, DISK_ALERT_THRESHOLD


def get_system_status():
    cpu_usage = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    boot_time = psutil.boot_time()
    uptime_seconds = int(time.time() - boot_time)

    alerts = []

    if cpu_usage >= CPU_ALERT_THRESHOLD:
        alerts.append(f"High CPU usage detected: {cpu_usage}%")

    if memory.percent >= MEMORY_ALERT_THRESHOLD:
        alerts.append(f"High memory usage detected: {memory.percent}%")

    if disk.percent >= DISK_ALERT_THRESHOLD:
        alerts.append(f"High disk usage detected: {disk.percent}%")

    return {
        "cpu_usage_percent": cpu_usage,
        "memory_usage_percent": memory.percent,
        "disk_usage_percent": disk.percent,
        "uptime_seconds": uptime_seconds,
        "alerts": alerts,
    }