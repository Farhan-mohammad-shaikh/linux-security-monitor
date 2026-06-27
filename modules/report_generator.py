from datetime import datetime
from pathlib import Path
from config import REPORT_DIR


def generate_text_report(system_status, listening_ports):
    Path(REPORT_DIR).mkdir(exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_path = Path(REPORT_DIR) / f"security_report_{timestamp}.txt"

    with open(report_path, "w", encoding="utf-8") as report:
        report.write("Sentinel Linux Security Report\n")
        report.write("=" * 32 + "\n")
        report.write(f"Generated at: {datetime.now()}\n\n")

        report.write("System Status\n")
        report.write("-" * 13 + "\n")
        report.write(f"CPU Usage: {system_status['cpu_usage_percent']}%\n")
        report.write(f"Memory Usage: {system_status['memory_usage_percent']}%\n")
        report.write(f"Disk Usage: {system_status['disk_usage_percent']}%\n")
        report.write(f"Uptime: {system_status['uptime_seconds']} seconds\n\n")

        report.write("Listening Network Ports\n")
        report.write("-" * 23 + "\n")

        if listening_ports:
            for port in listening_ports:
                report.write(
                    f"{port['ip']}:{port['port']} | "
                    f"Process: {port['process']} | PID: {port['pid']}\n"
                )
        else:
            report.write("No listening ports detected.\n")

        report.write("\nAlerts\n")
        report.write("-" * 6 + "\n")

        if system_status["alerts"]:
            for alert in system_status["alerts"]:
                report.write(f"- {alert}\n")
        else:
            report.write("No system alerts detected.\n")

    return str(report_path)