from datetime import datetime
from pathlib import Path
from config import REPORT_DIR


def generate_text_report(system_status, listening_ports, ssh_status, detection_result):
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

        report.write("\nSSH Authentication\n")
        report.write("-" * 18 + "\n")

        if ssh_status["failed_logins"]:
            report.write("Failed login attempts:\n")
            for ip, count in ssh_status["failed_logins"].items():
                report.write(f"{ip}: {count}\n")
        else:
            report.write("No failed SSH login attempts found.\n")

        if ssh_status["successful_logins"]:
            report.write("\nRecent successful SSH logins:\n")
            for login in ssh_status["successful_logins"][-5:]:
                report.write(f"{login['user']} from {login['ip']}\n")
        else:
            report.write("No successful SSH logins found.\n")

        report.write("\nAlerts\n")
        report.write("-" * 6 + "\n")

        report.write("\nSecurity Assessment\n")
        report.write("-" * 19 + "\n")
        report.write(f"Risk Level: {detection_result['risk_level']}\n")
        report.write(f"Security Score: {detection_result['score']}/100\n")

        if detection_result["findings"]:
            report.write("\nFindings:\n")
            for finding in detection_result["findings"]:
                report.write(
                    f"[{finding['severity'].upper()}] "
                    f"{finding['title']} - {finding['description']}\n"
                )
        else:
            report.write("No security findings detected.\n")

        all_alerts = []
        all_alerts.extend(system_status["alerts"])
        all_alerts.extend(ssh_status["alerts"])

        if all_alerts:
            for alert in all_alerts:
                report.write(f"- {alert}\n")
        else:
            report.write("No alerts detected.\n")

    return str(report_path)