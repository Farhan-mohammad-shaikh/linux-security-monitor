from modules.system_monitor import get_system_status
from modules.network_monitor import get_listening_ports
from modules.ssh_monitor import get_ssh_authentication_status
from modules.detection_engine import run_detection
from modules.report_generator import generate_text_report


def print_system_status(system_status):
    print("\nSystem Status")
    print("-" * 13)
    print(f"CPU Usage: {system_status['cpu_usage_percent']}%")
    print(f"Memory Usage: {system_status['memory_usage_percent']}%")
    print(f"Disk Usage: {system_status['disk_usage_percent']}%")
    print(f"Uptime: {system_status['uptime_seconds']} seconds")


def print_listening_ports(listening_ports):
    print("\nListening Ports")
    print("-" * 15)

    if listening_ports:
        for port in listening_ports:
            print(
                f"{port['ip']}:{port['port']} | "
                f"{port['process']} | PID: {port['pid']}"
            )
    else:
        print("No listening ports detected.")


def print_ssh_status(ssh_status):
    print("\nSSH Authentication")
    print("-" * 18)

    if ssh_status["failed_logins"]:
        print("Failed login attempts:")
        for ip, count in ssh_status["failed_logins"].items():
            print(f"{ip}: {count}")
    else:
        print("No failed SSH login attempts found.")

    if ssh_status["successful_logins"]:
        print("\nRecent successful SSH logins:")
        for login in ssh_status["successful_logins"][-5:]:
            print(f"{login['user']} from {login['ip']}")
    else:
        print("No successful SSH logins found.")

    if ssh_status["alerts"]:
        print("\nSSH Alerts:")
        for alert in ssh_status["alerts"]:
            print(f"- {alert}")


def print_security_assessment(detection_result):
    print("\nSecurity Assessment")
    print("-" * 19)
    print(f"Risk Level: {detection_result['risk_level']}")
    print(f"Security Score: {detection_result['score']}/100")

    if detection_result["findings"]:
        print("\nFindings:")
        for finding in detection_result["findings"]:
            print(
                f"[{finding['severity'].upper()}] "
                f"{finding['title']} - {finding['description']}"
            )
    else:
        print("No security findings detected.")


def main():
    print("Sentinel Linux Security Monitor")
    print("=" * 32)

    system_status = get_system_status()
    listening_ports = get_listening_ports()
    ssh_status = get_ssh_authentication_status()
    detection_result = run_detection(system_status, listening_ports, ssh_status)

    print_system_status(system_status)
    print_listening_ports(listening_ports)
    print_ssh_status(ssh_status)
    print_security_assessment(detection_result)

    report_path = generate_text_report(
        system_status,
        listening_ports,
        ssh_status,
        detection_result
    )

    print("\nReport generated:")
    print(report_path)


if __name__ == "__main__":
    main()