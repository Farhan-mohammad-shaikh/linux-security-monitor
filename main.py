from modules.system_monitor import get_system_status
from modules.network_monitor import get_listening_ports
from modules.report_generator import generate_text_report


def main():
    print("Sentinel Linux Security Monitor")
    print("=" * 32)

    system_status = get_system_status()
    listening_ports = get_listening_ports()

    print("\nSystem Status")
    print("-" * 13)
    print(f"CPU Usage: {system_status['cpu_usage_percent']}%")
    print(f"Memory Usage: {system_status['memory_usage_percent']}%")
    print(f"Disk Usage: {system_status['disk_usage_percent']}%")
    print(f"Uptime: {system_status['uptime_seconds']} seconds")

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

    report_path = generate_text_report(system_status, listening_ports)

    print("\nReport generated:")
    print(report_path)


if __name__ == "__main__":
    main()