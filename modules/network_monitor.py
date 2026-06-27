import psutil


def get_listening_ports():
    ports = []

    for conn in psutil.net_connections(kind="inet"):
        if conn.status == psutil.CONN_LISTEN:
            local_address = conn.laddr.ip if conn.laddr else "unknown"
            local_port = conn.laddr.port if conn.laddr else "unknown"
            process_name = "unknown"

            if conn.pid:
                try:
                    process_name = psutil.Process(conn.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    process_name = "unknown"

            ports.append({
                "ip": local_address,
                "port": local_port,
                "process": process_name,
                "pid": conn.pid,
            })

    return ports