import re
from collections import defaultdict
from pathlib import Path


AUTH_LOG_PATHS = [
    "/var/log/auth.log",
    "/var/log/secure",
]


def find_auth_log():
    for path in AUTH_LOG_PATHS:
        if Path(path).exists():
            return path
    return None


def get_ssh_authentication_status(threshold=5):
    log_path = find_auth_log()

    result = {
        "log_file": log_path,
        "failed_logins": {},
        "successful_logins": [],
        "alerts": [],
    }

    if log_path is None:
        result["alerts"].append("No authentication log file found.")
        return result

    failed_attempts = defaultdict(int)

    failed_pattern = re.compile(r"Failed password.*from (\d+\.\d+\.\d+\.\d+)")
    success_pattern = re.compile(r"Accepted .* for ([^\s]+) from (\d+\.\d+\.\d+\.\d+)")

    try:
        with open(log_path, "r", encoding="utf-8", errors="ignore") as log_file:
            for line in log_file:
                failed_match = failed_pattern.search(line)
                if failed_match:
                    ip = failed_match.group(1)
                    failed_attempts[ip] += 1

                success_match = success_pattern.search(line)
                if success_match:
                    user = success_match.group(1)
                    ip = success_match.group(2)
                    result["successful_logins"].append({
                        "user": user,
                        "ip": ip,
                        "log": line.strip(),
                    })

    except PermissionError:
        result["alerts"].append(
            "Permission denied while reading authentication logs. Try running with sudo."
        )
        return result

    result["failed_logins"] = dict(failed_attempts)

    for ip, count in failed_attempts.items():
        if count >= threshold:
            result["alerts"].append(
                f"Possible brute-force attempt from {ip}: {count} failed SSH logins."
            )

    return result