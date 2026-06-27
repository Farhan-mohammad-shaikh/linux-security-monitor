# Sentinel Linux Security Monitor

A lightweight Linux Security Monitoring tool written in Python.

This project performs basic host-based security monitoring by collecting Linux system information, monitoring network services, inspecting SSH authentication logs, analyzing running processes, and generating a security assessment report.

---

## Features

- System resource monitoring
  - CPU usage
  - Memory usage
  - Disk usage
  - System uptime

- Network monitoring
  - Detect listening TCP ports
  - Identify exposed services
  - Resolve owning processes

- SSH monitoring
  - Failed login detection
  - Successful login detection
  - SSH authentication alerts

- Process monitoring
  - Top CPU consuming processes
  - Top memory consuming processes
  - Suspicious process detection

- Security assessment engine
  - Security score (0-100)
  - Risk level
  - Detection findings

- Report generation
  - Timestamped security reports
  - Plain text report output

---

## Project Structure
linux-security-monitor/
│
├── modules/
│ ├── system_monitor.py
│ ├── network_monitor.py
│ ├── ssh_monitor.py
│ ├── process_monitor.py
│ ├── detection_engine.py
│ └── report_generator.py
│
├── reports/
├── screenshots/
├── sample_logs/
│
├── main.py
├── config.py
├── requirements.txt
└── README.md


## Installation

```bash
git clone https://github.com/Farhan-mohammad-shaikh/linux-security-monitor.git
cd linux-security-monitor
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## Run

```bash
python main.py
```

---

## Example Output

```text
Risk Level: MEDIUM
Security Score: 76/100

Findings:
[MEDIUM] Non-standard exposed service
Port 1880 exposed on 0.0.0.0
Port 1883 exposed on 0.0.0.0
```
