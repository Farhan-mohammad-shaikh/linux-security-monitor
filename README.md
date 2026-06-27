# Linux Security Monitor

A modular Linux security monitoring and incident detection tool written in Python.

## Overview

Linux Security Monitor collects security-relevant information from a Linux system, analyzes potential risks, and generates automated security reports.

The project demonstrates Linux system monitoring, Python automation, basic blue-team concepts, incident detection, and modular software design.

## Features

- System health monitoring: CPU, memory, disk, uptime
- Listening port detection
- SSH authentication log monitoring
- Running process monitoring
- Rule-based detection engine
- Security risk scoring
- Automated text report generation

## Technologies

- Python 3
- Linux
- psutil
- Git
- Regular Expressions

## Project Structure

```text
linux-security-monitor/
├── main.py
├── config.py
├── requirements.txt
├── modules/
│   ├── system_monitor.py
│   ├── network_monitor.py
│   ├── process_monitor.py
│   ├── ssh_monitor.py
│   ├── detection_engine.py
│   └── report_generator.py
├── reports/
├── screenshots/
└── sample_logs/