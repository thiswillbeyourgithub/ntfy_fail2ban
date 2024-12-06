# Fail2Ban to Ntfy Notifier

A Python script that monitors Fail2Ban logs and sends notifications about blocked IPs and security events to [ntfy.sh](https://ntfy.sh).

## Features

- Monitors Fail2Ban logs through journalctl
- Tracks ignored, found, and banned IP addresses
- Monitors UFW (Uncomplicated Firewall) blocks
- Sends formatted notifications via ntfy.sh
- Configurable time window for log analysis

## Requirements

- Python 3.6+
- Linux system with systemd (for journalctl)
- Fail2Ban installed and configured
- UFW (Uncomplicated Firewall) installed
- Access to ntfy.sh service

## Installation

1. Clone this repository
2. Install required packages:
```bash
pip install fire requests
```

## Configuration

Set your ntfy.sh topic as an environment variable:
```bash
export NTFY_TOPIC="your-topic-name"
```

## Usage

Run the script with default settings (24 hours of logs):
```bash
python fail2ban_to_ntfy.py
```

Specify a custom time window:
```bash
python fail2ban_to_ntfy.py --hours=48
```

## Output

The script provides a detailed report including:
- Ignored IP addresses
- Found (suspicious) IP addresses
- Banned IP addresses
- UFW-blocked IP addresses

The report is sent as a notification to your configured ntfy.sh topic.
