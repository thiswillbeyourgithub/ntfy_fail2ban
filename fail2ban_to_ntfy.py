import os
import subprocess
from datetime import datetime, timedelta
import fire
import re
import requests

def send_notif(
    message: str,
    topic: str,
    title: str = "Fail2Ban status",
    ) -> str:
    """
    Send a notification to a specified ntfy.sh topic.

    Args:
        message (str): The message content to be sent.
        topic (str): The ntfy.sh topic to send the notification to.
        title (str, optional): The title of the notification. Defaults to "WDoc Summaries".

    Returns:
        str: The message that was sent.
    """
    requests.post(
        url=f"https://ntfy.sh/{topic}",
        data=message.encode(encoding='utf-8'),
        headers={
            "Title": title,
            # "Priority": "urgent",
            # "Tags": "warning,skull"
        },
    )
    return message


def get_journalctl_logs(hours):
    # Calculate the start time
    try:
        # Run the journalctl command and capture the output
        result = subprocess.check_output(
            f"journalctl -o cat --since \"{hours}h ago\" | grep -E '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'",
            shell=True,
            text=True
        ).strip()

        return result
    except subprocess.CalledProcessError as e:
        print(f"Error running journalctl: {e}")
        return None

def get_ufw_logs(hours):
# journalctl -o cat --since "{hours} hours ago" | grep "UFW BLOCK" | grep -v SRC=192.168.1.254 | cut -d' ' -f 11-12 | uniq | sort
    command = f"""
journalctl --since "{hours} hours ago" | grep "UFW BLOCK" | grep -v SRC=192.168.1.254 | cut -d' ' -f 11-11 | cut -c 5- | uniq | sort | uniq
""".strip()
    result = subprocess.check_output(command, shell=True, text=True)
    return result

def main(hours=24):
    """
    Retrieve and print journalctl logs for the specified time frame,
    filtering for lines containing "fail2ban" and extracting IPv4 addresses.
    Categorizes IPs into ignored, found, banned, and others.
    
    :param hours: Number of hours to look back (default: 24)
    """
    content = ""
    def p(message):
        nonlocal content
        content += "\n" + str(message)
    logs = get_journalctl_logs(hours)
    if logs:
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        fail2ban_logs = []
        ignored_ips = {}
        found_ips = {}
        banned_ips = {}
        else_ips = {}

        for line in logs.splitlines():
            if "fail2ban.filter" in line.lower():
                if "timezone issue" in line:
                    continue
                ip_addresses = re.findall(ip_pattern, line)
                if not ip_addresses:
                    continue
                if len(ip_addresses) != 1:
                    print(f"Found multiple IP: {line}")
                for ip_address in ip_addresses:
                    if ip_address == "28.0.6.1":  # this is the version number
                        continue
                    if "Ignore " in line and " by pi" in line:
                        if ip_address not in ignored_ips:
                            ignored_ips[ip_address] = [line]
                    elif " Found " in line:
                        if ip_address not in found_ips:
                            found_ips[ip_address] = [line]
                    elif "banned" in line.lower():
                        if ip_address not in banned_ips:
                            banned_ips[ip_address] = [line]
                    else:
                        if ip_address not in else_ips:
                            else_ips[ip_address] = [line]
                        else:
                            else_ips[ip_address].append(line)

        ufw_blocked = get_ufw_logs(hours)

        if not (ignored_ips or found_ips or banned_ips or ufw_blocked):
            raise SystemExit()

        if ignored_ips:
            p("\nIgnored IPs:")
            for k, v in ignored_ips.items():
                p(f"- {k}:")
                for li in v:
                    p("    - " + li)
        if found_ips:
            p("\nFound IPs:")
            for k, v in found_ips.items():
                p(f"- {k}:")
                for li in v:
                    p("    - " + li)
        if banned_ips:
            p("\nBanned IPs:")
            for k, v in banned_ips.items():
                p(f"- {k}:")
                for li in v:
                    p("    - " + li)

        p("IP recap:")
        if ignored_ips:
            p("\nIgnored IPs:")
            p(list(ignored_ips.keys()))
        if found_ips:
            p("\nFound IPs:")
            p(list(found_ips.keys()))
        if banned_ips:
            p("\nBanned IPs:")
            p(list(banned_ips.keys()))
        if else_ips:
            p("\nElse IPs:")
            p(list(else_ips.keys()))

        p("\nBanned by ufw:")
        p(ufw_blocked)

    else:
        p("Failed to retrieve logs.")
    return content

if __name__ == "__main__":
    out = fire.Fire(main)
    send_notif(
        message=out,
        topic=os.environ["NTFY_TOPIC"],
        title="Fail2Ban - Status"
    )
