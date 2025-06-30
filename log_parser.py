import re
from datetime import datetime
from collections import defaultdict
import json
import os
import requests

TELEGRAM_BOT_TOKEN = "7982017843:AAHcg4PRcjqLOvQMKWM9606D7aF4O-vl8kU"
TELEGRAM_CHAT_ID = "1661451709"

def parse_auth_log_entry(log_line):
    match = re.search(r'Failed password for (\S+) from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port (\d+)', log_line)
    if match:
        username, ip_address, port = match.groups()
        return {
            "timestamp": datetime.now().isoformat(),
            "event_type": "failed_login",
            "username": username,
            "ip_address": ip_address,
            "port": int(port),
            "raw_log": log_line.strip()
        }
    return None

def parse_syslog_portscan_entry(log_line):
    match = re.search(r'SRC=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*DPT=(\d+).*PROTO=(TCP|UDP).*SYN', log_line)
    if match:
        src_ip, dest_port, protocol = match.groups()
        return {
            "timestamp": datetime.now().isoformat(),
            "event_type": "network_scan",
            "src_ip": src_ip,
            "dest_port": int(dest_port),
            "protocol": protocol,
            "raw_log": log_line.strip()
        }
    return None

def ingest_and_parse_logs(auth_log_path, syslog_path):
    parsed_events = []
    with open(auth_log_path, 'r') as f:
        for line in f:
            event = parse_auth_log_entry(line)
            if event:
                parsed_events.append(event)
    with open(syslog_path, 'r') as f:
        for line in f:
            event = parse_syslog_portscan_entry(line)
            if event:
                parsed_events.append(event)
    return parsed_events

def detect_failed_logins(events, threshold=5):
    failed_attempts = defaultdict(list)
    alerts = []
    for event in events:
        if event["event_type"] == "failed_login":
            ip = event["ip_address"]
            failed_attempts[ip].append(event)
            if len(failed_attempts[ip]) == threshold:
                alerts.append({
                    "alert_type": "Brute Force Detected",
                    "ip_address": ip,
                    "failed_attempts_count": len(failed_attempts[ip]),
                    "details": [f"User: {att['username']}, Port: {att['port']}" for att in failed_attempts[ip]],
                    "timestamp": event["timestamp"]
                })
    return alerts

def detect_port_scan(events, unique_port_threshold=3):
    scan_attempts = defaultdict(set)
    alerts = []
    for event in events:
        if event["event_type"] == "network_scan":
            src_ip = event["src_ip"]
            dest_port = event["dest_port"]
            scan_attempts[src_ip].add(dest_port)
            if len(scan_attempts[src_ip]) == unique_port_threshold:
                alerts.append({
                    "alert_type": "Port Scan Detected",
                    "src_ip": src_ip,
                    "unique_ports_scanned": len(scan_attempts[src_ip]),
                    "ports": list(scan_attempts[src_ip]),
                    "timestamp": event["timestamp"]
                })
    return alerts

ALERTS_FILE = "detected_alerts.json"

def store_alert(alert):
    alerts = []
    if os.path.exists(ALERTS_FILE):
        try:
            with open(ALERTS_FILE, 'r') as f:
                alerts = json.load(f)
        except json.JSONDecodeError:
            alerts = []
    alerts.append(alert)
    with open(ALERTS_FILE, 'w') as f:
        json.dump(alerts, f, indent=4)

def send_telegram_alert(alert_data):
    message = (
        f"\ud83d\udea8 *SECURITY ALERT* \ud83d\udea8\n\n"
        f"Type: `{alert_data['alert_type']}`\n"
        f"IP: `{alert_data.get('ip_address', alert_data.get('src_ip', 'N/A'))}`\n"
        f"Time: `{alert_data['timestamp']}`\n\n"
        f"Details:\n```json\n{json.dumps(alert_data, indent=2)}\n```"
    )
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "Markdown"
    }
    try:
        response = requests.post(url, json=payload)
        response.raise_for_status()
    except requests.exceptions.RequestException:
        pass

if __name__ == "__main__":
    auth_log = "simulated_auth.log"
    syslog_log = "simulated_syslog.log"
    events = ingest_and_parse_logs(auth_log, syslog_log)
    all_alerts = []
    all_alerts.extend(detect_failed_logins(events))
    all_alerts.extend(detect_port_scan(events))
    if all_alerts:
        for alert in all_alerts:
            print(alert)
            store_alert(alert)
            send_telegram_alert(alert)
    else:
        print("No new alerts detected.") 