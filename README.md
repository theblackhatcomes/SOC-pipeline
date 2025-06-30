# Security Event Detection Pipeline

A mini-pipeline to detect suspicious activities from system logs, with real-time alerting and a hacker-themed dashboard.

## Pipeline Schema

![Pipeline Schema](../Editor%20_%20Mermaid%20Chart-2025-06-30-205308.png)

## Features

- Simulates system logs for failed logins and port scans
- Parses and detects brute force and port scan attacks
- Sends real-time alerts via Telegram
- Stores alerts in JSON
- Live-updating hacker-themed web dashboard

## Quick Start

```sh
python simulate_logs.py
python log_parser.py
python dashboard.py
```

## License

MIT 