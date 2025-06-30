# Security Event Detection Pipeline

A mini-pipeline to detect suspicious activities from system logs, with real-time alerting and a hacker-themed dashboard.

## Pipeline Schema

![Editor _ Mermaid Chart-2025-06-30-205308](https://github.com/user-attachments/assets/fb512fa9-0c39-42c1-9f3b-9101b51cc8c8)


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
