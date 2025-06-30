import time
from datetime import datetime

AUTH_LOG_FILE = "simulated_auth.log"
PORTSCAN_LOG_FILE = "simulated_syslog.log"

def current_log_time():
    return datetime.now().strftime('%b %d %H:%M:%S')

def generate_auth_logs():
    with open(AUTH_LOG_FILE, 'w') as f:
        for i in range(1, 11):
            log = f"{current_log_time()} myhost sshd[12345]: Failed password for user{i} from 192.168.1.100 port 5000{i} ssh2\n"
            f.write(log)
            time.sleep(0.05)
        for i in range(1, 4):
            log = f"{current_log_time()} myhost sshd[67890]: Failed password for user_valid from 10.0.0.50 port 5000{i} ssh2\n"
            f.write(log)
            time.sleep(0.05)

def generate_portscan_logs():
    entries = [
        (22, 36675),
        (80, 36676),
        (443, 36677),
        (23, 36678),
        (3389, 36679),
    ]
    with open(PORTSCAN_LOG_FILE, 'w') as f:
        for port, log_id in entries:
            log = (
                f"{current_log_time()} myhost kernel: IN=eth0 OUT= MAC=... "
                f"SRC=172.16.0.1 DST=192.168.1.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 "
                f"ID={log_id} DF PROTO=TCP SPT=45678 DPT={port} WINDOW=29200 RES=0x00 SYN URGP=0\n"
            )
            f.write(log)
            time.sleep(0.05)

def main():
    print("Generating simulated logs...")
    generate_auth_logs()
    generate_portscan_logs()
    print(f"Logs generated: {AUTH_LOG_FILE} and {PORTSCAN_LOG_FILE}")

if __name__ == "__main__":
    main() 