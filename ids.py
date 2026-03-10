import re
import json
from datetime import datetime
from collections import defaultdict

LOG_FILE = "auth.log"
ALERT_FILE="alerts.json"
THRESHOLD=5
TIME_WINDOW=60
WHITELIST=["192.168.1.10"]

def parse_log(filepath):
    """
    Reads auth.log line by line.
    Returns a list of failed attempts:
    [
      { "ip": "192.168.1.105", "time": datetime_object, "user": "root" },
      ...
    ]
    """
    failed_attempts = []

    # This pattern extracts timestamp, username, and IP from each line
    pattern = r'(\w{3}\s+\d+\s+\d+:\d+:\d+).*Failed password for (\w+) from (\d+\.\d+\.\d+\.\d+)'

    with open(filepath, "r") as f:
        for line in f:
            match = re.search(pattern, line)
            if match:
                raw_time = match.group(1)   # "Mar  9 21:03:11"
                username = match.group(2)   # "root"
                ip       = match.group(3)   # "192.168.1.105"

                # Convert raw time string into a datetime object
                time_obj = datetime.strptime(raw_time, "%b %d %H:%M:%S")

                failed_attempts.append({
                    "ip":       ip,
                    "time":     time_obj,
                    "username": username
                })

    return failed_attempts

def detect_bruteforce(failed_attempts):
    """
    Groups failed attempts by IP address.
    For each IP, checks if THRESHOLD attempts
    happened within TIME_WINDOW seconds.
    Returns a list of confirmed attacks.
    """
    # Group all attempts by IP address
    # { "192.168.1.105": [attempt1, attempt2, ...], ... }
    attempts_by_ip = defaultdict(list)
    for attempt in failed_attempts:
        attempts_by_ip[attempt["ip"]].append(attempt)

    attacks_detected = []

    for ip, attempts in attempts_by_ip.items():

        # Skip whitelisted IPs
        if ip in WHITELIST:
            print(f"[~] Skipping whitelisted IP: {ip}")
            continue

        # Sort attempts by time (oldest first)
        attempts.sort(key=lambda x: x["time"])

        # Sliding window — check every group of attempts
        for i in range(len(attempts)):
            window = []

            for j in range(i, len(attempts)):
                time_diff = (attempts[j]["time"] - attempts[i]["time"]).seconds

                if time_diff <= TIME_WINDOW:
                    window.append(attempts[j])
                else:
                    break

            # If enough attempts in window → attack confirmed
            if len(window) >= THRESHOLD:
                attacks_detected.append({
                    "ip":         ip,
                    "count":      len(window),
                    "first_seen": window[0]["time"].strftime("%H:%M:%S"),
                    "last_seen":  window[-1]["time"].strftime("%H:%M:%S"),
                    "usernames":  list(set([a["username"] for a in window])),
                    "severity":   "HIGH" if len(window) >= 10 else "MEDIUM" if len(window) >= 7 else "LOW"
                })
                break  # one alert per IP is enough

    return attacks_detected

def print_alert(attack):
    """Prints a formatted alert to the terminal."""
    print("\n" + "═" * 45)
    print("         ⚠️  BRUTE FORCE DETECTED  ⚠️")
    print("═" * 45)
    print(f"  IP Address   : {attack['ip']}")
    print(f"  Attempts     : {attack['count']} in {TIME_WINDOW} seconds")
    print(f"  First Seen   : {attack['first_seen']}")
    print(f"  Last Seen    : {attack['last_seen']}")
    print(f"  Targets      : {', '.join(attack['usernames'])}")
    print(f"  Severity     : {attack['severity']}")
    print("═" * 45)


def save_alerts(attacks, filepath):
    """Saves all alerts to a JSON file."""
    output = {
        "scan_time":      datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_alerts":   len(attacks),
        "threshold_used": THRESHOLD,
        "time_window_s":  TIME_WINDOW,
        "alerts":         attacks
    }
    with open(filepath, "w") as f:
        json.dump(output, f, indent=4)

    print(f"\n[*] Alerts saved to {filepath}")


def main():
    print("\n[*] SSH Brute-Force Intrusion Detection System")
    print("[*] " + "─" * 42)
    print(f"[*] Reading {LOG_FILE}...")

    # Step 1 — Parse the log
    failed_attempts = parse_log(LOG_FILE)
    print(f"[*] Found {len(failed_attempts)} failed login attempts")

    # Step 2 — Run detection
    print(f"[*] Analyzing with threshold={THRESHOLD}, window={TIME_WINDOW}s...")
    attacks = detect_bruteforce(failed_attempts)

    # Step 3 — Print alerts
    if attacks:
        for attack in attacks:
            print_alert(attack)
        save_alerts(attacks, ALERT_FILE)
        print(f"\n[!] Scan complete — {len(attacks)} threat(s) detected.\n")
    else:
        print("\n[✓] Scan complete — No threats detected.\n")


if __name__ == "__main__":
    main()