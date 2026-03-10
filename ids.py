import re
import json
from datetime import datetime
from collections import defaultdict

# ─── CONFIGURATION ────────────────────────────────────────
LOG_FILE    = "auth.log"
ALERT_FILE  = "alerts.json"
THRESHOLD   = 5
TIME_WINDOW = 60
WHITELIST   = ["192.168.1.10"]
# ──────────────────────────────────────────────────────────


def parse_log(filepath):
    """
    Reads auth.log line by line.
    Returns a list of failed attempts.
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
    attempts_by_ip = defaultdict(list)
    for attempt in failed_attempts:
        attempts_by_ip[attempt["ip"]].append(attempt)

    attacks_detected = []

    for ip, attempts in attempts_by_ip.items():

        # Skip whitelisted IPs
        if ip in WHITELIST:
            print(f"[~] Skipping whitelisted IP: {ip}")
            continue

        # Sort attempts by time oldest first
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

    print(f"[*] Alerts saved to {filepath}")


def generate_html_report(attacks, filepath="report.html"):
    """
    Generates a clean HTML threat report
    from the list of detected attacks.
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Build the attack rows
    if attacks:
        rows = ""
        for i, attack in enumerate(attacks, 1):
            severity = attack["severity"]

            # Color code by severity
            if severity == "HIGH":
                badge = '<span style="background:#ff4444;color:white;padding:3px 10px;border-radius:12px;font-size:12px;">HIGH</span>'
            elif severity == "MEDIUM":
                badge = '<span style="background:#ff9900;color:white;padding:3px 10px;border-radius:12px;font-size:12px;">MEDIUM</span>'
            else:
                badge = '<span style="background:#2196F3;color:white;padding:3px 10px;border-radius:12px;font-size:12px;">LOW</span>'

            rows += f"""
            <tr>
                <td>{i}</td>
                <td><code>{attack['ip']}</code></td>
                <td>{attack['count']}</td>
                <td>{attack['first_seen']}</td>
                <td>{attack['last_seen']}</td>
                <td>{', '.join(attack['usernames'])}</td>
                <td>{badge}</td>
            </tr>
            """
        summary_color = "#ff4444"
        summary_text  = f"{len(attacks)} Threat(s) Detected"
    else:
        rows = '<tr><td colspan="7" style="text-align:center;color:#888;">No threats detected</td></tr>'
        summary_color = "#4CAF50"
        summary_text  = "No Threats Detected"

    # full HTML page
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SSH IDS — Threat Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}

        body {{
            font-family: 'Segoe UI', sans-serif;
            background: #0a0d14;
            color: #e2e8f0;
            padding: 40px 20px;
        }}

        .container {{
            max-width: 900px;
            margin: 0 auto;
        }}

        .header {{
            background: #111520;
            border: 1px solid #1e2535;
            border-top: 3px solid #00e5ff;
            border-radius: 8px;
            padding: 30px;
            margin-bottom: 24px;
        }}

        .header h1 {{
            font-size: 24px;
            color: #00e5ff;
            margin-bottom: 6px;
        }}

        .header p {{
            color: #64748b;
            font-size: 14px;
        }}

        .cards {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 16px;
            margin-bottom: 24px;
        }}

        .card {{
            background: #111520;
            border: 1px solid #1e2535;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }}

        .card .number {{
            font-size: 32px;
            font-weight: bold;
            color: #00e5ff;
        }}

        .card .label {{
            font-size: 12px;
            color: #64748b;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            margin-top: 4px;
        }}

        .status {{
            background: {summary_color}22;
            border: 1px solid {summary_color};
            border-radius: 8px;
            padding: 16px 24px;
            margin-bottom: 24px;
            font-weight: bold;
            color: {summary_color};
            font-size: 16px;
        }}

        .table-wrap {{
            background: #111520;
            border: 1px solid #1e2535;
            border-radius: 8px;
            overflow: hidden;
        }}

        .table-wrap h2 {{
            padding: 20px 24px;
            font-size: 14px;
            letter-spacing: 0.1em;
            text-transform: uppercase;
            color: #00e5ff;
            border-bottom: 1px solid #1e2535;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
        }}

        th {{
            background: #161b28;
            padding: 12px 16px;
            text-align: left;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            color: #64748b;
        }}

        td {{
            padding: 14px 16px;
            border-bottom: 1px solid #1e2535;
            font-size: 14px;
        }}

        tr:last-child td {{ border-bottom: none; }}
        tr:hover td {{ background: #161b28; }}

        code {{
            background: #1e2535;
            padding: 2px 8px;
            border-radius: 4px;
            font-family: monospace;
            color: #00e5ff;
        }}

        .footer {{
            text-align: center;
            margin-top: 24px;
            color: #64748b;
            font-size: 12px;
        }}
    </style>
</head>
<body>
<div class="container">

    <div class="header">
        <h1>⚡ SSH Brute-Force IDS — Threat Report</h1>
        <p>Generated: {now} &nbsp;|&nbsp; Log file: {LOG_FILE} &nbsp;|&nbsp;
        Threshold: {THRESHOLD} attempts / {TIME_WINDOW}s</p>
    </div>

    <div class="cards">
        <div class="card">
            <div class="number">{len(attacks)}</div>
            <div class="label">Threats Detected</div>
        </div>
        <div class="card">
            <div class="number">{THRESHOLD}</div>
            <div class="label">Alert Threshold</div>
        </div>
        <div class="card">
            <div class="number">{TIME_WINDOW}s</div>
            <div class="label">Time Window</div>
        </div>
    </div>

    <div class="status">
        {'⚠️' if attacks else '✅'} &nbsp; {summary_text}
    </div>

    <div class="table-wrap">
        <h2>// Attack Details</h2>
        <table>
            <thead>
                <tr>
                    <th>#</th>
                    <th>IP Address</th>
                    <th>Attempts</th>
                    <th>First Seen</th>
                    <th>Last Seen</th>
                    <th>Targeted Users</th>
                    <th>Severity</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </div>

    <div class="footer">
        SSH Brute-Force IDS &nbsp;|&nbsp; Built with Python &nbsp;|&nbsp;
        github.com/mayssgh/ssh-ids-project
    </div>

</div>
</body>
</html>"""

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[*] HTML report saved to {filepath}")


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

    # Step 3 — Print alerts and generate outputs
    if attacks:
        for attack in attacks:
            print_alert(attack)
        save_alerts(attacks, ALERT_FILE)
        generate_html_report(attacks)
        print(f"\n[!] Scan complete — {len(attacks)} threat(s) detected.\n")
    else:
        save_alerts([], ALERT_FILE)
        generate_html_report([])
        print("\n[✓] Scan complete — No threats detected.\n")



if __name__ == "__main__":
    main()