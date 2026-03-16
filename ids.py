import re
import json
import time
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
                raw_time = match.group(1)
                username = match.group(2)
                ip       = match.group(3)

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


def ml_anomaly_detection(failed_attempts):
    """
    Uses Isolation Forest (unsupervised ML model)
    to detect anomalies in login attempt patterns.
    Works alongside rule-based detection to catch
    subtle attacks that stay under the threshold.
    """
    from sklearn.ensemble import IsolationForest
    import numpy as np

    if len(failed_attempts) < 3:
        print("[~] Not enough data for ML analysis (need 3+ entries)")
        return []

    # Build feature matrix — convert each IP's behavior into numbers
    ip_features = {}

    for attempt in failed_attempts:
        ip = attempt["ip"]
        if ip not in ip_features:
            ip_features[ip] = {
                "times":     [],
                "usernames": set()
            }
        ip_features[ip]["times"].append(
            attempt["time"].hour * 3600 +
            attempt["time"].minute * 60 +
            attempt["time"].second
        )
        ip_features[ip]["usernames"].add(attempt["username"])

    # Convert to feature vectors
    # Each IP becomes: [attempt_count, time_spread, unique_users, avg_interval]
    ips = []
    X   = []

    for ip, data in ip_features.items():
        if ip in WHITELIST:
            continue

        times         = sorted(data["times"])
        attempt_count = len(times)
        time_spread   = times[-1] - times[0] if len(times) > 1 else 0
        unique_users  = len(data["usernames"])
        avg_interval  = time_spread / attempt_count if attempt_count > 1 else 0

        ips.append(ip)
        X.append([attempt_count, time_spread, unique_users, avg_interval])

    if len(X) < 2:
        print("[~] Not enough IPs for ML comparison (need 2+)")
        return []

    # Train Isolation Forest
    # contamination = expected proportion of anomalies in the data
    model       = IsolationForest(contamination=0.3, random_state=42)
    X_array     = np.array(X)
    predictions = model.fit_predict(X_array)
    scores      = model.decision_function(X_array)

    # Collect anomalies — IsolationForest returns -1 for anomalies
    ml_alerts = []

    for i, prediction in enumerate(predictions):
        if prediction == -1:
            ml_alerts.append({
                "ip":            ips[i],
                "attempt_count": int(X[i][0]),
                "time_spread":   int(X[i][1]),
                "unique_users":  int(X[i][2]),
                "avg_interval":  round(X[i][3], 1),
                "anomaly_score": round(float(scores[i]), 4)
            })
            print(f"[ML] Anomaly detected — {ips[i]} "
                  f"(score: {scores[i]:.4f}, "
                  f"attempts: {int(X[i][0])}, "
                  f"users targeted: {int(X[i][2])})")

    return ml_alerts


def generate_html_report(attacks, ml_alerts=None, filepath="report.html"):
    """
    Generates a clean HTML threat report
    from the list of detected attacks and ML anomalies.
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if ml_alerts is None:
        ml_alerts = []

    # Build rule-based attack rows
    if attacks:
        rows = ""
        for i, attack in enumerate(attacks, 1):
            severity = attack["severity"]

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

    # Build ML anomaly rows
    if ml_alerts:
        ml_rows = ""
        for alert in ml_alerts:
            ml_rows += f"""
            <tr>
                <td><code>{alert['ip']}</code></td>
                <td>{alert['attempt_count']}</td>
                <td>{alert['unique_users']}</td>
                <td>{alert['avg_interval']}s</td>
                <td>{alert['anomaly_score']}</td>
                <td><span style="background:#ff4444;color:white;padding:3px 10px;border-radius:12px;font-size:12px;">ANOMALY</span></td>
            </tr>
            """
    else:
        ml_rows = '<tr><td colspan="6" style="text-align:center;color:#888;">No ML anomalies detected</td></tr>'

    # Build the full HTML page
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
            grid-template-columns: repeat(4, 1fr);
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

        .card .number.ml {{
            color: #7c3aed;
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
            margin-bottom: 24px;
        }}

        .table-wrap h2 {{
            padding: 20px 24px;
            font-size: 14px;
            letter-spacing: 0.1em;
            text-transform: uppercase;
            color: #00e5ff;
            border-bottom: 1px solid #1e2535;
        }}

        .table-wrap h2.ml {{
            color: #7c3aed;
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
        <h1>SSH Brute-Force IDS — Threat Report</h1>
        <p>Generated: {now} &nbsp;|&nbsp; Log file: {LOG_FILE} &nbsp;|&nbsp;
        Threshold: {THRESHOLD} attempts / {TIME_WINDOW}s</p>
    </div>

    <div class="cards">
        <div class="card">
            <div class="number">{len(attacks)}</div>
            <div class="label">Rule Alerts</div>
        </div>
        <div class="card">
            <div class="number ml">{len(ml_alerts)}</div>
            <div class="label">ML Anomalies</div>
        </div>
        <div class="card">
            <div class="number">{THRESHOLD}</div>
            <div class="label">Threshold</div>
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
        <h2>// Rule-Based Detection</h2>
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

    <div class="table-wrap">
        <h2 class="ml">// ML Anomaly Detection</h2>
        <table>
            <thead>
                <tr>
                    <th>IP Address</th>
                    <th>Attempts</th>
                    <th>Unique Users</th>
                    <th>Avg Interval</th>
                    <th>Anomaly Score</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                {ml_rows}
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


def live_monitor(filepath):
    """
    Watches auth.log in real time.
    Every new line added to the file is
    immediately analyzed for brute-force patterns.
    Runs forever until user presses Ctrl+C.
    """
    print("\n[*] SSH Brute-Force IDS — Live Monitoring Mode")
    print("[*] " + "─" * 42)
    print(f"[*] Watching {filepath} for new entries...")
    print("[*] Press Ctrl+C to stop\n")

    # Tracks failed attempts per IP in memory
    live_attempts = defaultdict(list)

    # Same regex pattern as parse_log
    pattern = r'(\w{3}\s+\d+\s+\d+:\d+:\d+).*Failed password for (\w+) from (\d+\.\d+\.\d+\.\d+)'

    # Open the file and jump to the END
    with open(filepath, "r") as f:
        f.seek(0, 2)

        try:
            while True:
                line = f.readline()

                # No new line yet — wait and try again
                if not line:
                    time.sleep(0.5)
                    continue

                match = re.search(pattern, line)
                if not match:
                    continue

                raw_time = match.group(1)
                username = match.group(2)
                ip       = match.group(3)

                # Skip whitelisted IPs
                if ip in WHITELIST:
                    continue

                time_obj = datetime.strptime(raw_time, "%b %d %H:%M:%S")

                live_attempts[ip].append({
                    "time":     time_obj,
                    "username": username
                })

                count = len(live_attempts[ip])
                print(f"[{time_obj.strftime('%H:%M:%S')}] "
                      f"Failed login #{count} — {ip} tried user '{username}'")

          
                attempts = sorted(live_attempts[ip], key=lambda x: x["time"])
                window   = []

                for attempt in attempts:
                    time_diff = (time_obj - attempt["time"]).seconds
                    if time_diff <= TIME_WINDOW:
                        window.append(attempt)

                # If threshold reached → fire alert
                if len(window) >= THRESHOLD:
                    attack = {
                        "ip":         ip,
                        "count":      len(window),
                        "first_seen": window[0]["time"].strftime("%H:%M:%S"),
                        "last_seen":  window[-1]["time"].strftime("%H:%M:%S"),
                        "usernames":  list(set([a["username"] for a in window])),
                        "severity":   "HIGH" if len(window) >= 10 else "MEDIUM" if len(window) >= 7 else "LOW"
                    }

                    print_alert(attack)
                    save_alerts([attack], ALERT_FILE)
                    generate_html_report([attack])

                    
                    live_attempts[ip] = []

        except KeyboardInterrupt:
            print("\n\n[*] Monitoring stopped by user.")
            print("[*] Final report saved to report.html\n")


def main():
    print("\n[*] SSH Brute-Force Intrusion Detection System")
    print("[*] " + "─" * 42)
    print("[*] Select mode:")
    print("[*]   1 — Scan mode    (analyze existing log file)")
    print("[*]   2 — Monitor mode (watch log file live)")
    print()

    mode = input("    Enter 1 or 2: ").strip()

    if mode == "1":
        print(f"\n[*] Reading {LOG_FILE}...")

        # Step 1 — Parse the log
        failed_attempts = parse_log(LOG_FILE)
        print(f"[*] Found {len(failed_attempts)} failed login attempts")

        # Step 2 — Rule-based detection
        print(f"\n[*] Running rule-based detection...")
        print(f"[*] Threshold={THRESHOLD}, window={TIME_WINDOW}s")
        attacks = detect_bruteforce(failed_attempts)

        if attacks:
            for attack in attacks:
                print_alert(attack)
        else:
            print("[✓] Rule-based: No threats detected")

        # Step 3 — ML anomaly detection
        print(f"\n[*] Running ML anomaly detection...")
        ml_alerts = ml_anomaly_detection(failed_attempts)

        if not ml_alerts:
            print("[✓] ML detection: No anomalies detected")

        # Step 4 — Compare results
        print("\n" + "─" * 45)
        print("  DETECTION COMPARISON")
        print("─" * 45)
        print(f"  Rule-based alerts : {len(attacks)}")
        print(f"  ML anomaly alerts : {len(ml_alerts)}")

        rule_ips = set(a["ip"] for a in attacks)
        ml_ips   = set(a["ip"] for a in ml_alerts)

        only_rule = rule_ips - ml_ips
        only_ml   = ml_ips - rule_ips
        both      = rule_ips & ml_ips

        if both:
            print(f"  Caught by BOTH    : {', '.join(both)}")
        if only_rule:
            print(f"  Rule-based only   : {', '.join(only_rule)}")
        if only_ml:
            print(f"  ML only (subtle)  : {', '.join(only_ml)}")
        print("─" * 45)

        # Step 5 — Save and report
        save_alerts(attacks, ALERT_FILE)
        generate_html_report(attacks, ml_alerts)
        print(f"\n[!] Scan complete — "
              f"{len(attacks)} rule alert(s), "
              f"{len(ml_alerts)} ML anomaly(s)\n")

    elif mode == "2":
        live_monitor(LOG_FILE)

    else:
        print("\n[!] Invalid option. Please enter 1 or 2.\n")


#Entry point
if __name__ == "__main__":
    main()