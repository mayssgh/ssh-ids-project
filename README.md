# SSH Brute-Force Intrusion Detection System

A Python-based IDS script that parses Linux `auth.log` files to detect 
SSH brute-force attacks using sliding window analysis.

## How It Works

1. Parses every line of `auth.log` for failed SSH login attempts
2. Extracts IP address, username, and timestamp using regex
3. Groups attempts by IP and applies a sliding time window algorithm
4. Fires a structured alert when attempts exceed the threshold

## Detection Logic

| Parameter    | Default | Description                        |
|--------------|---------|------------------------------------|
| Threshold    | 5       | Failed attempts to trigger alert   |
| Time Window  | 60s     | Time window to count attempts in   |
| Whitelist    | []      | Trusted IPs — never alerted        |

## Usage
```bash
python ids.py
```

## Sample Output
```
⚠️  BRUTE FORCE DETECTED
IP Address   : 192.168.1.105
Attempts     : 7 in 60 seconds
First Seen   : 21:03:11
Last Seen    : 21:03:40
Severity     : LOW
```

## Alert Output

Alerts are saved to `alerts.json` in structured format:
```json
{
    "scan_time": "2026-03-09 21:15:00",
    "total_alerts": 2,
    "threshold_used": 5,
    "time_window_s": 60,
    "alerts": [...]
}
```

## Skills Demonstrated

- Python log parsing with regex
- Sliding window detection algorithm
- JSON structured alert output
- Security threshold tuning
- False positive reduction via IP whitelisting

## Tools Used

- Python 3 (no external dependencies)
- Linux auth.log format
- JSON for alert structuring