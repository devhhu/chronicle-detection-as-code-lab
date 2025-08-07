import json
import os
from pathlib import Path
from collections import defaultdict
from datetime import datetime, timedelta, timezone


BASE_DIR = Path(__file__).resolve().parent.parent
LOG_DIR = BASE_DIR / "processed-logs"
ALERTS_DIR = BASE_DIR / "alerts"
ALERTS_DIR.mkdir(exist_ok=True)


def current_utc_time():
    return datetime.now(timezone.utc).isoformat()


try:
    log_file = next(LOG_DIR.rglob("*.log"))
except StopIteration:
    print("No log file found.")
    exit(1)

def load_all_logs():
    with open(log_file, "r") as f:
        return [json.loads(line) for line in f if line.strip().startswith("{")]


def match_suspicious_admin_login(event):
    is_admin = event.get("geo", {}).get("is_admin", False)
    event_type = event.get("event_type")
    country = event.get("geo", {}).get("country")
    return event_type == "LOGIN" and is_admin and country in {"RU", "CN", "IN"}


def match_impossible_travel(events):
    user_logins = defaultdict(list)
    suspicious = []

    for event in events:
        try:
            timestamp = datetime.fromisoformat(event["metadata"]["event_timestamp"])
            email = event["principal"]["email_addresses"][0]
            country = event["geo"]["country"]
            user_logins[email].append((timestamp, country, event))
        except:
            continue

    for email, logs in user_logins.items():
        logs.sort()
        for i in range(1, len(logs)):
            t1, c1, e1 = logs[i - 1]
            t2, c2, e2 = logs[i]
            if c1 != c2 and (t2 - t1) < timedelta(minutes=5):
                suspicious.append((e1, e2))
    return suspicious


def match_thresholded_logins(events, threshold=3, window_minutes=10):
    country_buckets = defaultdict(list)
    alerts = []

    for event in events:
        try:
            if event.get("event_type") != "LOGIN":
                continue
            timestamp = datetime.fromisoformat(event["metadata"]["event_timestamp"])
            country = event["geo"]["country"]
            country_buckets[country].append((timestamp, event))
        except:
            continue
# Sliding window here
    for country, logs in country_buckets.items():
        logs.sort()
        window = timedelta(minutes=window_minutes)
        for i in range(len(logs)):
            count = 1
            window_logs = [logs[i][1]]
            for j in range(i + 1, len(logs)):
                if logs[j][0] - logs[i][0] <= window:
                    count += 1
                    window_logs.append(logs[j][1])
                else:
                    break
            if count >= threshold:
                alerts.append({
                    "rule_name": f"High Volume Login from {country}",
                    "severity": "MEDIUM",
                    "event_count": count,
                    "events": window_logs,
                    "alert_generated_at": current_utc_time()
                })
                break  # Only one alert per country
    return alerts


if __name__ == "__main__":
    all_logs = load_all_logs()

    if not all_logs:
        print("No log entries found.")
        exit(0)
        

    suspicious_admins = list(filter(match_suspicious_admin_login, all_logs))
    print(f"\n[+] Suspicious Admin Logins: {len(suspicious_admins)}")
    print(json.dumps(suspicious_admins, indent=2))

    with open(ALERTS_DIR / "suspicious_admin_login_alerts.json", "w") as f:
        json.dump({
            "rule_name": "Suspicious Admin Login",
            "severity": "HIGH",
            "alert_generated_at": current_utc_time(),
            "alerts": suspicious_admins
        }, f, indent=2)


    impossible_travels = match_impossible_travel(all_logs)
    print(f"\n[+] Impossible Travel Events: {len(impossible_travels)}")

    formatted = []
    for e1, e2 in impossible_travels:
        formatted.append({
            "rule_name": "Impossible Travel",
            "severity": "CRITICAL",
            "matched_events": [e1, e2],
            "alert_generated_at": current_utc_time()
        })

    with open(ALERTS_DIR / "impossible_travel_alerts.json", "w") as f:
        json.dump(formatted, f, indent=2)


    country_alerts = match_thresholded_logins(all_logs)
    print(f"\n[+] Thresholded Login Bursts by Country: {len(country_alerts)}")

    with open(ALERTS_DIR / "high_volume_login_alerts.json", "w") as f:
        json.dump(country_alerts, f, indent=2)
