import json
from pathlib import Path
from collections import defaultdict
from datetime import datetime, timedelta
import yaml

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
ALERTS_DIR = Path(__file__).resolve().parent.parent / "alerts"
ALERTS_DIR.mkdir(exist_ok=True)


LOG_DIR = Path(__file__).resolve().parent.parent / "processed-logs"

def load_yaml_rules():
    rules = []
    for rule_file in RULES_DIR.glob("*.yml"):
        with open(rule_file) as f:
            rules.append(yaml.safe_load(f))
    return rules

def match_suspicious_admin_login(event):
    try:
        is_admin = event.get("geo", {}).get("is_admin")
        event_type = event.get("event_type")
        country = event.get("geo", {}).get("country")
        return event_type == "LOGIN" and is_admin is True and country not in ["GB", "US", "CA"]
    except Exception as e:
        return False

def match_impossible_travel(events):
    user_logins = defaultdict(list)
    suspicious = []

    for event in events:
        try:
            timestamp = datetime.fromisoformat(event["metadata"]["event_timestamp"].replace("Z", "+00:00"))
            email = event["principal"]["email_addresses"][0]
            country = event["geo"]["country"]
            user_logins[email].append((timestamp, country, event))
        except Exception:
            continue

    for email, logs in user_logins.items():
        logs.sort()
        for i in range(1, len(logs)):
            t1, c1, e1 = logs[i - 1]
            t2, c2, e2 = logs[i]
            if c1 != c2 and (t2 - t1) < timedelta(minutes=5):
                suspicious.append((e1, e2))
    return suspicious

def load_all_logs():
    logs = []
    for file in LOG_DIR.rglob("*.log"):
        try:
            with open(file, "r") as f:
                for line in f:
                    if line.strip().startswith("{"):
                        logs.append(json.loads(line))
        except Exception:
            continue
    return logs
def alert(event, rule_title, severity):
    alert = {
        "rule": rule_title,
        "severity": severity,
        "timestamp": event["metadata"]["event_timestamp"],
        "principal": event["principal"]["email_addresses"][0],
        "country": event["geo"]["country"],
        "ip": event["network"]["ip"]
    }
    print("\n[+]------ New detection -----[+]")
    print(json.dumps(alert, indent=2))

if __name__ == "__main__":
    all_logs = load_all_logs()
    if not all_logs:
        print("No log entries found.")
        exit(0)

    rules = load_yaml_rules()

    for rule in rules:
        print(f"\n== Running Rule: {rule['name']} ==")
        if not rule.get("enabled", False):
            print(f"Rule {rule['name']} is disabled.")
            continue

        logic = rule.get("logic")
        alerts = []

        if logic == "impossible_travel":
            for e1, e2 in match_impossible_travel(all_logs):
                alert = {
                    "rule_name": rule["name"],
                    "detected_at": datetime.utcnow().isoformat() + "Z",
                    "details": {
                        "email": e1["principal"]["email_addresses"][0],
                        "countries": [e1["geo"]["country"], e2["geo"]["country"]],
                        "time_diff_minutes": (
                            datetime.fromisoformat(e2["metadata"]["event_timestamp"]) -
                            datetime.fromisoformat(e1["metadata"]["event_timestamp"])
                        ).seconds // 60
                    },
                    "severity": rule["severity"]
                }
                alerts.append(alert)

        elif logic == "suspicious_admin_login":
            for e in filter(match_suspicious_admin_login, all_logs):
                alert = {
                    "rule_name": rule["name"],
                    "detected_at": datetime.utcnow().isoformat() + "Z",
                    "details": {
                        "email": e["principal"]["email_addresses"][0],
                        "country": e["geo"]["country"]
                    },
                    "severity": rule["severity"]
                }
                alerts.append(alert)

        if alerts:
            for a in alerts:
                print(json.dumps(a, indent=2))

            alert_file = ALERTS_DIR / f"{logic}_alerts.json"
            with open(alert_file, "a") as f:
                for a in alerts:
                    f.write(json.dumps(a) + "\n")
        else:
            print("No alerts generated.")

