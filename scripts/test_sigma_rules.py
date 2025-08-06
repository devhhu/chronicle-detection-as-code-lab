import json
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_PATH = os.path.join(BASE_DIR, "logs", "suspicious_admin_login.json")

def load_event(file_path):
    with open(file_path, "r") as f:
        return json.load(f)

def match_suspicious_admin_login(event):
    try:
        if (
            event.get("event_type") == "LOGIN" and
            event.get("is_admin") is True and
            event.get("geo_country_code") not in ["GB", "US", "CA"]
        ):
            return True
    except Exception as e:
        print(f"Error evaluating rule: {e}")
    return False

if __name__ == "__main__":
    log = load_event(LOG_PATH)
    result = match_suspicious_admin_login(log)
    
    if result:
        print("✅ MATCH: Rule triggered on event.")
        exit(0)
    else:
        print("❌ NO MATCH: Rule did not trigger.")
        exit(1)
