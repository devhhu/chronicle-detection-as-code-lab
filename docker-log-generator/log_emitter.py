import json
import random
import time
import ipaddress
from datetime import datetime, timezone
from fluent import sender
from fluent import event

# Setup Fluentd connection (use service name as hostname in Docker)
sender.setup('log-emitter', host='fluentd', port=24224)

# === Country to CIDR Map for public IPs ===
country_ip_map = {
    "US": ["3.0.0.0/8", "13.52.0.0/16", "34.0.0.0/8"],
    "GB": ["51.140.0.0/14", "35.176.0.0/15"],
    "BR": ["170.246.0.0/16", "200.160.0.0/16"],
    "CN": ["101.89.0.0/16", "36.112.0.0/12"],
    "RU": ["95.163.0.0/16", "87.250.0.0/16"],
    "IN": ["103.27.0.0/16", "49.205.0.0/16"],
    "CA": ["142.112.0.0/16", "184.108.0.0/16"]
}

# === ASN Info ===
asn_info = {
    "US": ("AS15169", "Google LLC"),
    "GB": ("AS16509", "Amazon.com, Inc."),
    "BR": ("AS28573", "Claro S.A."),
    "CN": ("AS4808", "China Unicom"),
    "RU": ("AS12389", "Rostelecom"),
    "IN": ("AS55410", "Reliance Jio"),
    "CA": ("AS852", "TELUS Communications Inc.")
}

# === Email Pool ===
email_pool = [
    "user1@example.com",
    "user2@example.com",
    "user3@example.com",
    "user4@example.com",
    "user5@example.com"
]

# === Helper: Pick random public IP ===
def random_ip_from_cidr(cidr_block):
    net = ipaddress.IPv4Network(cidr_block)
    hosts = list(net.hosts())
    return str(random.choice(hosts))

# === Emit Logs ===
def emit_log():
    while True:
        timestamp = datetime.now(timezone.utc).isoformat()

        email = random.choice(email_pool)
        is_admin = random.choice([True, False])
        severity = random.choice(["LOW", "MEDIUM", "HIGH"])
        rule = "None"

        geo_code = random.choice(list(country_ip_map.keys()))
        cidr = random.choice(country_ip_map[geo_code])
        ip_address = random_ip_from_cidr(cidr)
        asn_number, asn_name = asn_info[geo_code]
        fake_rdns = f"host-{ip_address.replace('.', '-')}.{asn_name.lower().replace(' ', '')}.com"

        log = {
            "metadata": {
                "event_timestamp": timestamp,
                "ingested_timestamp": timestamp
            },
            "product": "gcp",
            "event_type": "LOGIN",
            "vendor_name": "Google",
            "principal": {
                "email_addresses": [email],
                "ip": ip_address,
                "hostname": fake_rdns
            },
            "geo": {
                "country": geo_code,
                "is_admin": is_admin
            },
            "network": {
                "asn": asn_number,
                "asn_name": asn_name,
                "ip": ip_address,
                "reverse_dns": fake_rdns
            },
            "security_result": {
                "severity": severity,
                "rule_name": rule
            }
        }

        print("Sending log:", json.dumps(log))
        event.Event('udm.login', log)  # This tag is matched in fluent.conf
        time.sleep(2)

if __name__ == "__main__":
    emit_log()
