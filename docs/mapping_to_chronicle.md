# Mapping Simulation to Google Chronicle (SecOps)

This project simulates a detection-as-code workflow similar to Google Chronicle.

## 🔗 Data Format
All logs are emitted in a **UDM-like structure** inspired by Google's Unified Data Model.

Example:
```json
{
  "metadata": {
    "event_timestamp": "2025-08-06T12:00:00Z"
  },
  "product": "gcp",
  "event_type": "LOGIN",
  "principal": {
    "email_addresses": ["user1@example.com"],
    "ip": "3.5.6.7",
    "hostname": "host-3-5-6-7.google.com"
  },
  "geo": {
    "country": "RU",
    "is_admin": true
  },
  "network": {
    "asn": "AS12389",
    "asn_name": "Rostelecom"
  },
  "security_result": {
    "severity": "HIGH",
    "rule_name": "None"
  }
}
