
# Detection-as-Code Lab (Google SecOps-Inspired)

This project simulates the Detection-as-Code (DaC) lifecycle as it would operate in a Google Chronicle SecOps environment, all without needing access to a Chronicle license.

Instead, I’ve reverse-engineered the expected detection flow using:

* UDM-compatible synthetic logs
* Custom Python detection logic
* YAML/YARA-L rules
* Terraform-like IaC definitionsReference lists and CI-style simulation

The goal is to mirror a real-life cloud-scale detection pipeline and demonstrate deep understanding of how Chronicle rules, log ingestion, and alert triage work.

### Project Structure
```
.
├── `docker-log-generator/`      # Emits mock UDM logs to Fluentd
├── `fluentd/`                  # Collects and buffers logs locally
├── `processed-logs/udm_log/`    # Log sink (simulates Chronicle UDM ingestion)
├── `scripts/`                   # Custom Python logic to match logs with rules
├── `rules/`                     # YARA-L and YAML rule definitions
├── `reference_lists/`           # Chronicle-style reference lists (IP ranges, etc.)
├── `terraform/`                 # Example rule and datasource definitions (Chronicle-like)
├── `secops_rules.yaml`          # DaC-friendly YAML defining rules to deploy
├── `secops_reference_lists.yaml`
├── `alerts/`                    # Simulated alerts generated from matching rules
├── `docs/`                      # Technical documentation
├── `Makefile`                   # Easy CLI for bringing the system up/down
└── `tests/`                     # Rule test cases
```

### Project Goal

Engineering:
* Sample UDM event generation
* Log forwarding via Fluentd
* Python detection engine to process and alert

Detection Life Cycle Management:
* Detection logic in YARA-L format
* Terraform IaC to manage rules and data sources
* Simulated GitOps model for lifecycle management


### High-Level Architecture

<img width="1864" height="1004" alt="image" src="https://github.com/user-attachments/assets/b6de6b23-e013-4545-ae3c-bd855db7174b" />





#### Step 1: Log Generation
Logs are emitted by `docker-log-generator/log_emitter.py`, simulating user activity like `logins`, `admin changes`, `geolocation anomalies`, etc. The logs are already UDM-shaped (based on Chronicle’s Unified Data Model) and pushed to Fluentd:
```
{
  "metadata": {
    "event_timestamp": "2025-08-06T12:34:56Z",
    ...
  },
  "principal": {
    "ip": "8.8.8.8",
    "location": {
      "country_or_region": "RU"
    },
    ...
  },
  "security_result": {
    "action": "LOGIN_SUCCESS",
    ...
  }
}
```

#### Step 2: Log Parsing + Matching
Logs are consumed by a custom Python engine in `scripts/match_logs_from_fluentd.py`, which performs:

* UDM field normalization
* Matching UDM fields against rule conditions
* Cross-referencing with reference lists (e.g., internal IP ranges)
* Emitting alerts to the alerts/ folder

This simulates what Chronicle’s Detection Engine would do using the YARA-L rule format.


#### Step 3: Rules & Reference Lists
YAML/YARA-L Rules define detection logic:
```
rule: impossible_travel
condition: |
  principal.ip NOT IN private_ip_ranges.txt AND
  principal.location.country_or_region CHANGED_WITHIN 1 HOUR
severity: HIGH
type: anomaly
```
Reference list example (reference_lists/private_ip_ranges.txt):
```
10.0.0.0/8
192.168.0.0/16
```

#### Step 4: Alerts & Tests
If a match is found, alerts are generated to the `alerts/` folder in JSON format. You can also run test cases in `tests/` against your rules.


Step 5: Terraform Emulation
The `terraform/` folder simulates how you would deploy rules and data sources using the Chronicle API. Each rule can be defined in `.tf` files and governed via secops_rules.yaml.

In a real Chronicle deployment, these `.tf` files would use the Chronicle Terraform provider to push rules via API.


### Emulation Details:

Preprocessing:
* log_emitter.py generates random UDM-compliant logs.
* Events simulate IAM, endpoint, and network behaviors.

Fluentd:
* Acts like a real forwarder agent.
* Forwards logs to processed-logs/.

Detection Matching:
* match_logs_from_fluentd.py reads logs.
* Applies all rules from rules/*.yml.
* Outputs matching alerts to alerts/.

Alert Output:
* Alerts are deduplicated and throttled per source country.
* Output is timestamped and grouped.
* Alerts are visible as JSON objects with field references.

