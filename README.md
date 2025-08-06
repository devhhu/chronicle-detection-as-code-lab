
This repo emulates how you would potentially leverage Google SecOps with a Detection-as-Code (DaC) approach:

* Sample UDM event generation
* Log forwarding via Fluentd
* Python detection engine to process and alert

* Detection logic in YARA-L format
* Terraform IaC to manage rules and data sources
* Simulated GitOps model for lifecycle management

### How It Works:

This is a full end-to-end simulation of what a Detection-as-Code pipeline would look like, and how it can be used to leverage Google SecOps. It involves:

* UDM Log Generation: Simulates endpoint or authentication events
* Fluentd Forwarding: Parses and forwards structured logs
* Detection Matching: Python engine applies YARA-L logic
* Alert Output: Alerts written to /alerts folder per rule
* Terraform Support: Template for how this would be leveraged in a production environment


### High-Level Architecture:
```mermaid
flowchart LR
  %% === Preprocessing & Environment Setup ===
  subgraph ENV_SETUP [Preprocessing and Environment Setup]
    A1[log_emitter.py - Generates fake UDM logs] --> A2[Fluentd - Forwards logs]
    A2 --> A3[processed-logs - Raw UDM log files]
  end

  %% === Detection Pipeline & Alert Management ===
  subgraph DETECTION_PIPELINE [Detection and Alert Management]
    A3 --> B1[match_logs_from_fluentd.py - Detection engine]
    B2[rules - YARA-L detection rules] --> B1
    B1 --> B3[alerts - JSON alerts output]
    B3 --> B4[Security Analyst - Reviews alerts via UI]

    subgraph DOCS [Documentation]
      B5[mapping_to_chronicle.md - UDM field reference]
      B6[udm_fields_reference.md - Terraform field mapping]
    end
    B5 --> B1
    B6 --> B1
  end

  %% === Terraform ===
  subgraph INFRA_AUTOMATION [Chronicle using Terraform]
    C1[log_source.tf - Mock datasources and UDM fields]
    C2[yara_rules.tf - Manage YARA-L rules]
    C1 --> C3[Chronicle SecOps UI]
    C2 --> C3

    C2 --> C4[Rule lifecycle - GitHub pull requests]
    C4 --> B2
    C4 --> C3
    C3 --> B4
  end

```

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

