```mermaid
flowchart TD
    subgraph Docker_Env [🧱 Docker Environment]
        A[📦 log_emitter.py <br> (Generates fake UDM logs)]
        B[🛠️ Fluentd <br> (Processes & forwards logs)]
    end

    subgraph Filesystem
        C[📁 processed-logs/ <br> (Raw UDM log files)]
        D[📁 rules/ <br> YARA-L rules (e.g., impossible_travel.yml)]
        E[📁 match_logs_from_fluentd.py <br> Detection engine]
        F[📁 alerts/ <br> JSON alerts (DaC output)]
    end

    subgraph Documentation
        G[📄 mapping_to_chronicle.md <br> (UDM mapping reference)]
        H[📄 udm_fields_reference.md <br> (Terraform data source mapping)]
    end

    subgraph Terraform_Infra
        I[🧾 log_source.tf <br> (Mock log source + UDM fields)]
        J[🔍 yara_rules.tf <br> (Sample YARA-L rules config)]
    end

    A -->|writes logs| C
    C --> B
    B -->|forwards logs| C

    C --> E
    E -->|matches against| D
    E -->|writes alerts| F

    D -->|Detection-as-Code| E
    F -->|alerts visible to| User[(👤 Security Engineer)]

    G --> User
    H --> I
    D --> J
    J -->|optional deployment| GoogleSecOps[(🧠 Chronicle UI)]

    click A "docker-log-generator/log_emitter.py" _blank
    click B "fluentd/fluent.conf" _blank
    click C "processed-logs/" _blank
    click D "rules/" _blank
    click E "scripts/match_logs_from_fluentd.py" _blank
    click F "alerts/" _blank
    click G "docs/mapping_to_chronicle.md" _blank
    click H "docs/udm_fields_reference.md" _blank
    click I "terraform/datasources/log_source.tf" _blank
    click J "terraform/rules/yara_rules.tf" _blank
```