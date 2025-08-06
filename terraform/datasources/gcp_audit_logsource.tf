resource "google_chronicle_log_source" "simulated_gcp_logins" {
  log_source_id = "simulated-gcp-logins"
  display_name  = "Simulated GCP Logins for DaC Lab"
  log_type      = "GCP_LOGIN"
  description   = "Mock log source simulating Chronicle UDM login events for testing Detection-as-Code"
  labels = {
    environment = "demo"
    team        = "security"
  }

  field_mappings = [
    {
      source_field = "principal.email_addresses[0]"
      udm_field    = "principal.email_addresses"
      data_type    = "STRING"
    },
    {
      source_field = "geo.country"
      udm_field    = "principal.geo.country"
      data_type    = "STRING"
    },
    {
      source_field = "event_type"
      udm_field    = "metadata.event_type"
      data_type    = "STRING"
    },
    {
      source_field = "metadata.event_timestamp"
      udm_field    = "metadata.event_timestamp"
      data_type    = "TIMESTAMP"
    },
    {
      source_field = "network.ip"
      udm_field    = "principal.ip"
      data_type    = "IP_ADDRESS"
    },
    {
      source_field = "network.asn"
      udm_field    = "network.asn"
      data_type    = "STRING"
    },
    {
      source_field = "network.reverse_dns"
      udm_field    = "network.reverse_dns"
      data_type    = "STRING"
    }
  ]
}
