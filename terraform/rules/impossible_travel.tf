resource "google_chronicle_rule" "impossible_travel" {
  rule_id   = "impossible_travel"
  rule_text = file("${path.module}/impossible_travel.yaral")
}

resource "google_chronicle_rule_deployment" "deploy_impossible_travel" {
  rule_id          = google_chronicle_rule.impossible_travel.rule_id
  deployment_name  = "impossible_travel_deployment"
  enable           = true
}
