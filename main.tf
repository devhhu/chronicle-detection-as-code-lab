module "secops_rules" {
  source = "./modules/secops_rules"
  rule_config_file = "secops_rules.yaml"
}

module "secops_references" {
  source = "./modules/secops_reference_lists"
  reference_config_file = "secops_reference_lists.yaml"
}
