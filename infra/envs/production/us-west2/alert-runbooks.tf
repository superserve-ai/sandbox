module "alert_runbooks" {
  source = "../../../modules/alert-runbooks"

  runbook_base_url = var.alert_runbook_base_url
}
