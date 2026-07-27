resource "google_compute_subnetwork" "staging_connector" {
  project       = local.project_id
  region        = local.region
  name          = "rayai-staging-connector-subnet"
  network       = "projects/${local.project_id}/global/networks/rayai-staging-vpc"
  ip_cidr_range = "10.8.0.0/28"
  purpose       = "PRIVATE"

  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
    filter_expr          = "true"
  }
}
