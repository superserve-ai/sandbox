output "contract" {
  value = {
    project_id  = var.project_id
    region      = var.region
    network     = google_compute_network.tenant.id
    subnetwork  = google_compute_subnetwork.tenant.id
    egress      = "ALL_TRAFFIC"
    subnet_cidr = var.subnet_cidr
    capacity = {
      usable_ipv4                = 4092
      max_steady_instances       = 896
      max_simultaneous_revisions = 2
      addresses_per_instance     = 2
      reserved_headroom          = 508
      allocation_block           = 16
    }
    cells = { for id, cell in var.db_cells : id => {
      network_tag = "qm-db-${id}-client"
      private_ip  = cell.private_ip
      port        = 5432
      firewall    = google_compute_firewall.cell[id].id
    } }
    control_db_denied_cidrs = var.control_db_cidrs
  }
}
