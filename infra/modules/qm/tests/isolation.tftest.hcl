mock_provider "google" {}

variables {
  project_id       = "example-qm-dev"
  region           = "us-west2"
  subnet_cidr      = "10.80.0.0/20"
  control_db_cidrs = ["10.90.0.2/32"]
  db_cells = {
    cell-01 = { private_ip = "10.91.0.2" }
    cell-02 = { private_ip = "10.91.0.3" }
  }
}

run "cell_boundary" {
  command = plan
  assert {
    condition = (
      google_compute_firewall.cell["cell-01"].destination_ranges == toset(["10.91.0.2/32"]) &&
      google_compute_firewall.cell["cell-01"].target_tags == toset(["qm-db-cell-01-client"]) &&
      google_compute_firewall.cell["cell-02"].target_tags == toset(["qm-db-cell-02-client"]) &&
      alltrue([for cell in google_compute_firewall.cell :
        length(cell.allow) == 1 && alltrue([for rule in cell.allow :
          rule.protocol == "tcp" && length(rule.ports) == 1 && contains(rule.ports, "5432")
        ])
      ])
    )
    error_message = "A cell policy must bind one persisted cell tag to one private endpoint on TCP 5432 only."
  }
  assert {
    condition = (
      google_compute_firewall.control[0].priority < google_compute_firewall.cell["cell-01"].priority &&
      google_compute_firewall.cell["cell-01"].priority < google_compute_firewall.private.priority &&
      google_compute_firewall.private.priority < google_compute_firewall.internet.priority &&
      google_compute_firewall.control[0].destination_ranges == toset(["10.90.0.2/32"]) &&
      alltrue([for firewall in [google_compute_firewall.control[0], google_compute_firewall.private] :
        length(firewall.deny) == 1 && alltrue([for rule in firewall.deny : rule.protocol == "all"])
      ]) &&
      alltrue([for range in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"] :
        contains(google_compute_firewall.private.destination_ranges, range)
      ]) &&
      length(coalesce(google_compute_firewall.private.target_tags, toset([]))) == 0 &&
      length(coalesce(google_compute_firewall.control[0].target_tags, toset([]))) == 0
    )
    error_message = "Control denial must override cell allows; untagged runtimes must still have private egress denied."
  }
  assert {
    condition = (
      google_compute_subnetwork.tenant.stack_type == "IPV4_ONLY" &&
      google_compute_router_nat.tenant.source_subnetwork_ip_ranges_to_nat == "LIST_OF_SUBNETWORKS"
    )
    error_message = "IPv6 or an unrelated subnet must not bypass the declared egress boundary."
  }
}

run "cell_without_control_contract" {
  command = plan
  variables {
    control_db_cidrs = []
  }
  expect_failures = [google_compute_firewall.cell]
}

run "duplicate_endpoint" {
  command = plan
  variables {
    db_cells = {
      cell-01 = { private_ip = "10.91.0.2" }
      cell-02 = { private_ip = "10.91.0.2" }
    }
  }
  expect_failures = [var.db_cells]
}
