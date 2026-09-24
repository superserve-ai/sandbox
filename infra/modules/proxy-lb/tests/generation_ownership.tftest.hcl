mock_provider "google" {}

variables {
  project_id  = "example-project"
  environment = "staging"
  region      = "us-central1"
  name        = "proxy-example"
}

run "legacy_has_no_ownership_resources" {
  command = plan

  assert {
    condition     = length(google_storage_bucket.generation_ownership) == 0
    error_message = "Legacy load balancers must not create generation ownership resources."
  }
}

run "cell_ownership_is_wired_and_durable" {
  command = plan

  variables {
    generation_cell = {
      zone            = "us-central1-a"
      instance        = "example-host"
      ip              = "192.0.2.10"
      network         = "example-network"
      subnetwork      = "example-subnetwork"
      target_tags     = ["example-proxy"]
      service_account = "example-proxy@example-project.iam.gserviceaccount.com"
      routes = {
        public = {
          protocol = "HTTP"
          listener = "public"
          probe    = "https://example.test/health"
          probe_ip = "192.0.2.1"
        }
        "public-tcp" = {
          protocol = "TCP"
          listener = "public"
          probe    = "https://example.test/health"
        }
        redirect = {
          protocol = "TCP"
          listener = "redirect"
          probe    = "http://example.test/health"
        }
      }
    }
  }

  assert {
    condition = toset(keys(google_compute_health_check.generation_tcp)) == toset(["public-tcp", "redirect"]) && alltrue([
      for check in google_compute_health_check.generation_tcp :
      length(check.tcp_health_check) == 1 &&
      check.tcp_health_check[0].port_specification == "USE_SERVING_PORT" &&
      length(check.http_health_check) == 0
    ])
    error_message = "TCP routes need dedicated USE_SERVING_PORT TCP health checks."
  }

  assert {
    condition = toset(keys(google_compute_health_check.generation_http)) == toset(["public"]) && alltrue([
      for check in google_compute_health_check.generation_http :
      length(check.http_health_check) == 1 &&
      check.http_health_check[0].port_specification == "USE_SERVING_PORT" &&
      check.http_health_check[0].response == "\"resolver_ready\":true" &&
      check.http_health_check[0].host == "proxy-readiness.invalid" &&
      length(check.tcp_health_check) == 0
    ])
    error_message = "HTTP-family routes need dedicated resolver-aware HTTP health checks."
  }

  assert {
    condition = (
      toset(google_project_iam_custom_role.generation[0].permissions) == toset([
        "compute.networkEndpointGroups.get",
        "compute.networkEndpointGroups.attachNetworkEndpoints",
        "compute.networkEndpointGroups.detachNetworkEndpoints",
      ]) &&
      toset(google_project_iam_custom_role.generation_support[0].permissions) == toset([
        "compute.instances.use",
        "compute.backendServices.get",
        "compute.zoneOperations.get",
      ])
    )
    error_message = "Endpoint mutation must be isolated from the controller's instance and health-check support permissions."
  }

  assert {
    condition = (
      google_project_iam_member.generation[0].condition[0].title == "Cell-owned proxy generation NEGs" &&
      google_project_iam_member.generation[0].condition[0].expression == "resource.type == 'compute.googleapis.com/NetworkEndpointGroup' && resource.name.startsWith('projects/example-project/zones/us-central1-a/networkEndpointGroups/proxy-example-')"
    )
    error_message = "The default must retain the existing fail-closed binding until supported cell isolation is validated."
  }

  assert {
    condition = (
      output.generation_rollout.ownership_bucket == google_storage_bucket.generation_ownership[0].name &&
      google_storage_bucket_iam_member.generation_ownership[0].bucket == output.generation_rollout.ownership_bucket &&
      google_storage_bucket_iam_member.generation_ownership[0].member == "serviceAccount:example-proxy@example-project.iam.gserviceaccount.com" &&
      google_storage_bucket_iam_member.generation_ownership[0].role == "roles/storage.objectUser"
    )
    error_message = "The controller manifest and bucket-scoped IAM must reference the same cell authority."
  }

  assert {
    condition = (
      !google_storage_bucket.generation_ownership[0].force_destroy &&
      length(google_storage_bucket.generation_ownership[0].lifecycle_rule) == 0 &&
      google_storage_bucket.generation_ownership[0].uniform_bucket_level_access &&
      google_storage_bucket.generation_ownership[0].public_access_prevention == "enforced"
    )
    error_message = "Cell ownership must remain private and must never expire automatically."
  }
}

run "frontend_addresses_are_preserved_in_manifest" {
  command = plan

  variables {
    generation_cell = {
      zone            = "us-central1-a"
      instance        = "example-host"
      ip              = "192.0.2.10"
      network         = "example-network"
      subnetwork      = "example-subnetwork"
      target_tags     = ["example-proxy"]
      service_account = "example-proxy@example-project.iam.gserviceaccount.com"
      routes = {
        public = {
          protocol = "HTTP"
          listener = "public"
          probe    = "https://example.test/health"
          probe_ip = "192.0.2.1"
        }
      }
    }
  }

  assert {
    condition     = output.generation_rollout.routes[0].probe_ip == "192.0.2.1"
    error_message = "The controller must probe the configured frontend address, preserving its normal hostname."
  }

  assert {
    condition = (
      toset(google_compute_firewall.generation[0].source_ranges) == toset(["35.191.0.0/16", "130.211.0.0/22"]) &&
      toset(one(google_compute_firewall.generation[0].allow).ports) == toset(["5007", "5008", "5100", "5101", "5110", "5111"])
    )
    error_message = "LB generation ingress must retain restricted health-check sources while admitting legacy bootstrap and generation listeners without exposing private peer or local-target ports."
  }
}

run "staging_can_explicitly_allow_project_wide_endpoints" {
  command = plan
  variables {
    staging_project_wide_generation_endpoints = true
    generation_cell = {
      zone            = "us-central1-a"
      instance        = "example-host"
      ip              = "192.0.2.10"
      network         = "example-network"
      subnetwork      = "example-subnetwork"
      target_tags     = ["example-proxy"]
      service_account = "example-proxy@example-project.iam.gserviceaccount.com"
      routes = { public = {
        protocol = "HTTP"
        listener = "public"
        probe    = "https://example.test/health"
      } }
    }
  }
  assert {
    condition     = length(google_project_iam_member.generation[0].condition) == 0
    error_message = "The staging opt-in must provide usable project-wide endpoint access."
  }
}

run "production_cannot_enable_project_wide_endpoints" {
  command = plan
  variables {
    environment                               = "production"
    staging_project_wide_generation_endpoints = true
  }
  expect_failures = [var.staging_project_wide_generation_endpoints]
}
