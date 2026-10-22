terraform {
  required_version = ">= 1.9.0"

  backend "gcs" {
    bucket = "superserve-terraform-state"
    prefix = "devbox/us-central1"
  }

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 7.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

locals {
  # Deliberately not the staging/production label set: deploy discovery keys on
  # environment, region and role labels, and nothing here may ever match it.
  labels = {
    managed_by  = "terraform"
    application = "superserve-devbox"
  }

  # IAM conditions can match resource names but not labels, so a fixed name
  # prefix is what keeps the devbox identity away from staging VMs, disks and
  # buckets that share this project.
  instance_name_prefix = { for zone in var.zones : zone => "projects/${var.project_id}/zones/${zone}/instances/${var.resource_name_prefix}" }
  disk_name_prefix     = { for zone in var.zones : zone => "projects/${var.project_id}/zones/${zone}/disks/${var.resource_name_prefix}" }
  bucket_name_prefix   = "projects/_/buckets/${var.bucket_name_prefix}"

  devbox_compute_condition = { for zone in var.zones : zone => join(" || ", [
    "(resource.type == \"compute.googleapis.com/Instance\" && resource.name.startsWith(\"${local.instance_name_prefix[zone]}\"))",
    "(resource.type == \"compute.googleapis.com/Disk\" && resource.name.startsWith(\"${local.disk_name_prefix[zone]}\"))",
  ]) }
  devbox_storage_condition = join(" || ", [
    "(resource.type == \"storage.googleapis.com/Bucket\" && resource.name.startsWith(\"${local.bucket_name_prefix}\"))",
    "(resource.type == \"storage.googleapis.com/Object\" && resource.name.startsWith(\"${local.bucket_name_prefix}\"))",
  ])

  ci_member        = "serviceAccount:${google_service_account.ci.email}"
  box_member       = "serviceAccount:${google_service_account.box.email}"
  operator_members = merge({ ci = local.ci_member }, { for member in var.engineer_members : member => member })
}

resource "google_project_service" "required" {
  for_each = toset([
    "apikeys.googleapis.com",
    "compute.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "iap.googleapis.com",
    "oslogin.googleapis.com",
    "recaptchaenterprise.googleapis.com",
    "sts.googleapis.com",
  ])

  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

module "network" {
  source = "../../../infra/modules/network"

  project_id             = var.project_id
  environment            = "devbox"
  region                 = var.region
  network_name           = "superserve-devbox"
  subnet_name            = "superserve-devbox-usc1"
  subnet_cidr            = var.subnet_cidr
  create_vpc_connector   = false
  manage_public_ssh_deny = true
  enable_iap_ssh         = true
  iap_ssh_target_tags    = [var.network_tag]
  labels                 = local.labels

  depends_on = [google_project_service.required]
}

resource "google_compute_router" "devbox" {
  project = var.project_id
  name    = "superserve-devbox-usc1"
  region  = var.region
  network = module.network.network_self_link
}

# Boxes have no external address; they reach package mirrors, GitHub, Stripe
# and Docker registries through NAT, which admits no inbound connections.
resource "google_compute_router_nat" "devbox" {
  project                             = var.project_id
  name                                = "superserve-devbox-usc1"
  router                              = google_compute_router.devbox.name
  region                              = var.region
  nat_ip_allocate_option              = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat  = "ALL_SUBNETWORKS_ALL_IP_RANGES"
  enable_dynamic_port_allocation      = true
  enable_endpoint_independent_mapping = false
  min_ports_per_vm                    = 1024
  max_ports_per_vm                    = 16384

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

resource "google_service_account" "ci" {
  project      = var.project_id
  account_id   = "superserve-devbox-ci"
  display_name = "Devbox workflows (GitHub Actions)"
  description  = "Creates, labels, reaches and deletes devbox VMs, disks and buckets only."
}

resource "google_service_account" "box" {
  project      = var.project_id
  account_id   = "superserve-devbox-vm"
  display_name = "Devbox VM"
  description  = "Attached to devbox VMs. No project roles beyond objects in devbox buckets."
}

resource "google_iam_workload_identity_pool" "github" {
  project                   = var.project_id
  workload_identity_pool_id = "superserve-devbox-github"
  display_name              = "Devbox GitHub Actions"
  description               = "Devbox workflows on the main branch of the sandbox repository."

  depends_on = [google_project_service.required]
}

resource "google_iam_workload_identity_pool_provider" "github" {
  project                            = var.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.github.workload_identity_pool_id
  workload_identity_pool_provider_id = "github"
  display_name                       = "GitHub Actions"

  attribute_mapping = {
    "google.subject"          = "assertion.sub"
    "attribute.actor"         = "assertion.actor"
    "attribute.environment"   = "assertion.environment"
    "attribute.ref"           = "assertion.ref"
    "attribute.repository"    = "assertion.repository"
    "attribute.repository_id" = "assertion.repository_id"
    "attribute.workflow_ref"  = "assertion.workflow_ref"
  }

  # The numeric IDs survive renames and cannot be claimed by a recreated
  # repository of the same name. Selected-branch code is built on the box,
  # never on the runner, so only the devbox workflows on main may hold this
  # identity. Events such as pull_request_target also run with ref main, so
  # the triggers and workflow files are pinned as well.
  attribute_condition = join(" && ", [
    "assertion.repository_owner_id == \"${var.github_repository_owner_id}\"",
    "assertion.repository_id == \"${var.github_repository_id}\"",
    "assertion.repository == \"${var.github_repository}\"",
    "assertion.ref == \"refs/heads/main\"",
    "assertion.environment == \"${var.github_environment}\"",
    "assertion.event_name in [\"workflow_dispatch\", \"schedule\"]",
    "assertion.workflow_ref.startsWith(\"${var.github_repository}/.github/workflows/devbox-\")",
    "assertion.workflow_ref.endsWith(\"@refs/heads/main\")",
  ])

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

resource "google_service_account_iam_member" "ci_workload_identity" {
  service_account_id = google_service_account.ci.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/attribute.repository_id/${var.github_repository_id}"
}

# OS Login does not honour the name condition on these grants, so the create
# workflow also binds roles/compute.osAdminLogin on each new instance itself;
# getIamPolicy and setIamPolicy below allow that, on devbox instances only.
resource "google_project_iam_custom_role" "lifecycle" {
  project     = var.project_id
  role_id     = "superserveDevboxLifecycle"
  title       = "Devbox lifecycle"
  description = "Create, label, reach and delete devbox VMs, disks and buckets. Granted only with a name-prefix condition."
  permissions = [
    "compute.disks.create",
    "compute.disks.delete",
    "compute.disks.get",
    "compute.disks.setLabels",
    "compute.disks.use",
    "compute.instances.attachDisk",
    "compute.instances.create",
    "compute.instances.delete",
    "compute.instances.get",
    "compute.instances.getIamPolicy",
    "compute.instances.getSerialPortOutput",
    "compute.instances.osAdminLogin",
    "compute.instances.osLogin",
    "compute.instances.setIamPolicy",
    "compute.instances.setLabels",
    "compute.instances.setMetadata",
    "compute.instances.setServiceAccount",
    "compute.instances.setTags",
    "storage.buckets.delete",
    "storage.buckets.get",
    "storage.buckets.update",
    "storage.objects.delete",
    "storage.objects.get",
    "storage.objects.list",
  ]
}

resource "google_project_iam_custom_role" "access" {
  project     = var.project_id
  role_id     = "superserveDevboxAccess"
  title       = "Devbox access"
  description = "Inspect and SSH into devbox VMs. Granted only with a name-prefix condition."
  permissions = [
    "compute.instances.get",
    "compute.instances.getSerialPortOutput",
    "compute.instances.osAdminLogin",
    "compute.instances.osLogin",
  ]
}

# List and bucket-create checks run against the project rather than the named
# resource, so they cannot carry a name condition. None of them can modify an
# existing resource.
resource "google_project_iam_custom_role" "discovery" {
  project     = var.project_id
  role_id     = "superserveDevboxDiscovery"
  title       = "Devbox discovery"
  description = "Find devbox resources and follow zonal operations."
  permissions = [
    "compute.disks.list",
    "compute.instances.list",
    "compute.machineTypes.get",
    "compute.projects.get",
    "compute.zoneOperations.get",
    "compute.zoneOperations.list",
    "compute.zones.get",
    "compute.zones.list",
    "storage.buckets.list",
  ]
}

# One binding per zone: a binding's condition cannot change in place, so adding
# a zone must add a binding rather than rewrite an existing one.
resource "google_project_iam_member" "ci_lifecycle" {
  for_each = local.devbox_compute_condition

  project = var.project_id
  role    = google_project_iam_custom_role.lifecycle.name
  member  = local.ci_member

  condition {
    title       = "devbox-resources-only"
    description = "Devbox VMs, disks and buckets, matched by name prefix."
    expression  = join(" || ", [each.value, local.devbox_storage_condition])
  }
}

moved {
  from = google_project_iam_member.ci_lifecycle
  to   = google_project_iam_member.ci_lifecycle["us-central1-a"]
}

resource "google_project_iam_custom_role" "bucket_create" {
  project     = var.project_id
  role_id     = "superserveDevboxBucketCreate"
  title       = "Devbox bucket creation"
  description = "Create the per-box template-build bucket."
  permissions = ["storage.buckets.create"]
}

resource "google_project_iam_member" "ci_bucket_create" {
  project = var.project_id
  role    = google_project_iam_custom_role.bucket_create.name
  member  = local.ci_member
}

resource "google_project_iam_member" "operator_discovery" {
  for_each = local.operator_members

  project = var.project_id
  role    = google_project_iam_custom_role.discovery.name
  member  = each.value
}

resource "google_project_iam_member" "engineer_access" {
  for_each = { for pair in setproduct(var.engineer_members, var.zones) : "${pair[0]} ${pair[1]}" => { member = pair[0], zone = pair[1] } }

  project = var.project_id
  role    = google_project_iam_custom_role.access.name
  member  = each.value.member

  condition {
    title       = "devbox-instances-only-${each.value.zone}"
    description = "Devbox VMs, matched by name prefix."
    expression  = "resource.type == \"compute.googleapis.com/Instance\" && resource.name.startsWith(\"${local.instance_name_prefix[each.value.zone]}\")"
  }
}

resource "google_project_iam_member" "operator_iap_ssh" {
  for_each = local.operator_members

  project = var.project_id
  role    = "roles/iap.tunnelResourceAccessor"
  member  = each.value

  condition {
    title       = "ssh-only"
    description = "IAP TCP forwarding to port 22."
    expression  = "destination.port == 22"
  }
}

resource "google_project_iam_custom_role" "subnet_use" {
  project     = var.project_id
  role_id     = "superserveDevboxSubnetUse"
  title       = "Devbox subnet use"
  description = "Attach VMs to the devbox subnet without external addresses."
  permissions = ["compute.subnetworks.get", "compute.subnetworks.use"]
}

resource "google_compute_subnetwork_iam_member" "ci_subnet_use" {
  project    = var.project_id
  region     = var.region
  subnetwork = module.network.subnetwork_name
  role       = google_project_iam_custom_role.subnet_use.name
  member     = local.ci_member
}

# OS Login on a VM with an attached service account requires the caller to be
# able to act as that account.
resource "google_service_account_iam_member" "operator_box_user" {
  for_each = local.operator_members

  service_account_id = google_service_account.box.name
  role               = "roles/iam.serviceAccountUser"
  member             = each.value
}

resource "google_project_iam_member" "box_bucket_objects" {
  project = var.project_id
  role    = "roles/storage.objectAdmin"
  member  = local.box_member

  condition {
    title       = "devbox-buckets-only"
    description = "Objects in devbox template-build buckets."
    expression  = local.devbox_storage_condition
  }
}

resource "google_recaptcha_enterprise_key" "devbox" {
  project      = var.project_id
  display_name = "superserve-devbox"
  labels       = local.labels

  # Boxes are only reached through local port forwarding, so the key is not
  # bound to a domain; it is a development key with no production use.
  web_settings {
    integration_type  = "SCORE"
    allow_all_domains = true
  }

  depends_on = [google_project_service.required]
}

resource "google_apikeys_key" "recaptcha" {
  project      = var.project_id
  name         = "superserve-devbox-recaptcha"
  display_name = "Devbox reCAPTCHA assessments"

  restrictions {
    api_targets {
      service = "recaptchaenterprise.googleapis.com"
    }
  }

  depends_on = [google_project_service.required]
}

# Verified guest kernel and base rootfs that boxes fetch at bootstrap. Its name
# deliberately falls outside bucket_name_prefix, so neither the box's object
# grant nor box destroy can match it; only the seeder writes, boxes only read.
resource "google_storage_bucket" "hostprep" {
  project                     = var.project_id
  name                        = var.hostprep_bucket
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  labels                      = local.labels

  versioning {
    enabled = true
  }

  lifecycle {
    precondition {
      condition     = !startswith(var.hostprep_bucket, var.bucket_name_prefix)
      error_message = "hostprep_bucket must not match bucket_name_prefix."
    }
  }
}

resource "google_storage_bucket_iam_member" "box_hostprep_read" {
  bucket = google_storage_bucket.hostprep.name
  role   = "roles/storage.objectViewer"
  member = local.box_member
}

resource "google_storage_bucket_iam_member" "hostprep_seeder" {
  bucket = google_storage_bucket.hostprep.name
  role   = "roles/storage.objectAdmin"
  member = var.hostprep_seeder
}
