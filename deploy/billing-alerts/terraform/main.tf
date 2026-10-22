terraform {
  required_version = ">= 1.7.0"
  backend "gcs" {
    bucket = "superserve-terraform-state-prod"
    prefix = "production/billing-alerts"
  }
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }
}

provider "google" {
  project = "rayai-prod"
  region  = "us-central1"
}

module "billing_alerts" {
  source = "../module"

  project_id               = "rayai-prod"
  environment              = "production"
  labels                   = { environment = "production", managed_by = "terraform", region = "us-central1" }
  notification_channel_ids = ["projects/rayai-prod/notificationChannels/17044408421759047225"]
  manage_paid_missing      = false
  cells = {
    east = {
      metric_location         = "us-east4-c"
      cloud_run_service       = "superserve-api-use4"
      cloud_run_region        = "us-east4"
      coverage_checks_enabled = true
    }
    west = {
      metric_location         = "us-west2-a"
      cloud_run_service       = "superserve-api-usw2"
      cloud_run_region        = "us-west2"
      coverage_checks_enabled = false
    }
  }
}
