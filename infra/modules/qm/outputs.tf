output "contract" {
  description = "Rendered QM shared-infrastructure contract."
  value       = local.qm_contract
}

output "domain" {
  description = "Base hostname tenants are served under (<slug>.<domain>)."
  value       = var.domain
}

output "sql_instance_name" {
  description = "Shared Cloud SQL instance name."
  value       = google_sql_database_instance.tenants.name
}

output "sql_connection_name" {
  description = "Cloud SQL connection name (project:region:instance)."
  value       = google_sql_database_instance.tenants.connection_name
}

output "sql_private_ip" {
  description = "Private IP of the shared Cloud SQL instance."
  value       = google_sql_database_instance.tenants.private_ip_address
}

output "sql_admin_secret_id" {
  description = "Secret Manager secret holding the instance admin password. Readable only by the provisioner."
  value       = google_secret_manager_secret.sql_admin.secret_id
}

output "api_database_url_secret_id" {
  description = "Secret Manager secret qm-api and the provisioner read DATABASE_URL (control-plane Postgres, qm_api role) from. Its version is added out of band."
  value       = google_secret_manager_secret.api_database_url.secret_id
}

output "address" {
  description = "Global external IPv4 address of the tenant load balancer."
  value       = google_compute_global_address.edge.address
}

output "url_map_name" {
  description = "HTTPS URL map the provisioner appends tenant host rules to."
  value       = google_compute_url_map.https.name
}

output "https_proxy_name" {
  description = "Target HTTPS proxy in front of the URL map."
  value       = google_compute_target_https_proxy.this.name
}

output "redirect_backend_service_name" {
  description = "Backend service serving the URL map default route."
  value       = google_compute_backend_service.redirect.name
}

output "certificate_map_id" {
  description = "Certificate Manager certificate map resource ID."
  value       = google_certificate_manager_certificate_map.this.id
}

output "dns_authorization" {
  description = "DNS record the domain owner must publish before the wildcard certificate can be issued. Written automatically when dns_managed_zone is set."
  value = {
    name        = google_certificate_manager_dns_authorization.this.name
    record_data = local.dns_authorization_record
  }
}

output "provisioner_service_account_email" {
  description = "Provisioner job identity."
  value       = google_service_account.provisioner.email
}

output "api_service_account_email" {
  description = "qm-api runtime identity."
  value       = google_service_account.api.email
}

output "api_service_name" {
  description = "qm-api Cloud Run service name."
  value       = google_cloud_run_v2_service.api.name
}

output "api_service_uri" {
  description = "qm-api Cloud Run service URI."
  value       = google_cloud_run_v2_service.api.uri
}

output "provisioner_job_name" {
  description = "Provisioner Cloud Run job name."
  value       = google_cloud_run_v2_job.provisioner.name
}

output "tenant_image_repository" {
  description = "Artifact Registry path tenant images are pulled from."
  value       = local.tenant_image_repository
}

output "tenant_image" {
  description = "Tagged image the provisioner deploys for new tenant services."
  value       = local.tenant_image
}

output "tenant_service_account_prefix" {
  description = "Account-ID prefix of runtime-created tenant service accounts."
  value       = local.tenant_service_account_prefix
}

output "tenant_bucket_name_pattern" {
  description = "Bucket name pattern the provisioner fills per tenant ({slug} placeholder)."
  value       = local.tenant_bucket_name_pattern
}

output "tenant_bucket_location" {
  description = "Location the provisioner creates tenant buckets in."
  value       = local.tenant_bucket_location
}

output "tenant_bucket_lifecycle_policy_json" {
  description = "Lifecycle policy (JSON API shape) the provisioner applies to every tenant bucket."
  value       = jsonencode(local.tenant_bucket_lifecycle_policy)
}

locals {
  qm_contract = {
    project_id                    = var.project_id
    environment                   = var.environment
    region                        = var.region
    domain                        = var.domain
    sql_instance_name             = google_sql_database_instance.tenants.name
    sql_connection_name           = google_sql_database_instance.tenants.connection_name
    sql_private_ip                = google_sql_database_instance.tenants.private_ip_address
    sql_tier                      = var.sql_tier
    sql_availability_type         = var.sql_availability_type
    sql_max_connections           = var.sql_max_connections
    tenant_capacity               = var.tenant_capacity
    sql_admin_secret_id           = google_secret_manager_secret.sql_admin.secret_id
    api_database_url_secret_id    = google_secret_manager_secret.api_database_url.secret_id
    address                       = google_compute_global_address.edge.address
    url_map_name                  = google_compute_url_map.https.name
    https_proxy_name              = google_compute_target_https_proxy.this.name
    redirect_backend_service_name = google_compute_backend_service.redirect.name
    certificate_map_id            = google_certificate_manager_certificate_map.this.id
    dns_managed_zone              = var.dns_managed_zone
    provisioner_service_account   = google_service_account.provisioner.email
    api_service_account           = google_service_account.api.email
    redirect_service_account      = google_service_account.redirect.email
    api_service_name              = google_cloud_run_v2_service.api.name
    redirect_service_name         = google_cloud_run_v2_service.redirect.name
    provisioner_job_name          = google_cloud_run_v2_job.provisioner.name
    tenant_image_repository       = local.tenant_image_repository
    tenant_image                  = local.tenant_image
    tenant_service_account_prefix = local.tenant_service_account_prefix
    tenant_bucket_name_pattern    = local.tenant_bucket_name_pattern
    tenant_bucket_location        = local.tenant_bucket_location
    tenant_bucket_lifecycle_rules = var.tenant_bucket_lifecycle_rules
    labels                        = var.labels
  }
}
