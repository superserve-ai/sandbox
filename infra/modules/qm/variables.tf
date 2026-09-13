variable "project_id" {
  description = "GCP project ID."
  type        = string
}

variable "environment" {
  description = "Environment name."
  type        = string
}

variable "region" {
  description = "Region for the Cloud SQL instance, Cloud Run services, the provisioner job, and the tenant image repository."
  type        = string
}

variable "resource_suffix" {
  description = "Project-global naming suffix shared with the rest of the environment (e.g. staging-usc1)."
  type        = string
}

variable "service_account_suffix" {
  description = "Service-account naming suffix. Keep it short: account IDs are capped at 30 characters and the longest prefix here is qm-provisioner-."
  type        = string

  validation {
    condition     = length("qm-provisioner-${var.service_account_suffix}") <= 30
    error_message = "service_account_suffix is too long: qm-provisioner-<suffix> must be at most 30 characters."
  }
}

variable "domain" {
  description = "Base hostname for tenant stacks: each tenant is served at https://<slug>.<domain>, so pass qm.<env-domain>. The wildcard certificate, certificate map, and DNS authorization are all derived from it. Required, but may be passed as null by a root whose enable_qm flag is off."
  type        = string
}

variable "marketing_url" {
  description = "Absolute URL the redirect service sends a bare request for / to."
  type        = string
}

variable "network_self_link" {
  description = "Self link of the VPC the Cloud SQL private IP is attached to (the environment's existing VPC)."
  type        = string
}

variable "vpc_network" {
  description = "VPC name for Cloud Run Direct VPC egress on the qm-api service and the provisioner job."
  type        = string
}

variable "vpc_subnetwork" {
  description = "Subnetwork name for Cloud Run Direct VPC egress. Must be in var.region and on var.vpc_network."
  type        = string
}

variable "vpc_tags" {
  description = "Network tags applied to Direct VPC egress traffic so firewall rules can select it."
  type        = list(string)
  default     = []
}

variable "vpc_egress" {
  description = "Cloud Run VPC egress mode. PRIVATE_RANGES_ONLY sends only RFC 1918 traffic (the Cloud SQL private IP) through the VPC; Google APIs stay on their public path."
  type        = string
  default     = "PRIVATE_RANGES_ONLY"
}

variable "create_private_service_connection" {
  description = "Whether to allocate a Private Service Access range and create the servicenetworking peering on var.network_self_link. Set false when the VPC already has a servicenetworking connection: creating a second one fails, and updating the existing one from here would replace its reserved-range list. In that case add the QM range to the existing connection out of band."
  type        = bool
  default     = true
}

variable "private_service_range_prefix_length" {
  description = "Prefix length of the Private Service Access range allocated for Cloud SQL. Google recommends at least /24 per instance; /20 leaves room for read replicas and future instances on the same peering."
  type        = number
  default     = 20
}

variable "private_service_range_address" {
  description = "Optional fixed first address for the Private Service Access range. Null lets Google pick a free block in the VPC."
  type        = string
  default     = null
}

variable "sql_database_version" {
  description = "Cloud SQL engine version for the shared tenant instance."
  type        = string
  default     = "POSTGRES_16"
}

variable "sql_tier" {
  description = "Cloud SQL machine tier. db-custom-2-7680 (2 vCPU / 7.5 GiB) carries the default max_connections comfortably; raise it together with tenant_capacity."
  type        = string
  default     = "db-custom-2-7680"
}

variable "sql_availability_type" {
  description = "ZONAL or REGIONAL. Production should run REGIONAL (synchronous standby in a second zone)."
  type        = string
  default     = "ZONAL"

  validation {
    condition     = contains(["ZONAL", "REGIONAL"], var.sql_availability_type)
    error_message = "sql_availability_type must be ZONAL or REGIONAL."
  }
}

variable "sql_disk_size_gb" {
  description = "Initial data disk size in GiB. Autoresize is on, so this is a floor."
  type        = number
  default     = 20
}

variable "tenant_capacity" {
  description = "Number of tenant stacks this shared instance is sized for. Drives the max_connections sizing check and is the number to raise the project's service-account quota to (plus platform accounts): every tenant gets its own qm-<slug> service account at runtime."
  type        = number
  default     = 25
}

variable "sql_connections_per_tenant" {
  description = "Postgres connections one tenant's QM container holds at steady state (its pool plus workers)."
  type        = number
  default     = 17
}

variable "sql_connection_headroom" {
  description = "Multiplier applied to tenant_capacity x sql_connections_per_tenant to leave room for qm-api, the provisioner, migrations, and operator sessions."
  type        = number
  default     = 1.3
}

variable "sql_max_connections" {
  description = "Value of the Postgres max_connections flag. Sized as tenant_capacity x sql_connections_per_tenant x sql_connection_headroom = 25 x 17 x 1.3 = 552.5, rounded up to 560. A check block warns when the flag no longer covers the configured capacity."
  type        = number
  default     = 560
}

variable "sql_backup_start_time" {
  description = "Daily automated backup window start (HH:MM, UTC)."
  type        = string
  default     = "03:00"
}

variable "sql_backup_retained_count" {
  description = "Number of daily automated backups retained."
  type        = number
  default     = 14
}

variable "sql_transaction_log_retention_days" {
  description = "Days of write-ahead log kept for point-in-time recovery (1-7 for Postgres)."
  type        = number
  default     = 7
}

variable "sql_admin_user" {
  description = "Name of the instance-level admin role the provisioner connects as to create tenant databases and roles."
  type        = string
  default     = "qm_admin"
}

variable "tenant_bucket_location" {
  description = "Location the provisioner creates tenant buckets in. Null uses var.region."
  type        = string
  default     = null
}

variable "tenant_bucket_lifecycle_rules" {
  description = "Lifecycle rules the provisioner applies to every tenant bucket, rendered to the JSON API lifecycle shape (tenant_bucket_lifecycle_policy_json output). Defaults reap abandoned multipart uploads and bound versioning growth."
  type = list(object({
    action = object({
      type          = string
      storage_class = optional(string)
    })
    condition = object({
      age                        = optional(number)
      days_since_noncurrent_time = optional(number)
      num_newer_versions         = optional(number)
      matches_prefix             = optional(list(string))
      matches_storage_class      = optional(list(string))
    })
  }))
  default = [
    {
      action    = { type = "AbortIncompleteMultipartUpload" }
      condition = { age = 7 }
    },
    {
      action    = { type = "Delete" }
      condition = { days_since_noncurrent_time = 30 }
    },
  ]
}

variable "tenant_image" {
  description = "Tagged image the provisioner deploys for every new tenant service (QM_TENANT_IMAGE). Null uses <tenant_image_repository>/qm:latest. Per-tenant pinning is the provisioner's concern; this is the fleet default."
  type        = string
  default     = null
}

variable "api_service_name" {
  description = "qm-api Cloud Run service name. Null uses superserve-qm-api-<resource_suffix>; the deploy workflow reads the same name from its QM_API_SERVICE variable."
  type        = string
  default     = null
}

variable "provisioner_job_name" {
  description = "Provisioner Cloud Run job name. qm-api's QM_PROVISIONER_JOB and the deploy workflow both default to qm-provisioner; jobs are regional, so the name is not suffixed."
  type        = string
  default     = "qm-provisioner"
}

variable "redirect_service_name" {
  description = "qm-redirect Cloud Run service name. Null uses qm-redirect-<resource_suffix>."
  type        = string
  default     = null
}

variable "api_image" {
  description = "qm-api container image. Must exist before the first apply: Cloud Run rejects a revision whose image cannot be pulled. Later image rollouts are owned by deploy tooling and ignored by Terraform."
  type        = string
}

variable "api_min_instances" {
  description = "qm-api minimum instance count."
  type        = number
  default     = 0
}

variable "api_max_instances" {
  description = "qm-api maximum instance count."
  type        = number
  default     = 10
}

variable "api_cpu_limit" {
  type    = string
  default = "1"
}

variable "api_memory_limit" {
  type    = string
  default = "512Mi"
}

variable "api_ingress" {
  description = "qm-api ingress setting."
  type        = string
  default     = "INGRESS_TRAFFIC_ALL"
}

variable "api_allow_public_invoker" {
  description = "Grant allUsers roles/run.invoker on qm-api. Off by default: unlike the sandbox API, nothing fronts qm-api with a load balancer yet, so callers authenticate to Cloud Run with their own identity until the public ingress path is decided."
  type        = bool
  default     = false
}

variable "api_env" {
  description = "Extra plaintext environment variables for qm-api, merged over the module-derived QM_* set (caller wins)."
  type        = map(string)
  default     = {}
}

variable "api_secrets" {
  description = "Extra secret-backed environment variables for qm-api keyed by env var name. The runtime SA must already be able to read them; the module only grants qm-* secrets."
  type = map(object({
    secret  = string
    version = optional(string, "latest")
  }))
  default = {}
}

variable "provisioner_image" {
  description = "Provisioner job container image. Null uses api_image: the service and the job are the same qm-api binary and are deployed together."
  type        = string
  default     = null
}

variable "provisioner_timeout_seconds" {
  description = "Per-task timeout for a provisioner execution. A tenant provision waits on Cloud SQL, Cloud Run, and load balancer operations, so this is generous."
  type        = number
  default     = 1800
}

variable "provisioner_cpu_limit" {
  type    = string
  default = "1"
}

variable "provisioner_memory_limit" {
  type    = string
  default = "512Mi"
}

variable "provisioner_env" {
  description = "Extra plaintext environment variables for the provisioner job, merged over the module-derived QM_* set (caller wins)."
  type        = map(string)
  default     = {}
}

variable "redirect_image" {
  description = "qm-redirect container image (302s /<slug> to https://<slug>.<domain> and / to marketing_url). Same existence requirement as api_image."
  type        = string
}

variable "redirect_env" {
  description = "Extra plaintext environment variables for the redirect service."
  type        = map(string)
  default     = {}
}

variable "backend_timeout_sec" {
  description = "Backend timeout for the redirect backend service."
  type        = number
  default     = 30
}

variable "dns_managed_zone" {
  description = "Optional Cloud DNS managed zone name (in var.project_id) that owns var.domain. When set, the module writes the certificate DNS-authorization CNAME plus A records for <domain> and *.<domain> pointing at the load balancer. Null leaves DNS to whoever owns the zone; the records to create are in the dns_authorization and address outputs."
  type        = string
  default     = null
}

variable "dns_ttl" {
  description = "TTL for managed DNS records."
  type        = number
  default     = 300
}

variable "labels" {
  description = "Labels applied to every resource that supports them."
  type        = map(string)
  default     = {}
}
