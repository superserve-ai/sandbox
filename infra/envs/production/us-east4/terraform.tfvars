project_id             = "rayai-prod"
environment            = "production"
region                 = "us-east4"
zone                   = "us-east4-c"
create_network         = false
network_name           = "superserve-production-vpc"
resource_suffix        = "use4"
service_account_suffix = "use4"
subnet_cidr            = "10.2.0.0/24"
connector_subnet_cidr  = "10.2.0.0/24"
host_internal_ip       = "10.2.0.2"
machine_type           = "c4-highmem-288-lssd-metal"
boot_disk_type         = "hyperdisk-balanced"
# The reservation-us-east-c4-288-lssd-metal reservation is non-specific
# (specificReservationRequired=false), so it can't be targeted by name. Null =
# default affinity, which auto-consumes that matching reservation in the zone.
reservation_name = null
