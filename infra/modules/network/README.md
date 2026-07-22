# network

Terraform module for VPC, subnet, connector, and firewall management.

Current intent:

- model `superserve-network-3cb2c3b` or its replacement
- capture dedicated rules for ports `50051`, `5007`, and `5008`
- support a Serverless VPC Access connector for Cloud Run
- enable VPC Flow Logs on every managed subnet with ten-minute aggregation,
  50% sampling, and all metadata
- optionally deny IPv4 and IPv6 ingress to TCP/UDP port 22 for explicitly
  tagged instances before environment-specific allow rules are evaluated
- optionally allow TCP/22 from the Google IAP range for environments that
  require administrator SSH; the deny and IAP allow are independent controls
  and both are disabled by default

The module does not manage firewall rules or instances that exist outside its
Terraform state. Those resources must be inventoried and remediated through
their owning configuration before the compliance check is considered complete.
