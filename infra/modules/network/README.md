# network

Terraform skeleton for VPC, subnet, connector, and firewall management.

Current intent:

- model `superserve-network-3cb2c3b` or its replacement
- capture dedicated rules for ports `50051`, `5007`, and `5008`
- support a Serverless VPC Access connector for Cloud Run

This module currently defines only the input/output contract so it can be validated without creating resources.
