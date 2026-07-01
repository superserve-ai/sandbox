# infra

Terraform skeleton layout for Superserve GCP adoption.

- `modules/` defines resource-area contracts
- `envs/` wires those contracts into staging, production, and a greenfield new-region target

All modules are schema-only at this stage, so they can be reviewed and iterated without applying infrastructure.
