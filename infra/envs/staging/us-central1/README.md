# staging

Staging environment configuration now consumes `terraform.tfvars`, but existing staging infrastructure should still be imported before Terraform manages it directly.

Files to use:

- `terraform.tfvars` for deployment-specific values such as region, suffixes, and Supabase config
- `imports.tf` for future import blocks
- `import-commands.sh` for manual import workflows
- `IMPORT_REVIEW.md` for adoption notes
