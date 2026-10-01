# One-time state adoption. The api module now declares the public invoker
# binding (allUsers -> roles/run.invoker) that has always existed out-of-band on
# this service; import it so the CD apply is a no-op instead of showing a
# (harmless but confusing) "add public access" create. iam_member is idempotent.
import {
  to = module.api.google_cloud_run_v2_service_iam_member.public_invoker[0]
  id = "projects/rayai-prod/locations/us-west2/services/superserve-api-usw2 roles/run.invoker allUsers"
}
