mock_provider "google" {}

variables {
  project_id                 = "example-project"
  environment                = "staging"
  bucket_name                = "example-backup"
  location                   = "us-central1"
  writer_members             = []
  reader_members             = ["serviceAccount:reader@example-project.iam.gserviceaccount.com"]
  restore_service_account_id = "example-restore"
  gc_service_account_id      = "example-gc"
}

run "control_plane_reader_is_read_only" {
  command = plan

  assert {
    condition = (
      google_storage_managed_folder.templates.name == "templates/" &&
      google_storage_managed_folder_iam_member.reader_view["serviceAccount:reader@example-project.iam.gserviceaccount.com"].managed_folder == "templates/" &&
      google_storage_managed_folder_iam_member.reader_view["serviceAccount:reader@example-project.iam.gserviceaccount.com"].role == "roles/storage.objectViewer" &&
      length(google_storage_bucket_iam_member.writer_create) == 0 &&
      !contains([for grant in values(google_storage_managed_folder_iam_member.reader_view) : grant.role], "roles/storage.objectCreator") &&
      !contains([for grant in values(google_storage_managed_folder_iam_member.reader_view) : grant.role], "roles/storage.objectAdmin")
    )
    error_message = "Control-plane readers must receive template managed-folder objectViewer access."
  }

  assert {
    condition = (
      contains(output.contract.reader_members, "serviceAccount:reader@example-project.iam.gserviceaccount.com") &&
      output.contract.reader_object_prefix == "templates/"
    )
    error_message = "The rendered backup contract must publish the configured reader and template prefix."
  }
}
