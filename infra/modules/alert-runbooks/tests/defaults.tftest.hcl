run "base_url_is_the_only_required_input" {
  command = plan
  variables {
    runbook_base_url = "https://example.com/runbooks/"
  }
  assert {
    condition     = length(output.urls) == 9 && length(toset(values(output.urls))) == 9
    error_message = "All nine procedures must have distinct default page destinations."
  }
  assert {
    condition = alltrue([
      for url in values(output.urls) : can(regex("^https://example.com/runbooks/[A-Za-z0-9_-]+$", url))
    ])
    error_message = "Default pages must use the configured base URL."
  }
}
