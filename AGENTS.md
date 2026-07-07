# Agent and contributor guidelines

This repository is open source. Everything committed here — code, comments,
test fixtures, commit messages — and everything attached to it on GitHub —
PR titles, PR descriptions, review comments — is public.

## Never reference internal context

- **No customer names.** Do not name customers, their domains, or anything
  that identifies a business relationship in code, fixtures, commits, or PR
  text. Use neutral placeholders (`pilot-team`, `example-team`) in tests and
  plain descriptions ("a customer with a large fleet") in prose.
- **No internal ticket references.** Do not cite issue-tracker IDs
  (`SS-123`-style) anywhere in the repo or in PR titles/descriptions. They
  are dead links to outside readers and leak internal planning. Describe the
  purpose in words instead: "part of the multi-region rollout", not a ticket
  number.
- **No internal URLs** (dashboards, trackers, internal docs) in committed
  files or PR text.

Cross-referencing public artifacts is fine: other PRs and issues in this
repository, upstream project issues, and public documentation.

## Code conventions

- Match the style, comment density, and idiom of the surrounding code.
- Comments explain constraints the code can't show — not what the next line
  does, and not review-time justifications.
- Test fixtures use invented data only: generated UUIDs, neutral names,
  RFC-reserved IPs and example domains.
