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
  (`SS-123`-style) in code, comments, test fixtures, or commit messages. They
  are dead links to outside readers and leak internal planning. Describe the
  purpose in words instead: "part of the multi-region rollout", not a ticket
  number.
- **No internal URLs** (dashboards, trackers, internal docs) in committed
  files.
- **PR bodies may link the tracker item they relate to.** A single line at
  the top of a PR description, verb matched to what the PR actually does:
  `Fixes: <URL>` for a bug fix or a Sentry alert this resolves,
  `Implements: <URL>` for a Linear issue or spec this builds out,
  `Relates to: <URL>` for a PR that's part of a larger tracked effort
  without fully resolving it. The destination being internal-only is fine;
  outside readers just see a dead link, same as any other private
  reference. This does not relax anything above: PR titles, code, comments,
  commits, and fixtures still describe the change in plain words with no
  ticket IDs or internal URLs, and the PR body must still explain the
  change in prose, not rely on the link alone.

Cross-referencing public artifacts is fine: other PRs and issues in this
repository, upstream project issues, and public documentation.

## Code conventions

- Match the style, comment density, and idiom of the surrounding code.
- Comments explain constraints the code can't show — not what the next line
  does, and not review-time justifications.
- Test fixtures use invented data only: generated UUIDs, neutral names,
  RFC-reserved IPs and example domains.

## Sandbox lifecycle performance

Sandbox startup and resume latency are critical product paths.

When changing code involved in sandbox creation, startup, restore, resume, reattach, pause/unpause, or related lifecycle transitions:

- Keep new I/O, network calls, database access, hashing, compression, serialization, logging, metrics emission, retries, and other potentially blocking work out of the synchronous startup/resume hot path whenever possible.
- Prefer asynchronous, deferred, precomputed, cached, or background work when correctness allows.
- Do not add loops over fleet-, artifact-, filesystem-, or user-sized collections to the hot path without demonstrating that the bound is small and stable.
- Do not add telemetry whose cost or volume scales per item on the hot path.
- If synchronous work is unavoidable, explicitly explain why it must be synchronous and assess its latency impact.
- Preserve existing startup/resume latency instrumentation and add measurement when introducing a new meaningful latency component.
