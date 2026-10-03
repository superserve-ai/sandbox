"""Classify configured API database targets without exposing connection values.

This module never connects to a database. Payload access belongs to an explicitly
released collector process; callers must not log provider output or exceptions.
"""

import datetime
import re
from urllib.parse import parse_qsl, unquote, urlsplit

from migrate_database import MigrationError, PROJECTS


BINDINGS = {
    "database-url-usw2": PROJECTS["usw2"],
    "database-url": PROJECTS["use4"],
}
MAX_VERSIONS = 1024


def require(condition):
    if not condition:
        raise MigrationError("API database binding is incomplete, changed or does not match the expected project")


def instant(value):
    try:
        result = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
        require(result.tzinfo is not None)
        return result.timestamp()
    except (ValueError, TypeError, AttributeError):
        raise MigrationError("Database binding timestamp is invalid") from None


def matches_project(payload, project):
    """Accept direct or Supabase transaction/session pooler project identities."""
    try:
        value = payload.decode("utf-8") if isinstance(payload, bytes) else payload
        require(isinstance(value, str) and len(value) <= 16384 and value == value.strip())
        url = urlsplit(value)
        user = unquote(url.username or "")
        params = parse_qsl(url.query, strict_parsing=True, keep_blank_values=True)
        require(url.scheme in {"postgres", "postgresql"} and user and url.password
                and url.path == "/postgres" and not url.fragment
                and len({k for k, _ in params}) == len(params)
                and all(k in {"sslmode", "connect_timeout", "application_name", "pgbouncer"} for k, _ in params))
        direct = (url.hostname == f"db.{project}.supabase.co" and url.port in (None, 5432)
                  and ("." not in user or user.rsplit(".", 1)[1] == project))
        pooler = (re.fullmatch(r"aws-[0-9]+-[a-z0-9-]+\.pooler\.supabase\.com", url.hostname or "")
                  and url.port in (5432, 6543) and user.rsplit(".", 1)[-1] == project
                  and "." in user)
        require(direct or pooler)
        return True
    except (MigrationError, ValueError, TypeError, UnicodeError):
        # Connection parsers can include the input in their exception text.
        raise MigrationError("API database URL does not identify the expected project") from None


def candidate_versions(secret, metadata, earliest_start, observed_at):
    """Cover every version latest could have selected during instance startup.

    Secret Manager retains destroyed version metadata. Require a contiguous
    numeric ledger so a missing page or recreated secret cannot hide a version.
    Every version since the last creation at/before the oldest relevant revision
    is a candidate, regardless of its current enabled/disabled state.
    """
    require(secret in BINDINGS and isinstance(metadata, list) and 0 < len(metadata) <= MAX_VERSIONS)
    start, end = instant(earliest_start), instant(observed_at)
    require(start <= end)
    prefixes = [f"projects/{project}/secrets/{secret}/versions/" for project in ('rayai-prod', '887554770957')]
    rows = []
    for item in metadata:
        require(isinstance(item, dict) and isinstance(item.get("name"), str))
        name = item["name"]
        matched = [prefix for prefix in prefixes if name.startswith(prefix)]
        require(len(matched) == 1)
        prefix = matched[0]
        require(re.fullmatch(r"[1-9][0-9]*", name[len(prefix):]))
        created = instant(item.get("createTime"))
        require(created <= end and item.get("state") in {"ENABLED", "DISABLED", "DESTROYED"})
        rows.append((int(name[len(prefix):]), created, item))
    rows.sort()
    require([n for n, _, _ in rows] == list(range(1, len(rows) + 1)))
    require(all(a[1] <= b[1] for a, b in zip(rows, rows[1:])))
    predecessors = [row for row in rows if row[1] <= start]
    require(predecessors)
    boundary = predecessors[-1][1]
    candidates = [item for _, created, item in rows if created >= boundary]
    # Disabled/destroyed candidates could remain loaded in a running process,
    # but cannot be read now. They require other runtime evidence, not omission.
    require(all(item["state"] == "ENABLED" for item in candidates))
    return candidates


def classify(secret, *, earliest_start, observed_at, list_versions, read_payload):
    """Use injected private providers; return only fixed, non-secret metadata."""
    try:
        before = list_versions(secret)
        candidates = candidate_versions(secret, before, earliest_start, observed_at)
        result = []
        for item in candidates:
            payload = read_payload(item["name"])
            try:
                matches_project(payload, BINDINGS[secret])
            finally:
                del payload
            result.append({"name": item["name"], "created_at": item["createTime"],
                           "expected_project_match": True})
        require(before == list_versions(secret))
        return {"secret": secret, "earliest_revision_start": earliest_start,
                "observed_at": observed_at, "versions": result}
    except Exception:
        # Provider exceptions may contain a response payload or connection URL.
        raise MigrationError("API database binding could not be privately verified") from None
