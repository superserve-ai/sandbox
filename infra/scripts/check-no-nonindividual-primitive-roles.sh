#!/usr/bin/env bash
set -euo pipefail

root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

python3 - "$root" <<'PY'
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
primitive_role = re.compile(r'roles/(owner|editor|viewer)')
non_individual_principal = re.compile(
    r'(serviceAccount:|principal(?:Set)?:\/\/|allUsers\b|allAuthenticatedUsers\b|group:|domain:)'
)


def brace_block(source, open_idx):
    depth = 0
    for idx in range(open_idx, len(source)):
        char = source[idx]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[open_idx : idx + 1]
    return None


issues = []
for path in sorted(root.rglob("*.tf")):
    if ".terraform" in path.parts:
        continue

    source = path.read_text()
    for match in primitive_role.finditer(source):
        role = match.group(0)
        role_idx = match.start()
        open_idx = source.rfind("{", 0, role_idx)
        if open_idx == -1:
            continue

        block = brace_block(source, open_idx)
        if block is None:
            continue

        if non_individual_principal.search(block):
            line = source.count("\n", 0, role_idx) + 1
            issues.append(f"{path}:{line} primitive non-individual assignment of {role}")

if issues:
    print("Primitive project roles assigned in Terraform IAM configuration:", file=sys.stderr)
    for issue in issues:
        print(issue, file=sys.stderr)
    raise SystemExit(1)

print(
    "PASS: repository regression check found no explicit Terraform assignment of roles/owner, roles/editor, or roles/viewer to a non-individual identity."
)
PY
