"""Configuration helpers for the devbox service entry points.

services-up.sh, install-api.sh and seed-base.sh call these subcommands as
root on the box. Each writes files atomically and never prints secret values.
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets as random
import shlex
import subprocess
import sys
import time
import uuid

ENV_KEY = re.compile(r"[A-Z][A-Z0-9_]*")
TEN_YEARS = 10 * 365 * 24 * 3600
DOCKER_DAEMON = {"iptables": False, "ip6tables": False, "bridge": "none"}

# Generated once per box and never rotated: the database keeps the passwords,
# issued Auth tokens keep the JWT secret, and the console shares the tokens.
GENERATED = {
    "POSTGRES_PASSWORD": lambda: random.token_hex(24),
    "PROMOTION_EVIDENCE_PROXY_PASSWORD": lambda: random.token_hex(24),
    "JWT_SECRET": lambda: random.token_hex(32),
    "SANDBOX_ACCESS_TOKEN_SEED": lambda: random.token_hex(32),
    "INTERNAL_API_TOKEN": lambda: random.token_hex(32),
    "OPERATOR_API_TOKEN": lambda: random.token_hex(32),
    "PROMOTION_CAPTURE_TOKEN": lambda: random.token_hex(32),
    "PROMOTION_ACCOUNT_TOKEN": lambda: random.token_hex(32),
    "SYSTEM_TEAM_ID": lambda: str(uuid.uuid4()),
    "SECRETS_SIGNING_KEY": lambda: base64.b64encode(random.token_bytes(32)).decode(),
}

# The only local secrets the containers receive.
COMPOSE_SECRETS = ("POSTGRES_PASSWORD", "JWT_SECRET", "ANON_KEY", "SERVICE_ROLE_KEY")

# API settings taken verbatim from devbox.env or secrets.env when present.
API_PASSTHROUGH = (
    "STRIPE_SECRET_KEY",
    "STRIPE_API_VERSION",
    "STRIPE_CHECKOUT_PRICE_IDS",
    "STRIPE_PRO_MONTHLY_PRICE_ID",
    "STRIPE_PRO_ANNUAL_PRICE_ID",
    "STRIPE_PORTAL_NO_CANCEL_CONFIGURATION",
    "BILLING_RESOURCE_CONFIG",
    "STRIPE_WEBHOOK_SECRET",
    "STRIPE_METER_ERROR_WEBHOOK_SECRET",
)


def read_env(path):
    """Parse a file of KEY=value lines written by write_env (shell quoting allowed)."""
    values = {}
    p = Path(path)
    if not p.exists():
        return values
    for number, line in enumerate(p.read_text().splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        key, sep, raw = line.partition("=")
        if not sep or not ENV_KEY.fullmatch(key):
            raise ValueError(f"{path}:{number}: expected KEY=value")
        parts = shlex.split(raw) if raw else [""]
        if len(parts) != 1:
            raise ValueError(f"{path}:{number}: value for {key} is not a single word")
        values[key] = parts[0]
    return values


def write_env(path, values, mode=0o600):
    """Atomically write values as shell-quoted KEY=value lines."""
    lines = []
    for key, value in values.items():
        if not ENV_KEY.fullmatch(key) or "\n" in value or "\r" in value:
            raise ValueError(f"invalid environment entry {key}")
        lines.append(f"{key}={shlex.quote(value)}\n")
    write_file(path, "".join(lines), mode)


# Shared secrets are read literally by some consumers and sourced by bash by
# others, so values are restricted to characters that need no quoting in a
# shell assignment.
PLAIN_VALUE = re.compile(r"[A-Za-z0-9@%+=:,./?_-]*")


def write_plain_env(path, values, mode=0o600):
    """Atomically write unquoted KEY=value lines; reject values that would need quoting."""
    for key, value in values.items():
        if not ENV_KEY.fullmatch(key) or not PLAIN_VALUE.fullmatch(value):
            raise ValueError(f"{key} must be an unquoted shell word")
    write_file(path, plain_env_text(values), mode)


def plain_env_text(values):
    return "".join(f"{k}={v}\n" for k, v in values.items())


def write_file(path, content, mode=0o600):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(f".{p.name}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w") as f:
        f.write(content)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, mode)
    os.replace(tmp, p)
    dir_fd = os.open(p.parent, os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def _b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def hs256_jwt(claims, secret):
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64url(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode())
    signature = hmac.new(secret.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest()
    return f"{header}.{payload}.{_b64url(signature)}"


def ed25519_keypair():
    """Return (PKCS#8 PEM private key, base64 raw 32-byte public key)."""
    pem = subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519"],
                         check=True, capture_output=True, text=True).stdout
    der = subprocess.run(["openssl", "pkey", "-pubout", "-outform", "DER"], input=pem.encode(),
                         check=True, capture_output=True).stdout
    return pem, base64.b64encode(der[-32:]).decode()


def database_url(user, password):
    return f"postgresql://{user}:{password}@127.0.0.1:54322/postgres?sslmode=disable"


def generate_secrets(existing, now=None):
    """Return existing plus every missing generated value."""
    values = dict(existing)
    for key, generate in GENERATED.items():
        if not values.get(key):
            values[key] = generate()
    if not values.get("DATABASE_URL"):
        values["DATABASE_URL"] = database_url("postgres", values["POSTGRES_PASSWORD"])
    issued = int(now if now is not None else time.time())
    for key, role in (("ANON_KEY", "anon"), ("SERVICE_ROLE_KEY", "service_role")):
        if not values.get(key):
            values[key] = hs256_jwt({"iss": "supabase", "role": role, "iat": issued, "exp": issued + TEN_YEARS},
                                    values["JWT_SECRET"])
    return values


def ensure_secrets(path, key_path, keypair=ed25519_keypair):
    existing = read_env(path)
    values = generate_secrets(existing)
    key_file = Path(key_path)
    if not values.get("PROMOTION_ACCOUNT_PUBLIC_KEY") or not key_file.exists():
        pem, public = keypair()
        write_file(key_file, pem)
        values["PROMOTION_ACCOUNT_PUBLIC_KEY"] = public
    current = Path(path).read_text() if Path(path).exists() else None
    if current != plain_env_text(values):
        write_plain_env(path, values)
    return values


def merge_docker_daemon(path):
    """Merge DOCKER_DAEMON into the daemon config. Returns True when it changed."""
    p = Path(path)
    current = json.loads(p.read_text()) if p.exists() and p.read_text().strip() else {}
    if not isinstance(current, dict):
        raise ValueError(f"{path} is not a JSON object")
    merged = {**current, **DOCKER_DAEMON}
    if merged == current:
        return False
    write_file(p, json.dumps(merged, indent=2, sort_keys=True) + "\n", 0o644)
    return True


def compose_images(compose_path):
    return re.findall(r"^\s+image:\s*(\S+)\s*$", Path(compose_path).read_text(), re.MULTILINE)


def image_digest(image):
    out = subprocess.run(["docker", "image", "inspect", "--format", "{{json .RepoDigests}}", image],
                         capture_output=True, text=True)
    digests = json.loads(out.stdout) if out.returncode == 0 and out.stdout.strip() else []
    return digests[0].split("@", 1)[1] if digests else None


def services_manifest(compose_path, stripe_enabled, digest=image_digest):
    """Non-secret description of the running services for the box manifest."""
    images = {}
    for ref in compose_images(compose_path):
        images[ref] = {"digest": digest(ref)}
    return {
        "images": images,
        "endpoints": {
            "auth": "http://127.0.0.1:54321/auth/v1",
            "rest": "http://127.0.0.1:54321/rest/v1",
            "postgres": "127.0.0.1:54322",
            "mailpit_ui": "http://127.0.0.1:8025",
            "mailpit_smtp": "127.0.0.1:1025",
        },
        "stripe_listen": stripe_enabled,
    }


def api_env(env, runtime):
    """Render the API environment from box config, local secrets and runtime.json."""
    def need(source, key):
        value = source.get(key)
        if not value:
            raise ValueError(f"{key} is required")
        return value

    values = {
        "API_HOST": "127.0.0.1",
        "API_PORT": env.get("API_PORT", "8080"),
        "DATABASE_URL": database_url("postgres", need(env, "POSTGRES_PASSWORD")),
        "PROMOTION_AUTH_DATABASE_URL": database_url("promotion_evidence_proxy", need(env, "PROMOTION_EVIDENCE_PROXY_PASSWORD")),
        "SANDBOX_ACCESS_TOKEN_SEED": need(env, "SANDBOX_ACCESS_TOKEN_SEED"),
        "INTERNAL_API_TOKEN": need(env, "INTERNAL_API_TOKEN"),
        "OPERATOR_API_TOKEN": need(env, "OPERATOR_API_TOKEN"),
        "PROMOTION_CAPTURE_TOKEN": need(env, "PROMOTION_CAPTURE_TOKEN"),
        "PROMOTION_ACCOUNT_TOKEN": need(env, "PROMOTION_ACCOUNT_TOKEN"),
        "PROMOTION_ACCOUNT_PUBLIC_KEY": need(env, "PROMOTION_ACCOUNT_PUBLIC_KEY"),
        "SYSTEM_TEAM_ID": need(env, "SYSTEM_TEAM_ID"),
        "SECRETS_SIGNING_KEY": need(env, "SECRETS_SIGNING_KEY"),
        "EMAIL_TRANSPORT": "smtp",
        "SMTP_HOST": "127.0.0.1",
        "SMTP_PORT": "1025",
        "QUOTA_EMAIL_FROM": need(env, "EMAIL_FROM"),
        "APP_ALLOWED_ORIGINS": need(env, "CONSOLE_URL"),
        "CONSOLE_URL": need(env, "CONSOLE_URL"),
        "EDGE_PROXY_DOMAIN": need(env, "EDGE_PROXY_DOMAIN"),
        "COMPUTE_RESTRICTIONS_SOURCE": "database",
        "TEMPLATE_BUILD_REGION": need(runtime, "host_region"),
        "BACKUP_BUCKET": need(env, "DEVBOX_BUCKET"),
        "DEFAULT_HOST_ID": need(runtime, "host_id"),
        "VMD_GRPC_ADDRESS": runtime.get("vmd_grpc_address") or "127.0.0.1:50051",
        "OTEL_SERVICE_VERSION": need(env, "SANDBOX_SHA"),
    }
    for key in API_PASSTHROUGH:
        if env.get(key):
            values[key] = env[key]
    return values


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    cmd = commands.add_parser("secrets", help="create missing local secrets")
    cmd.add_argument("path")
    cmd.add_argument("key_path")
    cmd = commands.add_parser("env-file", help="write the named process environment variables to a 0600 file")
    cmd.add_argument("path")
    cmd.add_argument("keys", nargs="+")
    cmd = commands.add_parser("compose-env", help="render the compose environment file; STRIPE_SECRET_KEY comes from the environment")
    cmd.add_argument("secrets_path")
    cmd.add_argument("path")
    cmd.add_argument("pairs", nargs="*")
    cmd = commands.add_parser("docker-daemon-config", help="exit 1 when the config changed")
    cmd.add_argument("path")
    cmd = commands.add_parser("services-json")
    cmd.add_argument("path")
    cmd.add_argument("compose")
    cmd.add_argument("stripe", nargs="?", default="")
    cmd = commands.add_parser("api-env", help="render the API environment from the process environment")
    cmd.add_argument("path")
    cmd.add_argument("runtime_json")
    args = parser.parse_args(argv)

    def pairs(items):
        out = {}
        for item in items:
            key, sep, value = item.partition("=")
            if not sep:
                raise ValueError(f"expected KEY=value, got {key}")
            out[key] = value
        return out

    try:
        if args.command == "secrets":
            ensure_secrets(args.path, args.key_path)
        elif args.command == "env-file":
            write_env(args.path, {key: os.environ.get(key, "") for key in args.keys})
        elif args.command == "compose-env":
            local = read_env(args.secrets_path)
            stripe = {"STRIPE_SECRET_KEY": os.environ.get("STRIPE_SECRET_KEY", "")}
            write_env(args.path, {**{k: local[k] for k in COMPOSE_SECRETS}, **stripe, **pairs(args.pairs)})
        elif args.command == "docker-daemon-config":
            return 1 if merge_docker_daemon(args.path) else 0
        elif args.command == "services-json":
            manifest = services_manifest(args.compose, args.stripe == "stripe")
            write_file(args.path, json.dumps(manifest, indent=2, sort_keys=True) + "\n", 0o644)
        elif args.command == "api-env":
            runtime = json.loads(Path(args.runtime_json).read_text())
            write_env(args.path, api_env(os.environ, runtime))
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"devbox_services {args.command}: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
