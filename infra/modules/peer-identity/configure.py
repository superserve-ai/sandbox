#!/usr/bin/env python3
"""Reconcile the managed identity API fields absent from the pinned provider."""
import json
import os
import subprocess
import tempfile
from pathlib import Path


def inline_certificate_issuance_config(config):
    return {
        "inlineCertificateIssuanceConfig": {
            "caPools": {config["region"]: config["ca_pool"]},
            "keyAlgorithm": "ECDSA_P256",
            "lifetime": "86400s",
            "rotationWindowPercentage": 50,
        }
    }


def attestation_policy(config):
    return {
        "attestationRules": [{
            "googleCloudResource": (
                f"//compute.googleapis.com/projects/{config['project_number']}"
                f"/uid/zones/{config['zone']}/instances/{config['instance_id']}"
            )
        }]
    }


def configure(config):
    def gcloud(*args):
        result = subprocess.run(
            ["gcloud", *args, f"--project={config['project_id']}", "--quiet", "--format=json"],
            check=True, stdout=subprocess.PIPE, text=True,
        )
        return json.loads(result.stdout) if result.stdout.strip() else None

    pool = ["iam", "workload-identity-pools"]
    location = ["--location=global"]
    pools = gcloud(*pool, "list", *location)
    existing = next((p for p in pools if p["name"].endswith("/" + config["pool_id"])), None)
    if existing is None:
        gcloud(*pool, "create", config["pool_id"], *location, "--mode=TRUST_DOMAIN")
    elif existing.get("mode") != "TRUST_DOMAIN" or existing.get("state") != "ACTIVE":
        raise RuntimeError("peer pool must be an active TRUST_DOMAIN")
    with tempfile.TemporaryDirectory() as tmp:
        issuance = Path(tmp) / "issuance.json"
        issuance.write_text(json.dumps(inline_certificate_issuance_config(config)))
        gcloud(*pool, "update", config["pool_id"], *location,
               f"--inline-certificate-issuance-config-file={issuance}")
        scoped = [*location, f"--workload-identity-pool={config['pool_id']}"]
        namespaces = gcloud(*pool, "namespaces", "list", *scoped)
        if not any(n["name"].endswith("/" + config["namespace"]) for n in namespaces):
            gcloud(*pool, "namespaces", "create", config["namespace"], *scoped)
        scoped.append(f"--namespace={config['namespace']}")
        identities = gcloud(*pool, "managed-identities", "list", *scoped)
        if not any(i["name"].endswith("/" + config["identity"]) for i in identities):
            gcloud(*pool, "managed-identities", "create", config["identity"], *scoped)
        policy = Path(tmp) / "attestation.json"
        policy.write_text(json.dumps(attestation_policy(config)))
        gcloud(*pool, "managed-identities", "set-attestation-rules", config["identity"],
               *scoped, f"--policy-file={policy}")
    principal = (f"principalSet://iam.googleapis.com/projects/{config['project_number']}/locations/global/"
                 f"workloadIdentityPools/{config['pool_id']}/*")
    for role in ("roles/privateca.workloadCertificateRequester", "roles/privateca.poolReader"):
        gcloud("privateca", "pools", "add-iam-policy-binding", config["ca_pool"],
               f"--location={config['region']}", f"--member={principal}", f"--role={role}")
    instance = gcloud("compute", "instances", "describe", config["instance_name"], f"--zone={config['zone']}")
    if str(instance["id"]) != config["instance_id"]:
        raise RuntimeError("instance ID changed; regenerate the Terraform plan")
    if instance["serviceAccounts"][0]["email"] != config["runtime_email"]:
        raise RuntimeError("dedicated runtime identity must be attached first")
    desired = config['spiffe_uri'].removeprefix('spiffe://')
    current = instance.get('workloadIdentityConfig', {})
    if current.get('identity') not in (None, '', desired):
        raise RuntimeError('existing managed identity differs; review immutable identity migration')
    if current.get('identity') != desired or not current.get('identityCertificateEnabled'):
        if instance.get('labels', {}).get('sandbox_status') == 'ready':
            raise RuntimeError('remove Host 2 from ready discovery before identity enablement')
        gcloud("compute", "instances", "update", config["instance_name"], f"--zone={config['zone']}",
               f"--identity={desired}", "--identity-certificate", "--most-disruptive-allowed-action=RESTART")


if __name__ == "__main__":
    configure(json.loads(os.environ["PEER_IDENTITY_CONFIG"]))
