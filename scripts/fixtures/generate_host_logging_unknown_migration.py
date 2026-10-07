#!/usr/bin/env python3
"""Capture hidden migration edits with local Terraform built-in resources only."""
import json
from pathlib import Path
import subprocess
import tempfile

CONFIG = '''
resource "terraform_data" "host" { input = "123456" }
locals {
  target = {
    baseline = "logging: {}"
    deadline = "2099-01-01T00:00:00Z"
    drained_instance_ids = []
    initialize_instance_ids = []
    instance_ids = [terraform_data.host.output]
    legacy_policy_name = "legacy-policy"
    phase = "preserve"
    retired = "{}"
    verified_instance_ids = []
  }
}
resource "terraform_data" "migration" { input = local.target }
output "artifact" { value = ARTIFACT_EXPRESSION }
'''


def generate():
    with tempfile.TemporaryDirectory(prefix='host-migration-unknown-') as directory:
        def terraform(*args):
            return subprocess.check_output(['terraform', *args], cwd=directory, text=True)

        config = Path(directory, 'main.tf')
        config.write_text(CONFIG.replace('ARTIFACT_EXPRESSION', 'jsonencode(local.target)'))
        terraform('init', '-input=false')
        terraform('apply', '-input=false', '-auto-approve')
        evidence = {'terraform_version': json.loads(terraform('version', '-json'))['terraform_version'],
                    'cases': {}}
        expressions = {
            'identity_only': 'jsonencode(local.target)',
            'phase_change': 'jsonencode(merge(local.target, {phase = "overlap"}))',
            'deadline_change': 'jsonencode(merge(local.target, {deadline = "2099-02-01T00:00:00Z"}))',
            'baseline_change': 'jsonencode(merge(local.target, {baseline = "logging: {receivers: {}}"}))',
        }
        for name, expression in expressions.items():
            config.write_text(CONFIG.replace('ARTIFACT_EXPRESSION', expression))
            case = {}
            for phase, extra in {'known': [], 'replacement': ['-replace=terraform_data.host']}.items():
                terraform('plan', '-input=false', '-out=plan', *extra)
                plan = json.loads(terraform('show', '-json', 'plan'))
                case[phase] = {'artifact': plan['output_changes']['artifact']}
                if phase == 'replacement':
                    change = next(r['change'] for r in plan['resource_changes']
                                  if r['address'] == 'terraform_data.migration')
                    # Keep the actual input diff; omit generated output/UUID
                    # metadata which is unrelated to this artifact proof.
                    case[phase]['migration'] = {'actions': change['actions']}
                    for section in ('before', 'after', 'after_unknown'):
                        case[phase]['migration'][section] = {'input': change[section]['input']}
            evidence['cases'][name] = case
        return evidence


if __name__ == '__main__':
    Path(__file__).with_name('host_logging_unknown_migration.json').write_text(
        json.dumps(generate(), indent=2) + '\n')
