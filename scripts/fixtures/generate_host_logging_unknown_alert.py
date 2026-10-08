#!/usr/bin/env python3
"""Regenerate unknown interpolation evidence using only local terraform_data."""
import json
from pathlib import Path
import subprocess
import tempfile

CONFIG = '''
variable "window" { default = "5m" }
variable "predicate" { default = "true" }
resource "terraform_data" "host" { input = "123456" }
output "query" {
  value = "(sum(sum_over_time({\\"collector_host_id\\" = \\"${terraform_data.host.output}\\"}[${var.window}])) or vector(0)) == 0"
}
output "filter" {
  value = "resource.type=\\"gce_instance\\" AND resource.labels.instance_id=\\"${terraform_data.host.output}\\" AND labels.host_logging_heartbeat=\\"${var.predicate}\\""
}
'''


def generate():
    with tempfile.TemporaryDirectory(prefix='host-alert-unknown-') as directory:
        def terraform(*args):
            return subprocess.check_output(['terraform', *args], cwd=directory, text=True)

        Path(directory, 'main.tf').write_text(CONFIG)
        terraform('init', '-input=false')
        terraform('apply', '-input=false', '-auto-approve')
        evidence = {'terraform_version': json.loads(terraform('version', '-json'))['terraform_version'],
                    'cases': {}}
        for name, variables in {'identity_only': [], 'window_change': ['-var=window=60m'],
                                'predicate_change': ['-var=predicate=false']}.items():
            case = {}
            for phase, extra in {'known': [], 'replacement': ['-replace=terraform_data.host']}.items():
                terraform('plan', '-input=false', '-out=plan', *variables, *extra)
                case[phase] = json.loads(terraform('show', '-json', 'plan'))['output_changes']
            evidence['cases'][name] = case
        return evidence


if __name__ == '__main__':
    Path(__file__).with_name('host_logging_unknown_alert.json').write_text(
        json.dumps(generate(), indent=2) + '\n')
