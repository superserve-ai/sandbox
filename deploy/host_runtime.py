"""Explicit scheduler limits shared by deployment and standby bootstrap."""
import shlex
import textwrap

CAPACITY_KEYS = ('VMD_SCHEDULABLE_MEMORY_MIB', 'VMD_SCHEDULABLE_VCPUS')
# Admission budgets, not machine totals. Other hosts require configured inputs.
HOST_CAPACITY = {'superserve-vmd-staging-2': (110000, 32)}


def capacity_inputs(instance_name, environment, configuration=None):
    config = configuration or {}
    defaults = HOST_CAPACITY.get(instance_name, ('', ''))
    fields = ('capacity_memory_mib', 'capacity_vcpus')
    return tuple(str(environment.get(key) or (config[field] if config.get(field) is not None else default))
                 for key, field, default in zip(CAPACITY_KEYS, fields, defaults))


def capacity_script(memory, vcpus, verify_only=False):
    script = '''
set -eu
capacity_host_id=$(sudo sed -n 's/^HOST_ID=//p' /etc/sandbox/vmd.env | tail -n 1)
if [ "$capacity_host_id" != default ]; then
    if [ -z "$capacity_host_id" ]; then
        echo 'ERROR: named host capacity requires HOST_ID' >&2
        exit 1
    fi
'''
    for key, supplied in zip(CAPACITY_KEYS, (memory, vcpus)):
        script += f'''
    capacity=$(sudo sed -n 's/^{key}=//p' /etc/sandbox/vmd.env | tail -n 1)
'''
        if not verify_only:
            script += f'''
    if [ -z "$capacity" ]; then
        capacity={shlex.quote(supplied)}
        # Validate the whole pair before persisting either value below.
    fi
'''
        script += f'''
    if ! awk -v value="$capacity" 'BEGIN {{ exit !(value ~ /^[0-9]+$/ && value+0 > 0 && value+0 <= 2147483647) }}'; then
        echo 'ERROR: named host requires positive explicit {key}; configure scheduler limits before activation' >&2
        exit 1
    fi
    {key}="$capacity"
'''
    if not verify_only:
        for key in CAPACITY_KEYS:
            script += f'''
    if [ -z "$(sudo sed -n 's/^{key}=//p' /etc/sandbox/vmd.env | tail -n 1)" ]; then
        sudo sed -i '/^{key}=/d' /etc/sandbox/vmd.env
        printf '{key}=%s\\n' "${key}" | sudo tee -a /etc/sandbox/vmd.env >/dev/null
    fi
'''
    return textwrap.dedent(script + '\nfi\n')
