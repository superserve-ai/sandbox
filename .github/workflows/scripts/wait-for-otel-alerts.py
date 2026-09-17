#!/usr/bin/env python3
"""Require same-revision production alert applies before collector rollout."""

import json
import os
import subprocess
import time


def api(path):
    result = subprocess.run(
        ['gh', 'api', '--paginate', '--slurp', path],
        check=True, capture_output=True, text=True,
    )
    return json.loads(result.stdout)


def alert_applies_ready(repository, sha, required_jobs):
    pages = api(f'repos/{repository}/actions/workflows/terraform-cd.yml/runs'
                f'?head_sha={sha}&event=push&branch=main&per_page=100')
    runs = [run for page in pages for run in page['workflow_runs']
            if run['head_sha'] == sha and run['head_branch'] == 'main']
    if not runs:
        return False
    run = max(runs, key=lambda item: item['id'])
    pages = api(f'repos/{repository}/actions/runs/{run["id"]}/jobs?filter=latest&per_page=100')
    jobs = {job['name']: job for page in pages for job in page['jobs']}
    for name in required_jobs:
        job = jobs.get(name)
        if job and job['status'] == 'completed' and job['conclusion'] != 'success':
            raise RuntimeError(f'{name} concluded {job["conclusion"]}; refusing collector rollout')
    if all(name in jobs and jobs[name]['status'] == 'completed' and
           jobs[name]['conclusion'] == 'success' for name in required_jobs):
        return True
    if run['status'] == 'completed':
        raise RuntimeError('Terraform CD finished without all required alert applies; refusing collector rollout')
    return False


def main():
    required_jobs = [name for flag, name in (
        ('OTEL_USE4_ENABLED', 'Apply production/us-east4'),
        ('OTEL_USW2_ENABLED', 'Apply production/us-west2'),
    ) if os.environ.get(flag)]
    if not required_jobs:
        return
    for _ in range(90):
        if alert_applies_ready(os.environ['GITHUB_REPOSITORY'], os.environ['GITHUB_SHA'], required_jobs):
            print('Same-revision production alert applies succeeded.')
            return
        print('Waiting for same-revision Terraform CD alert applies...', flush=True)
        time.sleep(20)
    raise RuntimeError('Timed out waiting for same-revision production alert applies; refusing collector rollout')


if __name__ == '__main__':
    main()
