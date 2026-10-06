#!/usr/bin/env python3
"""Observe the unchanged target revision's read-only release proof."""
import argparse
import hashlib
import importlib.util
import json
import linecache
import os
from pathlib import Path
import re
import subprocess
import sys
import time


def safe(value):
    text = str(value)
    for name in ('GH_TOKEN', 'GITHUB_TOKEN'):
        token = os.environ.get(name)
        if token:
            text = text.replace(token, '[REDACTED]')
    text = re.sub(r'(?:gh[pousr]_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+)', '[REDACTED]', text)
    text = re.sub(r'(?i)(authorization[:=]\s*)[^\r\n]+', r'\1[REDACTED]', text)
    text = re.sub(r'(https?://)[^/@\s]+:[^/@\s]+@', r'\1[REDACTED]@', text)
    return text


def emit(event, **fields):
    print(safe(json.dumps({'event': event, **fields}, sort_keys=True, default=str)), flush=True)


def summarize(payload):
    if not isinstance(payload, dict):
        return {'type': type(payload).__name__}
    if 'workflow_runs' in payload:
        keys = ('id', 'path', 'head_branch', 'head_sha', 'event', 'status', 'conclusion', 'run_attempt', 'updated_at')
        return {'total_count': payload.get('total_count'), 'workflow_runs': [
            {k: r.get(k) for k in keys} for r in payload['workflow_runs']]}
    if 'jobs' in payload:
        return {'total_count': payload.get('total_count'), 'jobs': [
            {k: j.get(k) for k in ('id', 'name', 'status', 'conclusion')} for j in payload['jobs']]}
    if 'object' in payload:
        return {'ref': payload.get('ref'), 'sha': payload['object'].get('sha')}
    return {k: payload[k] for k in ('message', 'status') if k in payload}


def observed_run(args, **kwargs):
    allowed = args[:2] == ['gh', 'api'] or (args[0] == 'git' and args[1] in ('fetch', 'merge-base', 'log'))
    if not allowed or any(x in args for x in ('--method', '-X', '--field', '-f', '-F', '--input')):
        raise RuntimeError('Diagnostic wrapper permits only the original read-only proof commands')
    emit('command_start', args=args, timeout=kwargs.get('timeout'))
    started = time.monotonic()
    actual = [*args, '--include'] if args[:2] == ['gh', 'api'] else args
    try:
        result = subprocess.run(actual, **kwargs)
    except (OSError, subprocess.TimeoutExpired) as exc:
        emit('command_exception', category=type(exc).__name__, elapsed=round(time.monotonic()-started, 3))
        raise
    stdout = result.stdout
    if args[:2] == ['gh', 'api']:
        normalized = stdout.replace('\r\n', '\n')
        match = re.match(r'\A(HTTP/[^\n]+)\n(.*?)\n\n(.*)\Z', normalized, re.S)
        if match:
            headers = {}
            for line in match.group(2).splitlines():
                key, _, value = line.partition(':')
                if key.lower() in ('x-github-request-id', 'x-ratelimit-remaining', 'x-ratelimit-reset', 'retry-after', 'date'):
                    headers[key.lower()] = value.strip()
            emit('http_response', status=match.group(1), headers=headers)
            stdout = match.group(3)
        try:
            emit('api_payload', **summarize(json.loads(stdout)))
        except (ValueError, TypeError) as exc:
            emit('api_payload_parse_failure', category=type(exc).__name__, bytes=len(stdout))
    else:
        emit('git_result', stdout=stdout[:12000], stderr=result.stderr[:1200])
    emit('command_end', returncode=result.returncode, elapsed=round(time.monotonic()-started, 3), stderr=result.stderr[:1200])
    return subprocess.CompletedProcess(args, result.returncode, stdout, result.stderr)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--target', required=True)
    parser.add_argument('--repository', required=True)
    args = parser.parse_args()
    if not re.fullmatch('[0-9a-f]{40}', args.target) or args.repository != 'superserve-ai/sandbox':
        raise SystemExit('Expected an exact sandbox repository target')
    path = Path('.github/workflows/scripts/wait-for-push-ci.py').resolve()
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    if head != args.target:
        raise SystemExit('Checkout does not match the explicit failed main SHA')
    source = path.read_bytes()
    exact = subprocess.check_output(['git', 'show', f'{args.target}:.github/workflows/scripts/wait-for-push-ci.py'])
    if source != exact:
        raise SystemExit('Proof source differs from the target commit')
    shallow = subprocess.check_output(['git', 'rev-parse', '--is-shallow-repository'], text=True).strip()
    emit('context', target=args.target, checkout=head, proof_sha256=hashlib.sha256(source).hexdigest(), shallow=shallow,
         dispatch_sha=os.environ.get('GITHUB_SHA'), actual_event=os.environ.get('GITHUB_EVENT_NAME'), proof_event='push', python=sys.version.split()[0])
    spec = importlib.util.spec_from_file_location('target_release_proof', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    def trace(frame, event, value):
        if frame.f_code.co_filename != str(path):
            return trace
        if event == 'exception':
            emit('proof_exception', function=frame.f_code.co_name, line=frame.f_lineno, category=value[0].__name__)
        elif event == 'return':
            result = value if isinstance(value, (bool, int, type(None))) else type(value).__name__
            emit('proof_return', function=frame.f_code.co_name, line=frame.f_lineno, result=result)
        elif event == 'line':
            source_line = linecache.getline(str(path), frame.f_lineno).strip()
            if source_line.startswith(('if ', 'elif ', 'for ', 'return ', 'raise ', 'except ')):
                state = {}
                for key in ('attempt', 'pending', 'baseline', 'names', 'success', 'total', 'page', 'changed'):
                    if key in frame.f_locals:
                        val = frame.f_locals[key]
                        state[key] = sorted(val) if isinstance(val, set) else val
                item = frame.f_locals.get('item')
                if isinstance(item, dict):
                    state['item'] = {k: item.get(k) for k in ('id', 'head_sha', 'status', 'conclusion', 'event', 'run_attempt')}
                emit('proof_decision', function=frame.f_code.co_name, line=frame.f_lineno, source=source_line, state=state)
        return trace

    sys.settrace(trace)
    try:
        ci = module.wait_for_ci(args.repository, args.target, 'push', run=observed_run)
        migration = module.wait_for_migration_baseline(args.repository, args.target, 'push', run=observed_run) if ci else False
    finally:
        sys.settrace(None)
    emit('result', ci=ci, migration_baseline=migration)
    return 0 if ci and migration else 1


if __name__ == '__main__':
    raise SystemExit(main())
