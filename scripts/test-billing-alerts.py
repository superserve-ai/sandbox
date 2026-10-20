#!/usr/bin/env python3
"""Exercise rendered alert predicates against PromQL and real console fixtures."""
import json
import re
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    plan = next(
        event['test_plan']
        for event in map(json.loads, Path(sys.argv[1]).read_text().splitlines())
        if event.get('type') == 'test_plan' and event.get('@testrun') == 'enabled'
    )
    rules = []
    for change in plan['resource_changes']:
        if change['type'] != 'google_monitoring_alert_policy':
            continue
        policy = change['change']['after']
        for condition in policy['conditions']:
            for log in condition.get('condition_matched_log') or []:
                pattern = json.loads(re.search(r'textPayload=~("(?:\\.|[^"\\])*")', log['filter']).group(1))
                subprocess.run(['go', 'run', './scripts/testdata/billing-console', pattern], check=True)
            for query in condition.get('condition_prometheus_query_language') or []:
                rules.append({'alert': change['index'], 'expr': query['query'], 'for': query['duration']})
    queries = plan['output_changes']['metric_queries']['after']
    common = 'project_id="example-project",job="sandbox-controlplane"'

    def series(metric, labels, values, cell='us-east4-c', instance='a'):
        return {'series': f'{metric}{{{common},location="{cell}",instance="{instance}",{labels}}}', 'values': values}

    def gauge(state, values, **kwargs):
        return series('billing_event_backlog_capped', f'state="{state}"', values, **kwargs)

    def counter(operation, values, result='success', **kwargs):
        return series('billing_operations_total', f'operation="{operation}",result="{result}"', values, **kwargs)

    def test(name, inputs, expectations, at='6m'):
        return {'name': name, 'interval': '1m', 'input_series': inputs, 'alert_rule_test': [
            {'eval_time': at, 'alertname': alert, 'exp_alerts': ([{'exp_labels': {}, 'exp_annotations': {}}] if active else [])}
            for alert, active in expectations.items()
        ]}

    tests = [
        test('duplicated observations create one incident', [gauge('entitlement_paid_missing', '3+0x10'), gauge('entitlement_paid_missing', '3+0x10', instance='b')], {'paid_missing': True}),
        test('west is covered and debt unknown is separate', [gauge('entitlement_debt_unknown', '1+0x10', cell='us-west2-a')], {'debt_unknown': True, 'paid_missing': False}),
        test('healthy and recovered gauges clear', [gauge('entitlement_paid_missing', '3 3 0+0x8'), gauge('entitlement_debt_unknown', '0+0x10')], {'paid_missing': False, 'debt_unknown': False}),
        test('errors survive a process counter reset', [counter('entitlement_coverage_sample', '0 0 1 0 1 1 1', result='error')], {'sampler_errors': True}),
        test('first isolated error needs no zero baseline', [counter('usage_entitlement_backlog', '1+0x10', result='error')], {'sampler_errors': True}, at='2m'),
        test('first observation eventually clears', [counter('usage_entitlement_backlog', '1+0x10', result='error')], {'sampler_errors': False}, at='8m'),
        test('old errors age out', [counter('usage_entitlement_backlog', '0 1 1+0x10', result='error')], {'sampler_errors': False}, at='8m'),
        test('healthy east cannot hide missing west', [counter('usage_entitlement_backlog', '0+2x10')], {'silent-east-usage_entitlement_backlog': False, 'silent-west-usage_entitlement_backlog': True}),
        test('frozen counter is not a healthy heartbeat', [counter('usage_entitlement_backlog', '10+0x10')], {'silent-east-usage_entitlement_backlog': True}),
        test('never seen coverage is missing', [], {'silent-east-entitlement_coverage_sample': True}),
        test('counter resets with progress stay healthy', [counter('usage_entitlement_backlog', '0 2 4 0 2 4 6')], {'silent-east-usage_entitlement_backlog': False}),
        test('progress resumes after a stall', [counter('usage_entitlement_backlog', '10+0x6 12 14 16')], {'silent-east-usage_entitlement_backlog': False}, at='9m'),
    ]
    tests[0]['promql_expr_test'] = [{'expr': queries['paid_missing'], 'eval_time': '6m', 'exp_samples': [{'labels': '{}', 'value': 3}]}]
    with tempfile.TemporaryDirectory(prefix='billing-alerts-') as tmp:
        root = Path(tmp)
        (root / 'rules.yml').write_text(json.dumps({'groups': [{'name': 'billing', 'interval': '1m', 'rules': rules}]}))
        (root / 'tests.yml').write_text(json.dumps({'rule_files': ['rules.yml'], 'evaluation_interval': '1m', 'tests': tests}))
        subprocess.run([sys.argv[2], 'test', 'rules', str(root / 'tests.yml')], check=True)
    print(f'{len(tests)} billing alert behavior scenarios passed')


if __name__ == '__main__':
    main()
