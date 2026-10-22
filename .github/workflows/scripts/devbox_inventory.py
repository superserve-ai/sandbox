"""List, select and destroy workflow-managed devboxes by label identity, never by name prefix."""
import argparse
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field

import devbox_contract as contract

ACTIONS = ('list', 'destroy-named', 'destroy-mine', 'destroy-all', 'auto-delete')
PROJECT_IN_LINK = re.compile(r'/projects/([^/]+)/')
CLOUD_ERRORS = (RuntimeError, subprocess.TimeoutExpired, ValueError)
ADOPTION_SLACK_SECONDS = 3600


@dataclass
class Resource:
    kind: str
    name: str
    zone: str
    labels: dict
    created: str = ''
    link: str = ''
    users: list = field(default_factory=list)
    manifest: dict | None = None
    recorded: list = field(default_factory=list)
    status: str = ''
    adopted: bool = False


@dataclass
class Box:
    name: str
    devbox_id: str
    resources: list

    def of(self, kind):
        return [r for r in self.resources if r.kind == kind]

    @property
    def instance(self):
        """The instance the box lives on: a fallback attempt in an earlier zone can leave another one behind."""
        return max(self.of('instance'), default=None, key=lambda i: (
            bool(i.manifest) and i.manifest.get('zone') == i.zone and i.manifest.get('state') != 'creating',
            _created(i.created) or 0))

    @property
    def primary(self):
        return self.instance or next(r for r in self.resources if not r.adopted)

    @property
    def zones(self):
        return sorted({r.zone for r in self.resources if r.zone})

    @property
    def zone(self):
        return ', '.join(self.zones)

    @property
    def owner(self):
        return self.primary.labels.get('owner', '')

    @property
    def expires_at(self):
        value = self.primary.labels.get('expires-at', '')
        return int(value) if value.isdigit() else None

    @property
    def manifest(self):
        return self.instance.manifest if self.instance else None

    @property
    def missing(self):
        return sorted(f'{kind} {name}' for kind, name in expected(self.name, self.devbox_id)
                      - {(r.kind, r.name) for r in self.resources})

    @property
    def unhandled(self):
        known = {(r['type'], r['name'], r.get('zone')) for zone in contract.DEVBOX_ZONES
                 for r in contract.resources(self.name, self.devbox_id, zone)}
        recorded = [r for i in self.of('instance') for r in i.recorded]
        return [f'{r.get("type")} {r.get("name")}' if isinstance(r, dict) else str(r) for r in recorded
                if not isinstance(r, dict) or (r.get('type'), r.get('name'), r.get('zone')) not in known]

    def identity_labels(self):
        anchor = self.primary
        return {key: anchor.labels[key] for key in contract.LABEL_KEYS if key in anchor.labels}

    @property
    def state(self):
        if not self.instance:
            return 'orphaned (no VM)'
        manifest_state = (self.manifest or {}).get('state')
        return f'{self.instance.status} / {manifest_state}' if manifest_state else self.instance.status

    def target(self):
        return {'name': self.name, 'zone': self.zone, 'devbox_id': self.devbox_id}


class Gcloud:
    def __init__(self, project):
        self.project = project

    def _run(self, *args, check=True):
        result = subprocess.run(['gcloud', *args, f'--project={self.project}'],
                                capture_output=True, text=True, timeout=900)
        if check and result.returncode:
            raise RuntimeError(f'gcloud {" ".join(args[:3])} failed: {result.stderr.strip()}')
        return result

    def _list(self, *args):
        return json.loads(self._run(*args, '--format=json').stdout or '[]')

    def instances(self):
        return self._list('compute', 'instances', 'list')

    def disks(self):
        return self._list('compute', 'disks', 'list')

    def buckets(self):
        return self._list('storage', 'buckets', 'list')

    def set_metadata(self, name, zone, key, value):
        with tempfile.NamedTemporaryFile('w', suffix='.json') as handle:
            handle.write(value)
            handle.flush()
            return self._failure('compute', 'instances', 'add-metadata', name, f'--zone={zone}',
                                 f'--metadata-from-file={key}={handle.name}')

    def label(self, resource, labels):
        values = ','.join(f'{key}={value}' for key, value in labels.items())
        if resource.kind == 'bucket':
            return self._failure('storage', 'buckets', 'update', f'gs://{resource.name}', f'--update-labels={values}')
        return self._failure('compute', 'disks', 'add-labels', resource.name, f'--zone={resource.zone}',
                             f'--labels={values}')

    def delete_instance(self, name, zone):
        return self._failure('compute', 'instances', 'delete', name, f'--zone={zone}', '--keep-disks=all', '--quiet')

    def delete_disk(self, name, zone):
        return self._failure('compute', 'disks', 'delete', name, f'--zone={zone}', '--quiet')

    def delete_bucket(self, name):
        emptied = self._run('storage', 'rm', '--recursive', '--all-versions', f'gs://{name}/**', check=False)
        failure = self._failure('storage', 'buckets', 'delete', f'gs://{name}', '--quiet')
        return failure and '\n'.join(filter(None, [emptied.stderr.strip() if emptied.returncode else '', failure]))

    def _failure(self, *args):
        result = self._run(*args, check=False)
        return (result.stderr.strip() or f'exit status {result.returncode}') if result.returncode else None


def expected(name, devbox_id):
    return {(r['type'], r['name']) for zone in contract.DEVBOX_ZONES for r in contract.resources(name, devbox_id, zone)}


def leftovers(name, devbox_id):
    instances = {n for kind, n in expected(name, devbox_id) if kind == 'instance'}
    return {(kind, n) for kind, n in expected(name, devbox_id)
            if kind == 'bucket' or (kind == 'disk' and n in instances)}


def _last(url):
    return (url or '').rsplit('/', 1)[-1]


UNREADABLE = 'devbox-manifest metadata without a readable resources list (fix or remove it on the instance)'
ABSENT = object()


def _raw_manifest(instance):
    for item in (instance.get('metadata') or {}).get('items') or []:
        if item.get('key') == contract.MANIFEST_METADATA_KEY:
            try:
                return json.loads(item.get('value') or '')
            except ValueError:
                return UNREADABLE
    return ABSENT


def _manifest(raw):
    try:
        return contract.validate_manifest(raw)
    except (ValueError, TypeError, AttributeError, KeyError):
        return None


def _recorded(raw):
    if raw is ABSENT:
        return []
    resources = raw.get('resources') if isinstance(raw, dict) else None
    return resources if isinstance(resources, list) else [UNREADABLE]


def _dict(value):
    return value if isinstance(value, dict) else {}


def _created(stamp):
    try:
        return datetime.datetime.fromisoformat(stamp.replace('Z', '+00:00')).timestamp()
    except (ValueError, AttributeError):
        return None


def collect(cloud):
    resources = []
    for i in cloud.instances():
        raw = _raw_manifest(i)
        resources.append(Resource('instance', i.get('name', ''), _last(i.get('zone')), _dict(i.get('labels')),
                                  i.get('creationTimestamp', ''), i.get('selfLink', ''), manifest=_manifest(raw),
                                  recorded=_recorded(raw), status=i.get('status', '')))
    resources += [Resource('disk', d.get('name', ''), _last(d.get('zone')), _dict(d.get('labels')),
                           d.get('creationTimestamp', ''), d.get('selfLink', ''), users=d.get('users') or [])
                  for d in cloud.disks()]
    resources += [Resource('bucket', b.get('name', ''), '', _dict(b.get('labels')), b.get('creation_time', ''))
                  for b in cloud.buckets()]
    return resources


def _placement(resource, project):
    if resource.kind == 'bucket':
        return None
    match = PROJECT_IN_LINK.search(resource.link)
    if not match or match.group(1) != project:
        return f'not in project {project}'
    try:
        contract.validate_zone(resource.zone)
    except contract.ContractError:
        return f'not in a devbox zone ({", ".join(contract.DEVBOX_ZONES)})'
    return None


def ineligibility(resource, project):
    name = resource.labels.get('devbox-name', '')
    try:
        contract.validate_name(name)
        devbox_id = contract.check_labels(resource.labels, name)
    except contract.ContractError as error:
        return str(error)
    if (resource.kind, resource.name) not in expected(name, devbox_id):
        return f'name does not match its devbox labels ({name}, {devbox_id})'
    return _placement(resource, project)


def _unlabelled(resource, project):
    return (resource.kind != 'instance' and all(key.startswith('goog-') for key in resource.labels)
            and _placement(resource, project) is None)


def _unadoptable(resource, group):
    links = {r.link for r in group if r.kind == 'instance'}
    foreign = [u for u in resource.users if u not in links]
    if foreign:
        return f'unlabelled and attached to {", ".join(map(_last, foreign))}'
    if resource.kind != 'bucket' and resource.zone not in {r.zone for r in group if not r.adopted}:
        return 'unlabelled and in a zone where the devbox that would claim it has no labelled resource'
    created = _created(resource.created)
    born = [t for t in (_created(r.created) for r in group if not r.adopted) if t is not None]
    if created is None or not born:
        return 'unlabelled and its creation time or its devbox creation time is unknown'
    if created < min(born) - ADOPTION_SLACK_SECONDS:
        return 'unlabelled and older than the devbox that would claim it'
    if created > max(born) + ADOPTION_SLACK_SECONDS:
        return 'unlabelled and newer than the create run of the devbox that would claim it'
    return None


def inventory(resources, project):
    """Group labelled resources by identity, then adopt the unlabelled boot disk or bucket that create
    can leave between its create and label calls: only by exact name under exactly one labelled box,
    only when detached or attached to that box, and only when not older than that box."""
    groups, ignored = {}, []
    for resource in resources:
        reason = ineligibility(resource, project)
        if reason:
            if resource.labels.get('managed-by') == contract.MANAGED_BY:
                ignored.append((resource, reason))
            continue
        key = (resource.labels['devbox-name'], resource.labels['devbox-id'])
        groups.setdefault(key, []).append(resource)
    claims = {}
    for key in groups:
        for item in leftovers(*key):
            claims.setdefault(item, []).append(key)
    for resource in resources:
        owners = claims.get((resource.kind, resource.name), [])
        if not owners or not _unlabelled(resource, project):
            continue
        if len(owners) > 1:
            owners = [key for key in owners if any(r.kind == 'instance' and r.link in resource.users
                                                   for r in groups[key])] or owners
        if len(owners) > 1:
            owners = [key for key in owners if _unadoptable(resource, groups[key]) is None] or owners
        reason = (f'unlabelled and claimed by {len(owners)} devboxes' if len(owners) > 1
                  else _unadoptable(resource, groups[owners[0]]))
        if reason:
            ignored.append((resource, reason))
            continue
        resource.adopted = True
        groups[owners[0]].append(resource)
    boxes = [Box(name, devbox_id, sorted(group, key=lambda r: (r.kind, r.name)))
             for (name, devbox_id), group in sorted(groups.items())]
    return boxes, ignored


def select(boxes, action, *, name='', owner='', now=0):
    if action == 'destroy-named':
        return [b for b in boxes if b.name == name]
    if action == 'destroy-mine':
        return [b for b in boxes if b.owner == owner]
    if action == 'destroy-all':
        return list(boxes)
    if action == 'auto-delete':
        return [b for b in boxes if b.expires_at is not None and b.expires_at <= now]
    return []


def set_token(targets):
    canonical = json.dumps(sorted((t['name'], t['zone'], t['devbox_id']) for t in targets))
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


def _utc(epoch):
    return datetime.datetime.fromtimestamp(epoch, datetime.UTC).strftime('%Y-%m-%d %H:%M UTC')


def _age(box, now):
    stamp = (box.manifest or {}).get('created_at') or box.primary.created
    try:
        created = datetime.datetime.fromisoformat(stamp.replace('Z', '+00:00')).timestamp()
    except (ValueError, AttributeError):
        return '?'
    hours = int((now - created) // 3600)
    return f'{hours // 24}d {hours % 24}h' if hours >= 24 else f'{hours}h'


def _cell(value):
    return ' '.join(str(value).split()).replace('|', '\\|')


def _revisions(box):
    manifest = box.manifest or {}
    running = next((v for v in (manifest.get('components'), manifest.get('revisions')) if isinstance(v, dict) and v), {})
    groups = {}
    for component, revision in running.items():
        if isinstance(revision, dict):
            key = f'{revision.get("branch") or "?"} @ {str(revision.get("sha") or "?")[:12]}'
            groups.setdefault(key, []).append(str(component))
    return _cell('; '.join(f'{key} ({", ".join(parts)})' for key, parts in groups.items()) or '?')


def render(boxes, ignored, now):
    if not boxes:
        lines = ['No workflow-managed devboxes found.']
    else:
        lines = ['| Name | Owner | Zone | State | Age | Expires at | Revisions | devbox-id |',
                 '| -- | -- | -- | -- | -- | -- | -- | -- |']
        for box in boxes:
            notes = [f'missing {", ".join(box.missing)}'] if box.missing else []
            notes += [f'unlabelled {", ".join(f"{r.kind} {r.name}" for r in box.resources if r.adopted)}'] \
                if any(r.adopted for r in box.resources) else []
            state = box.state + (f' (partial: {"; ".join(notes)})' if notes else '')
            expires = _utc(box.expires_at) if box.expires_at is not None else 'unset (never auto-deleted)'
            lines.append(f'| `{box.name}` | {box.owner or "?"} | {box.zone or "-"} | {state} | {_age(box, now)} '
                         f'| {expires} | {_revisions(box)} | `{box.devbox_id}` |')
        reachable = [b for b in boxes if b.instance]
        if reachable:
            lines += ['', 'Access (IAP tunnel):', '']
            for box in reachable:
                lines += [f'`{box.name}`:', '```', contract.forwarding_command(box.name, box.instance.zone), '```']
    if ignored:
        lines += ['', 'Ignored resources (never destroyed by these workflows):', '']
        lines += [f'- {r.kind} `{r.name}`: {reason}' for r, reason in ignored]
    return '\n'.join(lines)


def render_targets(targets):
    lines = ['| Name | Zone | devbox-id |', '| -- | -- | -- |']
    return '\n'.join(lines + [f'| `{t["name"]}` | {t["zone"] or "-"} | `{t["devbox_id"]}` |' for t in targets])


def plan(cloud, project, action, *, name='', actor='', confirm='', now=0):
    """Return (targets, report); raise SystemExit when the request must not proceed."""
    if action not in ACTIONS:
        raise SystemExit(f'Unknown action {action!r}')
    if action == 'destroy-named':
        try:
            contract.validate_name(name)
        except contract.ContractError as error:
            raise SystemExit(str(error)) from None
    boxes, ignored = inventory(collect(cloud), project)
    report = [render(boxes, ignored, now)]
    if action == 'list':
        return [], '\n'.join(report)
    owner = contract.normalize_owner(actor) if action == 'destroy-mine' else ''
    targets = [b.target() for b in select(boxes, action, name=name, owner=owner, now=now)]
    if not targets:
        return [], '\n'.join(report + ['', f'Nothing to destroy for {action}.'])
    report += ['', f'Target set for {action} ({len(targets)}):', '', render_targets(targets)]
    if action == 'destroy-all':
        token = set_token(targets)
        if not confirm:
            report += ['', f'Nothing was destroyed. To destroy exactly this set, rerun destroy-all with confirm `{token}`.']
            return [], '\n'.join(report)
        if confirm.strip() != token:
            raise SystemExit('\n'.join(report + ['', f'Confirmation does not match the current set (now `{token}`). '
                                                 'The set changed since it was approved; nothing was destroyed.']))
    return targets, '\n'.join(report)


def by_name(targets):
    names = {}
    for target in targets:
        names.setdefault(target['name'], []).append(target['devbox_id'])
    return [{'name': name, 'devbox_ids': ','.join(ids)} for name, ids in sorted(names.items())]


def find_with_blocked(cloud, project, name, devbox_id):
    """Return the box and every resource at one of its contract names that neither it nor another devbox
    provably owns; destroy refuses rather than leave such a resource behind and report the box gone."""
    resources = collect(cloud)
    boxes, ignored = inventory(resources, project)
    box = next((b for b in boxes if b.name == name and b.devbox_id == devbox_id), None)
    claimed = {id(r) for b in boxes for r in b.resources}
    reasons = {id(r): reason for r, reason in ignored}
    wanted = expected(name, devbox_id)
    return box, [(r, reasons.get(id(r), 'is not labelled as this devbox'))
                 for r in resources if id(r) not in claimed
                 and (((r.kind, r.name) in wanted and not _owned_elsewhere(r, name, devbox_id))
                      or _labelled_as(r, name, devbox_id))]


def _labelled_as(resource, name, devbox_id):
    labels = resource.labels
    return (labels.get('managed-by') == contract.MANAGED_BY and labels.get('devbox-name') == name
            and labels.get('devbox-id') == devbox_id)


def _owned_elsewhere(resource, name, devbox_id):
    labels = resource.labels
    other = labels.get('devbox-id')
    return (labels.get('managed-by') == contract.MANAGED_BY and labels.get('devbox-name') == name
            and other != devbox_id and isinstance(other, str) and contract.DEVBOX_ID_PATTERN.fullmatch(other) is not None
            and (resource.kind, resource.name) in expected(name, other))


def _delete(cloud, resource, instances):
    if resource.kind == 'bucket':
        return cloud.delete_bucket(resource.name)
    foreign = [u for u in resource.users if u not in {i.link for i in instances}]
    if foreign:
        return f'disk {resource.name} is attached to {", ".join(map(_last, foreign))}; not deleted'
    return cloud.delete_disk(resource.name, resource.zone)


def destroy(cloud, project, name, devbox_id, *, require_expired_at=None):
    """Delete exactly the resources of this devbox identity; succeed only when none remain.

    Unlabelled resources are labelled first so that any partial failure stays findable by a retry."""
    box, blocked = find_with_blocked(cloud, project, name, devbox_id)
    if blocked:
        raise SystemExit(f'Refusing to destroy {name} ({devbox_id}): ' + '; '.join(
            f'{r.kind} {r.name}: {reason}' for r, reason in blocked) + '. Nothing was deleted; resolve it and rerun.')
    if box is None:
        return f'`{name}` ({devbox_id}) is already gone.'
    if require_expired_at is not None and (box.expires_at is None or box.expires_at > require_expired_at):
        return f'`{name}` ({devbox_id}) is no longer expired; left in place.'
    if box.unhandled:
        raise SystemExit(f'Refusing to destroy {name} ({devbox_id}): its manifest records resources destroy cannot '
                         f'remove ({", ".join(box.unhandled)}); nothing was deleted.')
    for resource in [r for r in box.resources if r.adopted]:
        error = cloud.label(resource, box.identity_labels())
        if error:
            raise SystemExit(f'Could not label unlabelled {resource.kind} {resource.name} of {name} ({devbox_id}) '
                             f'before deleting; nothing was deleted, rerun to retry: {error}')
    for marked in [i for i in box.of('instance') if i.manifest is not None]:
        try:
            error = cloud.set_metadata(marked.name, marked.zone, contract.MANIFEST_METADATA_KEY,
                                       json.dumps(contract.with_state(marked.manifest, 'destroying')))
        except contract.ContractError as invalid:
            error = str(invalid)
        if error:
            print(f'::warning::Could not mark {name} in {marked.zone} as destroying: {error}')
    instances = box.of('instance')
    failures = [cloud.delete_instance(i.name, i.zone) for i in instances]
    failures += [_delete(cloud, r, instances) for r in box.resources if r.kind != 'instance']
    try:
        remaining, left = find_with_blocked(cloud, project, name, devbox_id)
    except CLOUD_ERRORS as error:
        raise SystemExit(f'Could not verify destroy of {name} ({devbox_id}): {error}\n'
                         + '\n'.join(f'- {f}' for f in failures if f)) from None
    if remaining or left:
        details = ([f'- {r.kind} {r.name}' for r in remaining.resources] if remaining else []) \
            + [f'- {r.kind} {r.name}: {reason}' for r, reason in left] + [f'- {f}' for f in failures if f]
        raise SystemExit(f'Destroy of {name} ({devbox_id}) incomplete; rerun to retry. Remaining:\n' + '\n'.join(details))
    return f'Destroyed `{name}` ({devbox_id}): ' + ', '.join(f'{r.kind} {r.name}' for r in box.resources)


def destroy_name(cloud, project, name, devbox_ids, *, require_expired_at=None):
    """Destroy every identity approved for one name; report each and fail if any is incomplete."""
    try:
        contract.validate_name(name)
        ids = [contract.validate_devbox_id(i) for i in devbox_ids.split(',')]
    except contract.ContractError as error:
        raise SystemExit(str(error)) from None
    reports, incomplete = [], []
    for devbox_id in ids:
        try:
            reports.append(destroy(cloud, project, name, devbox_id, require_expired_at=require_expired_at))
        except SystemExit as stop:
            reports.append(str(stop.code))
            incomplete.append(devbox_id)
        except CLOUD_ERRORS as error:
            reports.append(f'Destroy of {name} ({devbox_id}) failed: {error}; rerun to retry.')
            incomplete.append(devbox_id)
    if incomplete:
        raise SystemExit('\n\n'.join(reports + [f'Destroy incomplete for {name}: {", ".join(incomplete)}']))
    return '\n\n'.join(reports)


def _publish(report, outputs=None):
    print(report)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as handle:
            handle.write(report + '\n')
    if outputs and os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a') as handle:
            handle.writelines(f'{key}={value}\n' for key, value in outputs.items())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    planning = commands.add_parser('plan')
    planning.add_argument('--action', required=True, choices=ACTIONS)
    planning.add_argument('--name', default='')
    planning.add_argument('--actor', default='')
    planning.add_argument('--confirm', default='')
    destroying = commands.add_parser('destroy')
    destroying.add_argument('--name', required=True)
    destroying.add_argument('--devbox-ids', required=True, help='comma-separated devbox-ids for this name')
    destroying.add_argument('--require-expired', action='store_true')
    args = parser.parse_args(argv)
    cloud, now = Gcloud(contract.PROJECT), int(time.time())
    try:
        if args.command == 'plan':
            targets, report = plan(cloud, contract.PROJECT, args.action, name=args.name, actor=args.actor,
                                   confirm=args.confirm, now=now)
            matrix = by_name(targets)
            _publish(report, {'targets': json.dumps(matrix), 'count': len(matrix)})
        else:
            _publish(destroy_name(cloud, contract.PROJECT, args.name, args.devbox_ids,
                                  require_expired_at=now if args.require_expired else None))
    except SystemExit as stop:
        if isinstance(stop.code, str):
            _publish(stop.code)
            raise SystemExit(1) from None
        raise
    except contract.ContractError as error:
        _publish(f'Failed: {error}')
        raise SystemExit(1) from None
    except CLOUD_ERRORS as error:
        _publish(f'Failed: {error}. Rerun to retry.')
        raise SystemExit(1) from None


if __name__ == '__main__':
    sys.exit(main())
