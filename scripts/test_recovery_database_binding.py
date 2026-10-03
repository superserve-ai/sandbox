"""Private database identity classification, using synthetic secret providers."""

import copy
import unittest

from migrate_database import MigrationError
import recovery_database_binding as binding


class BindingTest(unittest.TestCase):
    def setUp(self):
        self.secret = "database-url-usw2"
        self.project = binding.BINDINGS[self.secret]
        self.rows = [{"name": f"projects/rayai-prod/secrets/{self.secret}/versions/{n}",
                      "createTime": f"2026-01-0{n}T00:00:00Z", "state": "ENABLED"}
                     for n in range(1, 4)]
        self.start, self.end = "2026-01-02T12:00:00Z", "2026-01-04T00:00:00Z"
        self.payload = f"postgresql://postgres:private-value@db.{self.project}.supabase.co:5432/postgres"

    def run_binding(self, rows=None, payload=None, after=None):
        rows = self.rows if rows is None else rows
        calls = []
        snapshots = iter([rows, rows if after is None else after])
        def read(name):
            calls.append(name)
            return self.payload if payload is None else payload
        result = binding.classify(self.secret, earliest_start=self.start, observed_at=self.end,
                                  list_versions=lambda _: next(snapshots), read_payload=read)
        return result, calls

    def test_all_potentially_loaded_versions_checked_without_values_in_output(self):
        result, calls = self.run_binding()
        self.assertEqual(calls, [row['name'] for row in self.rows[1:]])
        self.assertEqual(len(result['versions']), 2)
        self.assertNotIn('private-value', repr(result))
        self.assertNotIn('postgresql://', repr(result))
        self.assertNotIn(self.project, repr(result))

    def test_old_loaded_version_cannot_be_hidden_by_current_latest(self):
        for state in ['DISABLED', 'DESTROYED']:
            rows = copy.deepcopy(self.rows)
            rows[1]['state'] = state
            with self.subTest(state=state), self.assertRaises(MigrationError):
                self.run_binding(rows)
        rows = copy.deepcopy(self.rows)
        rows[0]['state'] = 'DESTROYED'
        self.run_binding(rows)  # Retired before any relevant instance startup.

    def test_missing_history_future_creation_and_rotation_fail_closed(self):
        variants = [self.rows[1:], self.rows[:1] + self.rows[2:], self.rows + [self.rows[-1]]]
        for key, value in [('name', 'projects/other/secrets/database-url-usw2/versions/2'),
                           ('createTime', '2026-02-01T00:00:00Z'), ('state', 'UNKNOWN')]:
            rows = copy.deepcopy(self.rows)
            rows[1][key] = value
            variants.append(rows)
        for rows in variants:
            with self.subTest(rows=rows), self.assertRaises(MigrationError):
                self.run_binding(rows)
        with self.assertRaises(MigrationError):
            self.run_binding(after=self.rows[:-1])
        changed = copy.deepcopy(self.rows)
        changed[1]['etag'] = 'rotation'
        with self.assertRaises(MigrationError):
            self.run_binding(after=changed)

    def test_identity_parser_rejects_redirects_and_suppresses_secret_errors(self):
        for value in [self.payload.replace(self.project, 'otherproject'),
                      self.payload + '?host=attacker.test', self.payload + '#fragment',
                      self.payload.replace('/postgres', '/other'), 'private-value', b'\xffprivate-value',
                      self.payload.replace(':5432', ':6432'),
                      self.payload + '?sslmode=require&sslmode=disable']:
            with self.subTest(value_type=type(value)), self.assertRaises(MigrationError) as caught:
                self.run_binding(payload=value)
            self.assertNotIn('private-value', str(caught.exception))
        for port in [5432, 6543]:
            url = f'postgres://postgres.{self.project}:private-value@aws-0-us-west-2.pooler.supabase.com:{port}/postgres'
            self.run_binding(payload=url)
        with self.assertRaises(MigrationError) as caught:
            binding.classify(self.secret, earliest_start=self.start, observed_at=self.end,
                             list_versions=lambda _: self.rows,
                             read_payload=lambda _: (_ for _ in ()).throw(RuntimeError(self.payload)))
        self.assertNotIn('private-value', str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)


if __name__ == '__main__':
    unittest.main()
