import hashlib
import json
import os
import shutil
import tempfile
import subprocess
import time
import unittest
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS = ROOT / "supabase/migrations"
CATALOG = "20261023000000_billing_plan_catalog.sql"
SUCCESSOR = "20261023000100_reconcile_obsolete_subscription_seeds.sql"
CLI = os.environ.get("SUPABASE_CLI", "supabase")


class CatalogSeedReconciliationTest(unittest.TestCase):
    container = "catalog-reconciliation-" + uuid.uuid4().hex[:12]
    evidence = []

    @classmethod
    def sql(cls, database, statement, check=True):
        result = subprocess.run(
            ["docker", "exec", "-i", cls.container, "psql", "-XAt",
             "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", database],
            input=statement, text=True, capture_output=True, check=False,
        )
        if check and result.returncode:
            raise AssertionError(result.stderr)
        return result

    @classmethod
    def setUpClass(cls):
        subprocess.run(
            ["docker", "run", "--rm", "-d", "--name", cls.container,
             "-e", "POSTGRES_HOST_AUTH_METHOD=trust", "postgres:17.6"],
            check=True, capture_output=True,
        )
        cls.addClassCleanup(lambda: subprocess.run(
            ["docker", "rm", "-f", cls.container], check=False, capture_output=True,
        ))
        for _ in range(100):
            ready = subprocess.run(
                ["docker", "exec", cls.container, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"],
                capture_output=True, check=False,
            )
            if ready.returncode == 0:
                break
            time.sleep(0.1)
        else:
            raise AssertionError("disposable PostgreSQL did not become ready")
        cli_version = subprocess.run([CLI, "--version"], text=True, capture_output=True, check=True).stdout.strip()
        if cli_version != "2.119.0":
            raise AssertionError("use the deployment-pinned Supabase CLI 2.119.0")
        cls.address = subprocess.run(
            ["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", cls.container],
            text=True, capture_output=True, check=True,
        ).stdout.strip()
        cls.projects = {}
        for variant in ("current", "deployed", "guarded"):

            database = "seed_" + variant
            cls.sql("postgres", "CREATE DATABASE " + database)
            replacement = None
            if variant != "current":
                fixture = json.loads((ROOT / "scripts/fixtures/catalog_reconciliation" / (variant + ".json")).read_text())
                replacement = fixture["sql"]
                if hashlib.sha256(replacement.encode()).hexdigest() != fixture["sha256"]:
                    raise AssertionError("historical fixture checksum differs")
            temporary = tempfile.TemporaryDirectory(prefix="catalog-migrations-")
            cls.addClassCleanup(temporary.cleanup)
            project = Path(temporary.name)
            directory = project / "supabase/migrations"
            directory.mkdir(parents=True)
            (project / "supabase/config.toml").write_text('project_id = "catalog-reconciliation-test"\n')
            applied = []
            for migration in sorted(MIGRATIONS.glob("*.sql")):
                if migration.name == SUCCESSOR:
                    continue
                statement = replacement if replacement is not None and migration.name == CATALOG else migration.read_text()
                (directory / migration.name).write_text(statement)
                applied.append(migration.name)
            if variant == "deployed":
                for migration in (ROOT / "supabase/shared-auth-history").glob("*.sql"):
                    shutil.copyfile(migration, directory / migration.name)
                    applied.append(migration.name)
            cls.projects[variant] = project
            started = time.monotonic()
            cls.push(database, project)
            cls.evidence.append({"variant": variant, "migrations": len(applied), "seconds": round(time.monotonic() - started, 3)})
            print(json.dumps(cls.evidence[-1]), flush=True)
        cls.migration = (MIGRATIONS / SUCCESSOR).read_text()

    @classmethod
    def push(cls, database, project):
        result = subprocess.run(
            [CLI, "db", "push", "--db-url", "postgresql://postgres@" + cls.address + ":5432/" + database + "?sslmode=disable",
             "--workdir", str(project), "--yes"], text=True, capture_output=True, check=False,
        )
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)

    def apply_successor(self, database, variant):
        original_history = self.sql(database, "SELECT jsonb_agg(to_jsonb(m) ORDER BY version) FROM supabase_migrations.schema_migrations m;").stdout
        temporary = tempfile.TemporaryDirectory(prefix="catalog-successor-")
        self.addCleanup(temporary.cleanup)
        project = Path(temporary.name) / "project"
        shutil.copytree(self.projects[variant], project)
        shutil.copyfile(MIGRATIONS / SUCCESSOR, project / "supabase/migrations" / SUCCESSOR)
        self.push(database, project)
        preserved_history = self.sql(database, "SELECT jsonb_agg(to_jsonb(m) ORDER BY version) FROM supabase_migrations.schema_migrations m WHERE version <> '20261023000100';").stdout
        self.assertEqual(original_history, preserved_history)
        self.assertEqual(self.sql(database, "SELECT count(*) FROM supabase_migrations.schema_migrations WHERE version='20261023000100';").stdout.strip(), "1")

    def database(self, variant="deployed"):
        database = "case_" + uuid.uuid4().hex
        self.sql("postgres", "CREATE DATABASE " + database + " TEMPLATE seed_" + variant)
        self.addCleanup(lambda: self.sql("postgres", "DROP DATABASE " + database + " WITH (FORCE)"))
        return database

    def snapshot(self, database):
        return self.sql(database, """
            SELECT json_build_object(
                'catalog',(SELECT jsonb_agg(to_jsonb(p) ORDER BY offer_key) FROM billing_plan p),
                'limits',(SELECT jsonb_agg(to_jsonb(p) ORDER BY offer_key) FROM plan_limits p),
                'guards',(SELECT jsonb_agg(jsonb_build_array(tgname,tgenabled,pg_get_triggerdef(oid)) ORDER BY tgname)
                    FROM pg_trigger WHERE tgrelid='billing_plan'::regclass AND NOT tgisinternal));
        """
        ).stdout.strip()

    def test_current_main_first_and_fresh_remain_unchanged(self):
        database = self.database("current")
        before = self.snapshot(database)
        self.apply_successor(database, "current")
        self.assertEqual(before, self.snapshot(database))
        self.assertEqual(self.sql(database, "SELECT billing_plan_offer('starter_monthly'),billing_plan_offer('starter_annual');").stdout.strip(), "f|f")
        self.assertEqual(self.sql(database, "SELECT count(*) FROM plan_limits WHERE offer_key IN ('starter_monthly','starter_annual');").stdout.strip(), "0")

    def test_known_historical_seeds_remove_only_catalog_rows(self):
        for variant in ("deployed", "guarded"):
            with self.subTest(variant=variant):
                database = self.database(variant)
                before = json.loads(self.snapshot(database))
                self.apply_successor(database, variant)
                after = json.loads(self.snapshot(database))
                self.assertEqual(after["catalog"], [row for row in before["catalog"] if row["family"] != "starter"])
                self.assertEqual(before["limits"], after["limits"])
                self.assertEqual(before["guards"], after["guards"])
                self.assertEqual(self.sql(database, "SELECT count(*) FROM plan_limits WHERE offer_key IN ('starter_monthly','starter_annual');").stdout.strip(), "2")
                self.assertEqual(self.sql(database, "SELECT billing_plan_offer('starter_monthly'),billing_plan_offer('starter_annual');").stdout.strip(), "f|f")
                self.sql(database, self.migration)
                self.assertEqual(after, json.loads(self.snapshot(database)))

    def test_unknown_altered_referenced_or_opaque_authority_refuses(self):
        cases = {
            "changed_amount": "UPDATE billing_plan SET charge_amount_cents=1 WHERE offer_key='starter_monthly'",
            "changed_availability": "UPDATE billing_plan SET available=true WHERE offer_key='starter_annual'",
            "partial_seed": "DELETE FROM billing_plan WHERE offer_key='starter_annual'",
            "unknown_schema": "CREATE TABLE unknown_journal(payload jsonb)",
            "unknown_ledger_column": "ALTER TABLE supabase_migrations.schema_migrations ADD COLUMN authority jsonb",
            "unknown_ledger_relation": "CREATE TABLE supabase_migrations.authority(id text)",
            "unexpected_namespace": "CREATE SCHEMA pgx; CREATE TABLE pgx.opaque_authority(id text)",
            "incoming_reference": "ALTER TABLE plan_limits ADD CONSTRAINT obsolete_catalog_reference FOREIGN KEY(offer_key) REFERENCES billing_plan(offer_key) NOT VALID",
            "unknown_guard": "CREATE TRIGGER unknown_guard BEFORE DELETE ON billing_plan FOR EACH ROW EXECUTE FUNCTION guard_billing_plan_contract()",
            "unknown_column": "ALTER TABLE billing_plan ADD COLUMN unknown_terms jsonb",
            "opaque_provider": "INSERT INTO stripe_webhook_event(event_id,event_type,payload) VALUES('evt_example','example','{\"id\":\"opaque\"}')",
            "frozen_provider": "INSERT INTO stripe_webhook_event(event_id,event_type,payload) VALUES('evt_example','example','{\"metadata\":{\"commercial_offer\":\"starter_monthly\"}}')",
            "semantic_marker": "UPDATE feature_flag SET description='starter_annual historical reference' WHERE key=(SELECT key FROM feature_flag LIMIT 1)",
            "opaque_credit": "INSERT INTO team(id,name) VALUES('00000000-0000-0000-0000-000000000123','example-team'); DELETE FROM billing_signup_choice; INSERT INTO team_credit_grant(team_id,amount_usd,remaining_usd,reason) VALUES('00000000-0000-0000-0000-000000000123',1,1,'opaque')",
            "frozen_choice": "INSERT INTO team(id,name) VALUES('00000000-0000-0000-0000-000000000123','example-team'); UPDATE billing_signup_choice SET offer_key='starter_monthly',state='pending',generation=now(),actor_id='00000000-0000-0000-0000-000000000124',base_price_id='price_example',request_payload='{\"PlanTerms\":{\"Amount\":10000}}' WHERE team_id='00000000-0000-0000-0000-000000000123'",
            "changed_control": "UPDATE billing_funding_policy SET max_observed_teams=3",
        }
        for name, setup in cases.items():
            with self.subTest(case=name):
                database = self.database()
                self.sql(database, setup)
                before = self.snapshot(database)
                result = self.sql(database, self.migration, check=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("obsolete catalog reconciliation", result.stderr)
                self.assertEqual(before, self.snapshot(database))

    def test_existing_read_lock_causes_atomic_nowait_refusal(self):
        database = self.database()
        before = self.snapshot(database)
        process = subprocess.Popen(
            ["docker", "exec", "-i", self.container, "psql", "-XAt", "-U", "postgres", "-d", database],
            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True,
        )
        process.stdin.write("SET application_name='catalog_lock_fixture'; BEGIN; LOCK TABLE billing_plan IN ACCESS SHARE MODE; SELECT pg_sleep(3); ROLLBACK;\n")
        process.stdin.close()
        try:
            for _ in range(100):
                held = self.sql(database, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity a JOIN pg_locks l ON l.pid=a.pid WHERE a.application_name='catalog_lock_fixture' AND l.relation='billing_plan'::regclass AND l.granted);").stdout.strip()
                if held == "t":
                    break
                time.sleep(0.01)
            else:
                self.fail("fixture did not acquire read lock")
            result = self.sql(database, self.migration, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("could not obtain lock", result.stderr)
        finally:
            process.wait(timeout=10)
        self.assertEqual(before, self.snapshot(database))

    def test_restricted_role_cannot_partially_reconcile(self):
        database = self.database()
        before = self.snapshot(database)
        role = "catalog_reader_" + uuid.uuid4().hex
        self.sql(database, "CREATE ROLE " + role)
        self.addCleanup(lambda: self.sql(database, "DROP ROLE " + role))
        result = self.sql(database, "SET ROLE " + role + "; " + self.migration, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("permission denied", result.stderr)
        self.assertEqual(before, self.snapshot(database))

    def test_acceptance_and_schema_writes_remain_fenced_until_transaction_end(self):
        database = self.database()
        before = self.snapshot(database)
        process = subprocess.Popen(
            ["docker", "exec", "-i", self.container, "psql", "-XAt", "-U", "postgres", "-d", database],
            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True,
        )
        process.stdin.write("SET application_name='catalog_acceptance_fence'; BEGIN; " + self.migration + " SELECT pg_sleep(3); ROLLBACK;\n")
        process.stdin.close()
        try:
            for _ in range(100):
                held = self.sql(database, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity a JOIN pg_locks l ON l.pid=a.pid WHERE a.application_name='catalog_acceptance_fence' AND a.wait_event='PgSleep' AND l.relation='billing_plan'::regclass AND l.mode='AccessExclusiveLock' AND l.granted);").stdout.strip()
                if held == "t":
                    break
                time.sleep(0.01)
            else:
                self.fail("migration did not reach fenced transaction hold")
            for statement in (
                "INSERT INTO stripe_webhook_event(event_id,event_type,payload) VALUES('evt_fenced','example','{}')",
                "CREATE TABLE new_authority(id text)",
            ):
                result = self.sql(database, "SET lock_timeout='100ms'; " + statement, check=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("lock timeout", result.stderr)
        finally:
            process.wait(timeout=10)
        self.assertEqual(before, self.snapshot(database))

    @classmethod
    def tearDownClass(cls):
        print(json.dumps({"disposable_migration_evidence": cls.evidence}, indent=2), flush=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
