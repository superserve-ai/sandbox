"""Exercise proxy selection through the shared selector and cloud discovery."""

import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import unittest
from concurrent.futures import Future
from types import SimpleNamespace
from unittest.mock import patch

SCRIPTS = Path(__file__).parent
SPEC = importlib.util.spec_from_file_location("proxy_target", SCRIPTS / "deploy-proxy.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
WORKFLOW = (SCRIPTS.parent / "deploy-proxy.yml").read_text()
STEPS = [s for s in re.split(r"^      - name: ", WORKFLOW, flags=re.M)
         if "python3 .github/workflows/scripts/deploy-proxy.py" in s]


class ProxyTargetTests(unittest.TestCase):
    def select(self, rows="", **overrides):
        env = dict(PATH=os.environ["PATH"], GCP_PROJECT="example-project",
                   GCP_REGION="us-west2", SHA="12345678", PROXY_DOMAIN="sandbox.example.test",
                   VMD_LABEL="component=vmd", DEPLOY_EVENT="workflow_dispatch",
                   DEPLOY_TARGET="standby", DEPLOY_ENVIRONMENT="production",
                   DEPLOY_PRODUCTION_CELL="usw2", DEPLOY_CELL="usw2")
        env.update(overrides)
        step = next(s for s in STEPS if f'DEPLOY_CELL: {env["DEPLOY_CELL"]}' in s)
        # Execute the workflow's actual selection prefix, without secret access or deployment.
        prefix = step.split("        run: |\n")[1].split('          : "${GCP_REGION:?', 1)[0]
        result = subprocess.run(["bash", "-eu", "-c", prefix + '\npython3 -c "import json, os; print(json.dumps(dict(os.environ)))"'],
                                cwd=SCRIPTS.parents[2], env=env, capture_output=True, text=True)
        if result.returncode:
            return 1, []
        env = json.loads(result.stdout)
        standby = env["DEPLOY_EVENT"] == "workflow_dispatch" and env["DEPLOY_TARGET"] == "standby"
        self.assertEqual(env["VMD_LABEL"], f'component=vmd-{env["DEPLOY_CELL"]}-standby' if standby else "component=vmd")
        selected = []

        class Executor:
            def __init__(self, **kwargs): pass
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def submit(self, fn, inst):
                selected.append(inst["name"])
                future = Future()
                future.set_result(None)
                return future

        def discover(args, **kwargs):
            self.assertEqual(args[:4], ["gcloud", "compute", "instances", "list"])
            self.assertIn(f'--filter=labels.{env["VMD_LABEL"]}' + ('' if env.get('EXPECTED_STANDBY_HOST') else ' AND status=RUNNING'), args)
            if rows is None:
                raise subprocess.CalledProcessError(1, args)
            return subprocess.CompletedProcess(args, 0, rows, "")

        with patch.dict(os.environ, env, clear=True), patch.object(MODULE.subprocess, "run", side_effect=discover), \
             patch.object(MODULE.os.path, "exists", return_value=True), patch.object(MODULE, "ThreadPoolExecutor", Executor):
            return MODULE.main(), selected

    def test_serving_and_push_keep_normal_fanout(self):
        for event, target in (("workflow_dispatch", "serving"), ("push", "serving"), ("push", "")):
            self.assertEqual(self.select("example-serving,us-west2-a\nexample-east,us-east4-a\n",
                                         DEPLOY_EVENT=event, DEPLOY_TARGET=target), (0, ["example-serving"]))

    def test_west_and_configured_east_standby(self):
        self.assertEqual(self.select("superserve-vmd-usw2-2,us-west2-a,RUNNING\n"),
                         (0, ["superserve-vmd-usw2-2"]))
        self.assertEqual(self.select("superserve-vmd-use4-3,us-east4-a,RUNNING\n",
                                    DEPLOY_CELL="use4", DEPLOY_PRODUCTION_CELL="use4", GCP_REGION="us-east4",
                                    VMD_STANDBY_HOST_USE4="superserve-vmd-use4-3"), (0, ["superserve-vmd-use4-3"]))

    def test_missing_unconfigured_wrong_or_stopped_production_standby_fails(self):
        for rows in ("", "other-host,us-west2-a,RUNNING\n", "superserve-vmd-usw2-2,us-east4-a,RUNNING\n",
                     "superserve-vmd-usw2-2,us-west2-a,TERMINATED\n",
                     "superserve-vmd-usw2-2,us-west2-a,RUNNING\nother-host,us-west2-b,RUNNING\n"):
            self.assertEqual(self.select(rows), (1, []))
        self.assertEqual(self.select(DEPLOY_CELL="use4", DEPLOY_PRODUCTION_CELL="use4", GCP_REGION="us-east4"), (1, []))

    def test_staging_absence_only_skips_for_production_standby(self):
        self.assertEqual(self.select(DEPLOY_CELL="staging", GCP_REGION="us-central1"), (0, []))
        self.assertEqual(self.select(DEPLOY_CELL="staging", GCP_REGION="us-central1",
                                    DEPLOY_ENVIRONMENT="staging"), (1, []))
        self.assertEqual(self.select("superserve-vmd-staging-2,us-central1-a,RUNNING\n",
                                    DEPLOY_CELL="staging", GCP_REGION="us-central1"), (0, ["superserve-vmd-staging-2"]))
        self.assertEqual(self.select("superserve-vmd-staging-2,us-central1-a,TERMINATED\n",
                                    DEPLOY_CELL="staging", GCP_REGION="us-central1"), (1, []))
        with self.assertRaises(subprocess.CalledProcessError):
            self.select(None, DEPLOY_CELL="staging", GCP_REGION="us-central1")

    def test_region_required_for_every_target(self):
        for event in ("push", "workflow_dispatch"):
            for target in ("serving", "standby"):
                for region in ("", " "):
                    self.assertEqual(self.select(GCP_REGION=region, DEPLOY_EVENT=event, DEPLOY_TARGET=target), (1, []))

    def test_workflow_guards_preserve_defaults_and_only_select_requested_standby_cell(self):
        self.assertIn("DEPLOY_TARGET: ${{ inputs.target || 'serving' }}", WORKFLOW)
        self.assertIn("VMD_STANDBY_HOST_USE4: ${{ vars.VMD_STANDBY_HOST_USE4 }}", WORKFLOW)
        self.assertIn("needs: [deploy-staging]", WORKFLOW)
        for event in ("push", "workflow_dispatch"):
            for target in ("", "serving", "standby"):
                for cell in ("", "use4", "usw2"):
                    for enabled in ("", "configured"):
                        context = dict(github=SimpleNamespace(event_name=event),
                                       inputs=SimpleNamespace(target=target, production_cell=cell),
                                       vars=SimpleNamespace(CLOUD_RUN_SERVICE_USW=enabled))
                        selected = []
                        for step in STEPS[1:]:
                            condition = re.search(r"^        if: (.+)$", step, re.M)[1]
                            if eval(condition.replace("&&", " and ").replace("||", " or "), {"__builtins__": {}}, context):
                                selected.append(re.search(r"DEPLOY_CELL: (\w+)", step)[1])
                        expected = [cell or "usw2"] if event == "workflow_dispatch" and target == "standby" else (["use4", "usw2"] if enabled else ["use4"])
                        self.assertEqual(selected, expected)


if __name__ == "__main__":
    unittest.main()
