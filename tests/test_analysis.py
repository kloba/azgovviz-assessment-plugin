"""Integration tests: synthetic AzGovViz + Resource Graph data -> findings -> HTML report (offline)."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "azure-governance-assessment" / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import fake_run  # noqa: E402
from azgov_assess import analysis, insights, report, util  # noqa: E402


class SyntheticRunTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.run_dir = fake_run.main(cls.tmp.name, with_azgovviz=True, with_checklists=False)
        run_data = util.read_json(cls.run_dir / "run.json")
        cls.result = analysis.analyze_run(cls.run_dir, run_data)
        cls.result.pop("_checklists", None)
        util.write_json(cls.run_dir / "analysis" / "findings.json", cls.result)
        cls.by_id = {f["id"]: f for f in cls.result["findings"]}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_no_analyzer_errors(self):
        self.assertEqual(self.result["analyzerErrors"], [])

    def test_identity_findings(self):
        self.assertEqual(self.by_id["IAM-006"]["status"], "fail")          # UAA at root '/'
        self.assertEqual(self.by_id["IAM-003"]["status"], "fail")          # orphaned assignment
        self.assertEqual(self.by_id["IAM-002"]["status"], "fail")          # SP with Owner at sub
        self.assertEqual(self.by_id["IAM-011"]["status"], "warn")          # policy MI with Owner
        self.assertEqual(self.by_id["IAM-010"]["status"], "warn")          # co-administrator
        self.assertEqual(self.by_id["IAM-012"]["status"], "warn")          # least-privilege advice in log
        self.assertEqual(self.by_id["IAM-004"]["metric"]["subscriptionsOverLimit"], 3)

    def test_policy_and_org_findings(self):
        self.assertEqual(self.by_id["GOV-004"]["status"], "warn")          # DoNotEnforce
        self.assertEqual(self.by_id["GOV-002"]["status"], "warn")          # MCSB on 2 of 3
        self.assertEqual(self.by_id["ORG-001"]["status"], "fail")          # sandbox sub under root
        self.assertEqual(self.by_id["ORG-004"]["status"], "pass")          # sandbox MG exists
        self.assertEqual(self.by_id["ORG-007"]["status"], "fail")          # MG creation not protected

    def test_security_network_cost(self):
        self.assertEqual(self.by_id["SEC-008"]["status"], "fail")          # anonymous container
        self.assertEqual(self.by_id["NET-001"]["status"], "fail")          # RDP from internet
        self.assertEqual(self.by_id["NET-002"]["status"], "pass")          # hub detected
        self.assertEqual(self.by_id["NET-004"]["status"], "warn")          # subnet IP exhaustion
        self.assertEqual(self.by_id["CST-002"]["status"], "warn")          # orphaned resources

    def test_alz_evidence_ids_are_guids(self):
        for f in self.result["findings"]:
            for g in f.get("alz", []):
                self.assertTrue(util.is_guid(g), f"{f['id']} has malformed ALZ guid {g}")

    def test_scores_and_hierarchy(self):
        ov = self.result["scores"]["overall"]
        self.assertTrue(0 <= ov["score"] <= 100)
        self.assertEqual(self.result["hierarchy"]["id"], fake_run.TENANT)
        self.assertEqual(self.result["facts"]["managementGroups"], 3)

    def test_report_renders_with_and_without_ai(self):
        path = report.render_run(self.run_dir)
        html = path.read_text(encoding="utf-8")
        self.assertIn("Governance maturity score", html)
        self.assertIn("IAM-006", html)
        self.assertNotIn("<script>alert", html)
        tpl = insights.template(self.result)
        tpl.pop("_instructions")
        tpl["executiveSummary"] = "Synthetic executive summary " * 5
        tpl["overallAssessment"] = "Synthetic verdict."
        for r in tpl["keyRisks"]:
            r["why"] = "because"
        tpl["domainCommentary"] = {k: "ok" for k in tpl["domainCommentary"]}
        self.assertEqual(insights.validate(tpl, self.result), [])
        util.write_json(self.run_dir / "analysis" / "ai-insights.json", tpl)
        html = report.render_run(self.run_dir).read_text(encoding="utf-8")
        self.assertIn("AI analysis", html)
        self.assertIn("Synthetic verdict.", html)


class CorrectedChecklistRunTests(unittest.TestCase):
    """Corrected and set-aside checklist items flow through results.json, the brief and the report."""

    HTTPS, SAP = "e7a8dc4a-20e2-47c3-b297-11b1352beee0", "82734c88-6ba2-4802-8459-11475e39e530"

    def test_corrections_reach_brief_and_report(self):
        from azgov_assess import checklists as cl
        upstream = json.loads((ROOT / "tests" / "fixtures" / "upstream_defective_queries.json").read_text(encoding="utf-8"))
        data = {"items": [
            {"guid": self.HTTPS, "text": "Require HTTPS <b>", "severity": "High", "service": "Storage",
             "category": "Security", "graph": upstream[self.HTTPS]["graph"]},
            {"guid": self.SAP, "text": "SAP public IP", "severity": "High", "service": "SAP", "category": "Security",
             "graph": upstream[self.SAP]["graph"]},
        ]}

        class Client:
            calls = 0
            scope = type("S", (), {"describe": lambda self, *a: "test scope"})()

            def query(self, kql):  # the corrected HTTPS query finds one account that fails
                return type("R", (), {"rows": [{"id": "/subscriptions/1/resourceGroups/rg/providers/Microsoft.Storage/"
                                                      "storageAccounts/sa1", "compliant": 0}],
                                      "truncated": False, "elapsed": 0.0})()

        class Source:
            ref, commit, commit_date, local = "main", "abc1234", None, None

            def load(self, key):
                return data

            def path_for(self, key):
                return f"checklists/{key}_checklist.en.json"

        with tempfile.TemporaryDirectory() as tmp:
            run_dir = fake_run.main(tmp, with_azgovviz=True, with_checklists=False)
            results = cl.ChecklistEvaluator(Client(), Source(), {"microsoft.storage/storageaccounts": 1}).evaluate(
                ["waf"], progress=False)
            util.write_json(run_dir / "checklists" / "results.json", cl.strip_private(results))
            result = analysis.analyze_run(run_dir, util.read_json(run_dir / "run.json"))
            result.pop("_checklists", None)
            util.write_json(run_dir / "analysis" / "findings.json", result)
            self.assertEqual({c["guid"]: c["action"] for c in result["sources"]["checklists"]["corrections"]},
                             {self.HTTPS: "corrected", self.SAP: "set aside"})
            brief = analysis.brief_markdown(result)
            self.assertIn("corrected or set aside", brief)
            html = report.render_run(run_dir).read_text(encoding="utf-8")
            self.assertIn("Checklist query corrections", html)
            self.assertIn('class="assist">query corrected<', html)
            self.assertIn("Upstream query (not used)", html)
            self.assertIn("Require HTTPS &lt;b&gt;", html)
            self.assertNotIn("Require HTTPS <b>", html)


if __name__ == "__main__":
    unittest.main()
