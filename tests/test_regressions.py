"""Regression tests for defects found in review (each test fails on the pre-fix code).

Run:  python3 -m unittest discover -s tests -v   (from the plugin root)
"""

import argparse
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "azure-governance-assessment" / "scripts"))

from azgov_assess import analysis, checklists as cl, cli, insights, report, scoring, util  # noqa: E402
from azgov_assess.analysis import Context  # noqa: E402
from azgov_assess.analyzers import network, policy  # noqa: E402

TENANT = "00000000-1111-2222-3333-444444444444"
SUB = "aaaaaaaa-0000-0000-0000-000000000001"


class InputValidationTests(unittest.TestCase):
    def test_tenant_values(self):
        for ok in (TENANT, "contoso.onmicrosoft.com", "M365x00000000.onmicrosoft.com"):
            self.assertTrue(util.is_tenant(ok), ok)
        for bad in ("x' + (Write-Output 'INJECTED') + '", "a b.com", "localhost", "", "contoso.com;rm"):
            self.assertFalse(util.is_tenant(bad), bad)

    def test_management_group_ids(self):
        self.assertTrue(util.is_mg_id("Contoso_(prod).1"))
        self.assertFalse(util.is_mg_id("mg'; rm"))

    def test_cli_rejects_injection(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            cli._tenant_arg("x' + (Write-Output 'INJECTED') + '")
        with self.assertRaises(argparse.ArgumentTypeError):
            cli._guid_list_arg(f"{SUB},abc")
        self.assertEqual(cli._guid_list_arg(f"{SUB}, {SUB}"), [SUB])  # duplicates collapse

    def test_token_script_takes_values_from_environment(self):
        from azgov_assess import auth
        self.assertNotIn("__TENANT__", auth._PWSH_TOKEN_SCRIPT)
        env = auth.pwsh_env(tenant="t'x", resource="r")
        self.assertEqual(env["AZGOV_PS_TENANT"], "t'x")


class ChecklistModeTests(unittest.TestCase):
    def test_comment_mentioning_non_compliant_does_not_select_compliant_mode(self):
        item = {"aprlGuid": "c42343ae", "graph": ""}
        q = "// Find all VMs in \"Non-compliant\" state\nresources | project recommendationId='x', id, name"
        self.assertEqual(cl.query_mode(item, q), "aprl")

    def test_capitalised_param1_is_aprl_style(self):
        q = "resources | where type =~ 'microsoft.network/loadbalancers' | project name, id, Param1='backendPools'"
        self.assertEqual(cl.query_mode({}, q), "aprl")

    def test_returned_columns_decide_first(self):
        rows = [{"id": "/subscriptions/1/x", "Compliant": False}]
        self.assertEqual(cl.query_mode({}, "resources | project id", rows), "compliant")
        out = cl.evaluate_rows({}, "resources | project id", rows, {})
        self.assertEqual(out["status"], "non_compliant")

    def test_url_in_string_is_not_a_comment(self):
        q = "resources | extend compliant = (properties.uri startswith 'https://x')"
        self.assertEqual(cl.query_mode({}, q), "compliant")

    def test_official_export_is_not_truncated(self):
        rows = [{"id": f"/subscriptions/1/r{i}", "compliant": i % 4 != 0} for i in range(200)]
        item = {"guid": "g1", "graph": "resources | extend compliant = true"}
        evaluated = cl.evaluate_rows(item, item["graph"], rows, {})
        self.assertEqual(len(evaluated["resources"]), 60)
        results = {"checklists": [{"key": "alz", "items": [{**item, **evaluated}]}]}
        checks = cl.official_graph_results(results, "alz")["checks"]
        self.assertEqual(len(checks), 200)
        self.assertEqual(sum(1 for c in checks if c["compliant"] == "false"), 50)
        cl.strip_private(results)
        self.assertNotIn("_verdicts", results["checklists"][0]["items"][0])


class PolicyStateTests(unittest.TestCase):
    def _ctx(self, inv):
        return Context(run_dir=Path("/tmp"), run={}, azgv=None, inventory=inv, checklists=None, tenant_id=TENANT)

    def test_per_resource_shape(self):
        inv = {"policyStates": [{"evaluations": 1000, "resources": 100, "nonCompliant": 50, "compliant": 50}]}
        f = policy._policy_states(self._ctx(inv))[0]
        self.assertEqual(f.status, "fail")
        self.assertIn("50 of 100", f.summary)

    def test_legacy_shape_does_not_double_count(self):
        inv = {"policyStates": [{"state": "NonCompliant", "n": 120, "resources": 50},
                                {"state": "Compliant", "n": 880, "resources": 100}]}
        f = policy._policy_states(self._ctx(inv))[0]
        self.assertIn("50 of 100", f.summary)


class NetworkRuleTests(unittest.TestCase):
    def test_port_ranges(self):
        for spec in ("22", "3389", "*", "0-65535", "3389-3390", '["20-30"]'):
            self.assertTrue(network.covers_mgmt_port(spec), spec)
        for spec in ("443", "20-21", '["80","443"]', ""):
            self.assertFalse(network.covers_mgmt_port(spec), spec)

    def test_source_prefix_arrays(self):
        self.assertTrue(network.from_internet('["10.0.0.0/8","0.0.0.0/0"]'))
        self.assertFalse(network.from_internet("VirtualNetwork"))


class InsightsRobustnessTests(unittest.TestCase):
    def test_wrong_types_are_reported_not_crashing(self):
        data = {"schema": insights.SCHEMA, "executiveSummary": "x" * 100, "keyRisks": [{"severity": 3}],
                "roadmap": [{"phase": "Now", "items": ["plain string item"]}],
                "domainCommentary": {"identity": ["list"]}}
        problems = insights.validate(data, {"findings": []})
        self.assertTrue(any("severity" in p for p in problems))
        self.assertTrue(any("items[0]" in p for p in problems))
        self.assertTrue(any("domainCommentary.identity" in p for p in problems))
        clean = insights.sanitize(data)
        self.assertEqual(clean["roadmap"][0]["items"][0]["title"], "plain string item")
        self.assertEqual(clean["keyRisks"][0]["severity"], "medium")
        self.assertEqual(clean["domainCommentary"], {})

    def test_sanitize_rejects_non_object(self):
        self.assertIsNone(insights.sanitize(["not", "an", "object"]))


class ReportSafetyTests(unittest.TestCase):
    def test_only_http_links(self):
        self.assertIsNone(report.safe_url("javascript:alert(1)"))
        self.assertIsNone(report.safe_url(" data:text/html,x"))
        self.assertEqual(report.safe_url("https://learn.microsoft.com/x"), "https://learn.microsoft.com/x")


class ScoringConsistencyTests(unittest.TestCase):
    def test_rating_matches_displayed_score(self):
        # 74.96 is displayed as "75" and must therefore be rated Managed, not Defined
        self.assertEqual(scoring.level_for(round(74.96, 1))["name"], "Managed")
        domains = scoring.score_domains(
            [{"domain": "identity", "status": "pass", "severity": "high"}], None)["domains"]
        identity = next(d for d in domains if d["key"] == "identity")
        self.assertEqual(identity["rating"], scoring.level_for(identity["score"]))


class SecondReviewTests(unittest.TestCase):
    def test_invalid_insights_json_is_a_problem_not_a_crash(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "ai-insights.json"
            p.write_text('{"schema": "x",}', encoding="utf-8")
            data, problems = insights.load(p)
            self.assertIsNone(data)
            self.assertTrue(problems and "not valid JSON" in problems[0])
        bad = {"schema": insights.SCHEMA, "executiveSummary": "x" * 100, "keyRisks": [
            {"title": "t", "why": "w", "recommendation": "r", "severity": "high", "domain": ["identity"]}]}
        self.assertTrue(any("domain" in p for p in insights.validate(bad, {"findings": []})))
        self.assertIsNone(insights.sanitize(bad)["keyRisks"][0]["domain"])

    def test_trend_flags_different_evidence(self):
        def run(sources):
            return {"sources": {k: {"available": v} for k, v in sources.items()},
                    "scores": {"overall": {"score": 50.0}, "domains": []}, "findings": []}
        t = analysis.compare(run({"azgovviz": True, "inventory": True}), run({"azgovviz": True, "inventory": False}))
        self.assertFalse(t["comparable"])
        self.assertEqual(t["sourceDiff"], ["Resource Graph inventory only in this run"])
        self.assertTrue(analysis.compare(run({"azgovviz": True}), run({"azgovviz": True}))["comparable"])

    def test_key_vault_exposure_without_storage_accounts(self):
        from azgov_assess.analyzers import security
        inv = {"keyVaults": [{"name": "kv1", "publicNetworkAccess": "Enabled", "defaultAction": "Allow"},
                             {"name": "kv2", "publicNetworkAccess": "Enabled", "defaultAction": "Deny"}]}
        ctx = Context(run_dir=Path("/tmp"), run={}, azgv=None, inventory=inv, checklists=None, tenant_id=TENANT)
        sec010 = [f for f in security.security_findings(ctx) if f.id == "SEC-010"]
        self.assertEqual(len(sec010), 1)
        self.assertIn("1 of 2 key vaults", sec010[0].summary)

    def test_ipv6_any_is_internet(self):
        self.assertTrue(network.from_internet("::/0"))

    def test_security_recommendation_title_renamed(self):
        from azgov_assess import inventory
        self.assertNotIn(" title", inventory.QUERIES["securityRecommendations"])
        self.assertEqual(inventory._rename("securityRecommendations", {"recommendation": "x"}), {"title": "x"})


class TrendTests(unittest.TestCase):
    def test_compare_reports_changes(self):
        def run(score, statuses, generated):
            return {"generatedAt": generated,
                    "scores": {"overall": {"score": score}, "domains": [{"key": "identity", "score": score}]},
                    "findings": [{"id": fid, "title": fid, "status": st, "summary": ""} for fid, st in statuses.items()]}
        before = run(40.0, {"IAM-001": "fail", "IAM-002": "pass", "GOV-001": "warn"}, "2025-06-03T00:00:00Z")
        after = run(47.5, {"IAM-001": "pass", "IAM-002": "fail", "GOV-001": "warn"}, "2026-10-08T00:00:00Z")
        t = analysis.compare(after, before, "/runs/base")
        self.assertEqual(t["overall"]["delta"], 7.5)
        self.assertEqual((t["improved"], t["regressed"]), (1, 1))
        self.assertEqual({c["id"]: c["change"] for c in t["changes"]}, {"IAM-001": "improved", "IAM-002": "regressed"})


if __name__ == "__main__":
    unittest.main()
