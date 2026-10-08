"""Unit tests for the azgov_assess engine (stdlib unittest; no Azure access needed).

Run:  python3 -m unittest discover -s tests -v   (from the plugin root)
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "azure-governance-assessment" / "scripts"))

from azgov_assess import checklists as cl  # noqa: E402
from azgov_assess import insights, report, scoring, util  # noqa: E402
from azgov_assess.azgovviz import csv_suffix, locate_outputs, read_csv  # noqa: E402


class ChecklistEvaluationTests(unittest.TestCase):
    def test_compliant_column_mixed_is_partial(self):
        item = {"graph": "resources | extend compliant = 1 | project id, compliant", "severity": "High"}
        rows = [{"id": "/subscriptions/1/a", "compliant": 1}, {"id": "/subscriptions/1/b", "compliant": 0},
                {"id": "/subscriptions/1/c", "compliant": "true"}]
        out = cl.evaluate_rows(item, item["graph"], rows, {})
        self.assertEqual(out["mode"], "compliant")
        self.assertEqual(out["status"], "partial")
        self.assertEqual(out["counts"]["compliant"], 2)
        self.assertEqual(out["counts"]["nonCompliant"], 1)
        # non-compliant resources are listed first
        self.assertEqual(out["resources"][0]["id"], "/subscriptions/1/b")

    def test_resource_with_any_failing_row_is_non_compliant(self):
        item = {"graph": "x | extend compliant = 1"}
        rows = [{"id": "r1", "compliant": True}, {"id": "r1", "compliant": False}]
        out = cl.evaluate_rows(item, item["graph"], rows, {})
        self.assertEqual(out["status"], "non_compliant")

    def test_compliant_column_no_rows_and_absent_type_is_not_applicable(self):
        item = {"graph": "resources | where type =~ 'microsoft.network/azurefirewalls' | extend compliant = 1",
                "arm-service": "microsoft.network/azurefirewalls"}
        out = cl.evaluate_rows(item, item["graph"], [], {"microsoft.compute/virtualmachines": 3})
        self.assertEqual(out["status"], "not_applicable")

    def test_compliant_column_no_rows_unknown_type_is_no_data(self):
        item = {"graph": "authorizationresources | extend compliant = 1"}
        out = cl.evaluate_rows(item, item["graph"], [], {"microsoft.compute/virtualmachines": 3})
        self.assertEqual(out["status"], "no_data")

    def test_aprl_rows_are_non_compliant_and_rest_compliant(self):
        item = {"graph": "resources | project recommendationId='x', name, id, tags, param1",
                "aprlGuid": "x", "recommendationResourceType": "Microsoft.Compute/virtualMachines"}
        rows = [{"recommendationId": "x", "name": "vm1", "id": "/subscriptions/1/vm1"}]
        out = cl.evaluate_rows(item, item["graph"], rows, {"microsoft.compute/virtualmachines": 4})
        self.assertEqual(out["mode"], "aprl")
        self.assertEqual(out["status"], "partial")
        self.assertEqual(out["counts"]["nonCompliant"], 1)
        self.assertEqual(out["counts"]["compliant"], 3)

    def test_aprl_no_rows_with_type_present_is_compliant(self):
        item = {"graph": "resources | project recommendationId='x', id", "aprlGuid": "x",
                "recommendationResourceType": "Microsoft.Storage/storageAccounts"}
        out = cl.evaluate_rows(item, item["graph"], [], {"microsoft.storage/storageaccounts": 2})
        self.assertEqual(out["status"], "compliant")
        self.assertEqual(out["counts"]["compliant"], 2)

    def test_aprl_type_absent_is_not_applicable(self):
        item = {"graph": "resources | project recommendationId='x', id", "aprlGuid": "x",
                "recommendationResourceType": "Microsoft.AVS/privateClouds"}
        out = cl.evaluate_rows(item, item["graph"], [], {})
        self.assertEqual(out["status"], "not_applicable")

    def test_subscription_container_type_mapping(self):
        item = {"graph": "x | project recommendationId='y', id", "aprlGuid": "y",
                "recommendationResourceType": "Microsoft.Subscription/Subscriptions"}
        out = cl.evaluate_rows(item, item["graph"], [], {"microsoft.resources/subscriptions": 3})
        self.assertEqual(out["status"], "compliant")
        self.assertEqual(out["counts"]["compliant"], 3)

    def test_listing_is_info(self):
        item = {"graph": "resources | where identity.type in~ ('SystemAssigned')"}
        out = cl.evaluate_rows(item, item["graph"], [{"id": "/subscriptions/1/x", "name": "x"}], {})
        self.assertEqual(out["status"], "info")

    def test_runnable_query_ignores_comment_only(self):
        self.assertIsNone(cl.runnable_query("// cannot-be-validated-with-arg\n"))
        self.assertIsNone(cl.runnable_query(None))
        self.assertTrue(cl.runnable_query("// header\nresources | take 1"))

    def test_summarize_scores_weighted(self):
        items = [
            {"status": "compliant", "severity": "High", "category": "A", "counts": {"compliant": 1, "nonCompliant": 0}},
            {"status": "non_compliant", "severity": "Low", "category": "A", "counts": {"compliant": 0, "nonCompliant": 2}},
            {"status": "manual", "severity": "High", "category": "B"},
        ]
        s = cl.summarize(items)
        self.assertEqual(s["evaluated"], 2)
        self.assertEqual(s["score"], 75.0)  # 3 / (3 + 1)
        self.assertEqual(s["statusCounts"]["manual"], 1)
        self.assertEqual(s["resourceCompliance"]["percent"], 33.3)

    def test_official_export_format(self):
        res = {"generatedAt": "x", "checklists": [{"key": "alz", "items": [
            {"guid": "g1", "resources": [{"id": "r1", "compliant": True}, {"id": "r2", "compliant": None}]}]}]}
        out = cl.official_graph_results(res, "alz")
        self.assertEqual(out["checks"], [{"guid": "g1", "compliant": "true", "id": "r1"}])


class ScoringTests(unittest.TestCase):
    def test_blend_and_levels(self):
        findings = [{"domain": "identity", "status": "pass", "severity": "high"},
                    {"domain": "identity", "status": "fail", "severity": "high"},
                    {"domain": "security", "status": "warn", "severity": "medium"}]
        res = scoring.score_domains(findings, None)
        ident = next(d for d in res["domains"] if d["key"] == "identity")
        sec = next(d for d in res["domains"] if d["key"] == "security")
        self.assertEqual(ident["score"], 50.0)
        self.assertEqual(sec["score"], 50.0)
        self.assertEqual(res["overall"]["score"], 50.0)
        self.assertEqual(res["overall"]["rating"]["name"], "Developing")
        self.assertEqual(scoring.level_for(95)["level"], 5)
        self.assertEqual(scoring.level_for(None)["name"], "Not assessed")

    def test_checklist_items_counted_once_across_checklists(self):
        item = {"guid": "g", "status": "non_compliant", "severity": "High", "category": "Security", "waf": "Security"}
        res = scoring.score_domains([], {"checklists": [{"key": "alz", "items": [dict(item)]},
                                                        {"key": "waf", "items": [dict(item)]}]})
        sec = next(d for d in res["domains"] if d["key"] == "security")
        self.assertEqual(sec["checks"]["checklistItems"], 1)

    def test_domain_mapping(self):
        self.assertEqual(scoring.domain_for_checklist_item("alz", {"category": "Network Topology and Connectivity"}), "network")
        self.assertEqual(scoring.domain_for_checklist_item("waf", {"waf": "Reliability"}), "resiliency")
        self.assertEqual(scoring.domain_for_checklist_item("aprl", {"category": "Monitoring and Alerting"}), "management")


class InsightsTests(unittest.TestCase):
    def test_validate_catches_problems(self):
        findings = {"findings": [{"id": "IAM-001"}]}
        bad = {"schema": "x", "executiveSummary": "TODO", "keyRisks": [{"severity": "huge", "relatedFindings": ["NOPE"]}]}
        problems = insights.validate(bad, findings)
        self.assertTrue(any("schema" in p for p in problems))
        self.assertTrue(any("NOPE" in p for p in problems))
        self.assertTrue(any("severity" in p for p in problems))

    def test_validate_accepts_good(self):
        findings = {"findings": [{"id": "IAM-001"}]}
        good = {"schema": insights.SCHEMA, "executiveSummary": "A" * 120,
                "keyRisks": [{"title": "t", "severity": "high", "why": "w", "recommendation": "r",
                              "relatedFindings": ["IAM-001"], "domain": "identity"}],
                "roadmap": [{"phase": "Now", "items": []}], "domainCommentary": {"identity": "ok"}}
        self.assertEqual(insights.validate(good, findings), [])


class ReportHelpersTests(unittest.TestCase):
    def test_markdown_is_escaped(self):
        out = report.md("Hello <script>alert(1)</script> **bold** and `code`\n\n- a\n- b")
        self.assertNotIn("<script>", out)
        self.assertIn("<strong>bold</strong>", out)
        self.assertIn("<code>code</code>", out)
        self.assertIn("<ul>", out)

    def test_markdown_links_only_http(self):
        out = report.md("[x](javascript:alert(1)) [ok](https://learn.microsoft.com)")
        self.assertNotIn('href="javascript', out)
        self.assertIn('href="https://learn.microsoft.com"', out)

    def test_glide_path_marker(self):
        svg = report.glide_path(62.4)
        self.assertIn("This tenant · 62.4", svg)
        self.assertIn("Optimized", svg)


class AzGovVizFilesTests(unittest.TestCase):
    def test_suffix_detection(self):
        self.assertEqual(csv_suffix("AzGovViz_6.7.2_20251008_101010_mg_x_RoleAssignments.csv"), "RoleAssignments")
        self.assertEqual(csv_suffix("AzGovViz_6.7.2_20251008_101010_mg_ResourceFluctuationDetailed.csv"),
                         "ResourceFluctuationDetailed")
        self.assertIsNone(csv_suffix("AzGovViz_6.7.2_20251008_101010_mg.csv"))
        self.assertIsNone(csv_suffix("other.csv"))

    def test_locate_and_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "AzGovViz_6.7.2_20251008_101010_contoso_root.csv").write_text("level;mgId\n0;contoso_root\n", encoding="utf-8")
            (d / "AzGovViz_6.7.2_20251008_101010_contoso_root_RoleAssignments.csv").write_text(
                "﻿Role;Scope\nOwner;/subscriptions/1\n", encoding="utf-8")
            files = locate_outputs(d)
            self.assertIn("", files)
            self.assertIn("RoleAssignments", files)
            rows = read_csv(files["RoleAssignments"])
            self.assertEqual(rows, [{"Role": "Owner", "Scope": "/subscriptions/1"}])


class UtilTests(unittest.TestCase):
    def test_truthy(self):
        self.assertTrue(util.truthy("True"))
        self.assertFalse(util.truthy(0))
        self.assertIsNone(util.truthy("maybe"))

    def test_parse_iso_variants(self):
        self.assertIsNotNone(util.parse_iso("2025-10-08T10:11:12.1234567Z"))
        self.assertIsNotNone(util.parse_iso("10/08/2025 10:11:12"))
        self.assertIsNone(util.parse_iso(""))

    def test_write_json_atomic(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "a" / "b.json"
            util.write_json(p, {"x": 1})
            self.assertEqual(json.loads(p.read_text()), {"x": 1})


if __name__ == "__main__":
    unittest.main()
