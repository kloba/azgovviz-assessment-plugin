"""Analysis stage: turns AzGovViz output + Resource Graph inventory + checklist results into scored findings."""

from __future__ import annotations

import traceback
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from . import scoring, util
from .azgovviz import AzGovVizData


@dataclass
class Finding:
    id: str
    domain: str
    title: str
    severity: str                      # critical | high | medium | low | info
    status: str                        # fail | warn | pass | info | not_assessed
    summary: str                       # one line, includes the key number(s)
    details: str = ""                  # why it matters
    recommendation: str = ""
    evidence: Optional[Dict[str, Any]] = None   # {"columns": [...], "rows": [[...]], "total": n}
    references: List[Dict[str, str]] = field(default_factory=list)
    source: str = ""
    alz: List[str] = field(default_factory=list)   # ALZ checklist GUIDs this finding evidences
    effort: str = "medium"             # low | medium | high
    metric: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return {k: v for k, v in d.items() if v not in (None, [], "")}


def evidence(columns: List[str], rows: List[List[Any]], limit: int = 50, note: str = "") -> Dict[str, Any]:
    clean = [[("" if v is None else (v if isinstance(v, (int, float)) else str(v)[:400])) for v in r]
             for r in rows[:limit]]
    out: Dict[str, Any] = {"columns": columns, "rows": clean, "total": len(rows)}
    if note:
        out["note"] = note
    return out


@dataclass
class Context:
    run_dir: Path
    run: Dict[str, Any]
    azgv: Optional[AzGovVizData]
    inventory: Optional[Dict[str, Any]]
    checklists: Optional[Dict[str, Any]]
    tenant_id: str
    now: Any = field(default_factory=util.utcnow)
    facts: Dict[str, Any] = field(default_factory=dict)

    def t(self, suffix: str) -> List[Dict[str, str]]:
        return self.azgv.table(suffix) if self.azgv and self.azgv.has(suffix) else []

    def has(self, suffix: str) -> bool:
        return bool(self.azgv and self.azgv.has(suffix))

    def inv(self, key: str) -> Optional[List[Dict[str, Any]]]:
        return (self.inventory or {}).get(key)

    def sub_name(self, sub_id: str) -> str:
        for s in self.inv("subscriptions") or []:
            if s.get("subscriptionId") == sub_id:
                return s.get("name") or sub_id
        for row in self.t("SubscriptionDetails"):
            if row.get("subscriptionId") == sub_id or row.get("SubscriptionId") == sub_id:
                return row.get("subscription") or row.get("Subscription") or sub_id
        return sub_id


Analyzer = Callable[[Context], List[Finding]]
_REGISTRY: List[Analyzer] = []


def analyzer(fn: Analyzer) -> Analyzer:
    _REGISTRY.append(fn)
    return fn


def _load_analyzers() -> None:
    # import for side effects (registration); order defines report order within a domain
    from .analyzers import hierarchy, identity, policy, security, network, management, cost  # noqa: F401


def analyze_run(run_dir: Path, run_data: Dict[str, Any]) -> Dict[str, Any]:
    _load_analyzers()
    azgv_dir = run_dir / "azgovviz"
    azgv = AzGovVizData(azgv_dir) if azgv_dir.exists() else None
    if azgv and not azgv.available:
        azgv = None
    inventory = util.read_json(run_dir / "inventory.json", None)
    checklists = util.read_json(run_dir / "checklists" / "results.json", None)
    tenant_id = (run_data.get("tenant") or {}).get("tenantId") or ""
    ctx = Context(run_dir=run_dir, run=run_data, azgv=azgv, inventory=inventory, checklists=checklists,
                  tenant_id=tenant_id)

    from .analyzers import facts as facts_mod
    ctx.facts = facts_mod.collect(ctx)
    extra = getattr(ctx, "extra", {}) or {}

    findings: List[Finding] = []
    errors: List[Dict[str, str]] = []
    for fn in _REGISTRY:
        try:
            findings.extend(fn(ctx) or [])
        except Exception as exc:  # one broken analyzer must never sink the report
            errors.append({"analyzer": f"{fn.__module__}.{fn.__name__}", "error": f"{type(exc).__name__}: {exc}",
                           "trace": traceback.format_exc(limit=3)})
            util.warn(f"analyzer {fn.__name__} failed: {exc}")
    seen = set()
    unique: List[Finding] = []
    for f in findings:
        if f.id in seen:
            continue
        seen.add(f.id)
        unique.append(f)
    findings = unique
    findings.sort(key=lambda f: (list(scoring.DOMAINS).index(f.domain) if f.domain in scoring.DOMAINS else 99,
                                 {"fail": 0, "warn": 1, "info": 2, "pass": 3, "not_assessed": 4}.get(f.status, 5),
                                 scoring.SEVERITY_ORDER.get(f.severity, 9), f.id))
    finding_dicts = [f.to_dict() for f in findings]

    assist = _assist_checklists(finding_dicts, checklists)
    if checklists:
        for cl in checklists.get("checklists", []):
            for item in cl.get("items", []):
                item["domain"] = scoring.domain_for_checklist_item(cl["key"], item)
    scores = scoring.score_domains(finding_dicts, checklists)

    by_status = Counter(f["status"] for f in finding_dicts)
    failed_sev = Counter(f["severity"] for f in finding_dicts if f["status"] in ("fail", "warn"))
    top = [f for f in finding_dicts if f["status"] in ("fail", "warn")]
    top.sort(key=lambda f: (scoring.SEVERITY_ORDER.get(f["severity"], 9), f["status"] != "fail", f["id"]))
    quick_wins = [f["id"] for f in top if f.get("effort") == "low" and f["severity"] in ("critical", "high", "medium")]

    checklist_summary = []
    failing_items: List[Dict[str, Any]] = []
    seen_guids = set()
    for cl in (checklists or {}).get("checklists", []):
        checklist_summary.append({"key": cl["key"], "title": cl["title"], **cl["summary"]})
        for item in cl.get("items", []):
            if item.get("status") not in ("non_compliant", "partial") or item.get("guid") in seen_guids:
                continue
            seen_guids.add(item.get("guid"))
            c = item.get("counts") or {}
            failing_items.append({"checklist": cl["key"], "guid": item.get("guid"), "id": item.get("id"),
                                  "severity": item.get("severity"), "domain": item.get("domain"),
                                  "category": item.get("category"), "text": item.get("text"),
                                  "status": item["status"], "nonCompliant": c.get("nonCompliant", 0),
                                  "compliant": c.get("compliant", 0)})
    failing_items.sort(key=lambda i: (scoring.SEVERITY_ORDER.get((i["severity"] or "").lower(), 9),
                                      -i["nonCompliant"], i["text"] or ""))

    return {
        "schema": "azgov-assess/findings@1",
        "generatedAt": util.iso(),
        "tenant": run_data.get("tenant"),
        "scope": run_data.get("scope"),
        "sources": {
            "azgovviz": {"available": bool(azgv), "version": azgv.version() if azgv else None,
                         "stage": (run_data.get("stages") or {}).get("azgovviz"),
                         "html": azgv.html_report().name if azgv and azgv.html_report() else None},
            "inventory": {"available": bool(inventory), "errors": (inventory or {}).get("errors")},
            "checklists": {"available": bool(checklists),
                           "source": (checklists or {}).get("source"),
                           "queries": (checklists or {}).get("queries")},
        },
        "facts": ctx.facts,
        "hierarchy": extra.get("hierarchy"),
        "subscriptions": extra.get("subscriptions") or [],
        "inventorySummary": extra.get("inventorySummary") or {},
        "findings": finding_dicts,
        "scores": scores,
        "summary": {
            "byStatus": dict(by_status),
            "failedBySeverity": {s: failed_sev.get(s, 0) for s in ("critical", "high", "medium", "low")},
            "topRisks": [f["id"] for f in top[:10]],
            "quickWins": quick_wins[:10],
            "checklists": checklist_summary,
            "checklistTopFailures": failing_items[:40],
        },
        "checklistAssist": assist,
        "analyzerErrors": errors,
        "_checklists": checklists,
    }


def _assist_checklists(findings: List[Dict[str, Any]], checklists: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Use platform findings as evidence for otherwise-manual ALZ checklist items."""
    mapping: Dict[str, Dict[str, Any]] = {}
    status_map = {"pass": "compliant", "fail": "non_compliant", "warn": "partial", "info": "info"}
    for f in findings:
        for guid in f.get("alz") or []:
            if f["status"] in status_map:
                prev = mapping.get(guid)
                # keep the most severe verdict when several findings evidence the same item
                rank = {"non_compliant": 0, "partial": 1, "info": 2, "compliant": 3}
                new = status_map[f["status"]]
                if not prev or rank[new] < rank[prev["status"]]:
                    mapping[guid] = {"status": new, "findingId": f["id"], "summary": f.get("summary")}
    if not checklists:
        return mapping
    from .checklists import summarize
    for cl in checklists.get("checklists", []):
        changed = False
        for item in cl.get("items", []):
            hit = mapping.get(item.get("guid"))
            if hit and item.get("status") in ("manual", "no_data", "info"):
                item["assistedBy"] = hit["findingId"]
                item["assistedStatus"] = hit["status"]
                item["assistedSummary"] = hit.get("summary")
                changed = True
        if changed:
            cl["summaryAssisted"] = summarize([
                {**i, "status": i.get("assistedStatus") or i["status"]} for i in cl["items"]])
    return mapping


# ----------------------------------------------------------------------------------------------
# Brief for the AI step
# ----------------------------------------------------------------------------------------------
def brief_markdown(result: Dict[str, Any], max_findings: int = 60) -> str:
    t = result.get("tenant") or {}
    sc = result["scores"]
    lines = [f"# Azure governance assessment brief - {t.get('displayName') or t.get('tenantId')}", ""]
    lines.append(f"- Tenant: {t.get('displayName') or '?'} ({t.get('defaultDomain') or '?'}) `{t.get('tenantId')}`")
    lines.append(f"- Scope: {(result.get('scope') or {}).get('description') or 'n/a'}")
    src = result["sources"]
    lines.append(f"- Sources: AzGovViz {src['azgovviz'].get('version') or 'not run'}; Resource Graph inventory "
                 f"{'yes' if src['inventory']['available'] else 'no'}; review-checklists "
                 f"{((src['checklists'].get('source') or {}).get('commit') or '')[:7] or ('yes' if src['checklists']['available'] else 'no')}")
    lines.append(f"- Overall score: **{sc['overall']['score']}** / 100 - maturity "
                 f"**{sc['overall']['rating']['name']}** (level {sc['overall']['rating']['level']})")
    lines.append("")
    lines.append("## Facts")
    for k, v in (result.get("facts") or {}).items():
        if isinstance(v, (int, float, str)) and v not in ("", None):
            lines.append(f"- {k}: {v}")
    lines.append("")
    lines.append("## Domain scores")
    lines.append("| Domain | Score | Platform | Checklists | Fail/Warn/Pass | Checklist items failing |")
    lines.append("|---|---|---|---|---|---|")
    for d in sc["domains"]:
        c = d["checks"]
        lines.append(f"| {d['name']} (`{d['key']}`) | {d['score'] if d['score'] is not None else 'n/a'} | "
                     f"{d['platformScore'] if d['platformScore'] is not None else '-'} | "
                     f"{d['checklistScore'] if d['checklistScore'] is not None else '-'} | "
                     f"{c['fail']}/{c['warn']}/{c['pass']} | {c['checklistFailing']}/{c['checklistItems']} |")
    lines.append("")
    lines.append("## Findings (fail/warn first)")
    shown = 0
    for f in result["findings"]:
        if f["status"] not in ("fail", "warn") and shown >= max_findings // 2:
            continue
        if shown >= max_findings:
            break
        shown += 1
        lines.append(f"- **{f['id']}** [{f['status'].upper()} / {f['severity']}] ({f['domain']}) {f['title']} - "
                     f"{f.get('summary', '')}")
        if f["status"] in ("fail", "warn") and f.get("recommendation"):
            lines.append(f"  - Recommendation: {f['recommendation']}")
    lines.append("")
    lines.append("## Azure review checklists")
    for c in result["summary"].get("checklists", []):
        s = c["statusCounts"]
        lines.append(f"- {c['title']}: score {c.get('score')}%, compliant {s['compliant']}, partial {s['partial']}, "
                     f"non-compliant {s['non_compliant']} (high {c['failedBySeverity'].get('High', 0)}), "
                     f"n/a {s['not_applicable'] + s['no_data']}, manual {s['manual']}")
    lines.append("")
    lines.append("Top failing checklist items (High severity first):")
    lines.extend(_top_checklist_failures(result))
    lines.append("")
    t = result.get("trend")
    if t and (t.get("overall") or {}).get("delta") is not None:
        lines.append("")
        lines.append(f"## Trend vs previous assessment ({t.get('baselineGeneratedAt')})")
        lines.append(f"- Overall: {t['overall']['before']} -> {t['overall']['after']} ({t['overall']['delta']:+})")
        for d in t.get("domains", []):
            if d.get("delta"):
                lines.append(f"- {d['name']}: {d['before']} -> {d['after']} ({d['delta']:+})")
        for c in t.get("changes", [])[:30]:
            lines.append(f"- {c['id']} {c['change']}: {c['before']} -> {c['after']} - {c['title']}")
    lines.append("")
    lines.append("Write `analysis/ai-insights.json` following `azgov-assess insights-template`. "
                 "Reference finding IDs; do not invent facts.")
    return "\n".join(lines) + "\n"


def _top_checklist_failures(result: Dict[str, Any], limit: int = 25) -> List[str]:
    out = []
    for i in (result.get("summary") or {}).get("checklistTopFailures", [])[:limit]:
        out.append(f"- [{i['checklist']}/{i.get('id') or i['guid'][:8]}] {i['severity']} ({i.get('domain')}) "
                   f"{(i.get('text') or '')[:160]} - {i['nonCompliant']} non-compliant / {i['compliant']} compliant")
    return out or ["- none"]


# ----------------------------------------------------------------------------------------------
# Trend versus a previous assessment run
# ----------------------------------------------------------------------------------------------
_RANK = {"fail": 0, "warn": 1, "pass": 2}


def compare(current: Dict[str, Any], baseline: Dict[str, Any], baseline_dir: str = "") -> Dict[str, Any]:
    """Score and finding-status changes between a baseline findings.json and the current one."""
    def by_key(res):
        return {d["key"]: d for d in (res.get("scores") or {}).get("domains", [])}
    cur_d, base_d = by_key(current), by_key(baseline)
    domains = []
    for key, d in cur_d.items():
        b = base_d.get(key, {})
        if d.get("score") is not None and b.get("score") is not None:
            domains.append({"key": key, "name": d.get("name") or key, "before": b["score"], "after": d["score"],
                            "delta": round(d["score"] - b["score"], 1)})
    base_f = {f["id"]: f for f in baseline.get("findings", [])}
    changes = []
    for f in current.get("findings", []):
        b = base_f.get(f["id"])
        if not b or f.get("status") not in _RANK or b.get("status") not in _RANK:
            continue
        if f["status"] != b["status"]:
            changes.append({"id": f["id"], "title": f.get("title") or f["id"], "domain": f.get("domain"),
                            "severity": f.get("severity"),
                            "before": b["status"], "after": f["status"],
                            "change": "improved" if _RANK[f["status"]] > _RANK[b["status"]] else "regressed",
                            "beforeSummary": b.get("summary"), "afterSummary": f.get("summary")})
    changes.sort(key=lambda c: (c["change"] != "regressed", scoring.SEVERITY_ORDER.get(c["severity"], 9), c["id"]))
    bo = ((baseline.get("scores") or {}).get("overall") or {}).get("score")
    co = ((current.get("scores") or {}).get("overall") or {}).get("score")
    return {
        "baselineGeneratedAt": baseline.get("generatedAt"),
        "baselineRun": baseline_dir,
        "baselineSources": {k: v.get("available") if isinstance(v, dict) else None
                            for k, v in (baseline.get("sources") or {}).items()},
        "overall": {"before": bo, "after": co, "delta": round(co - bo, 1) if bo is not None and co is not None else None},
        "domains": domains,
        "changes": changes,
        "improved": sum(1 for c in changes if c["change"] == "improved"),
        "regressed": sum(1 for c in changes if c["change"] == "regressed"),
    }
