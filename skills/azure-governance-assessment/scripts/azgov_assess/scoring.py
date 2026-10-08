"""Design-area (domain) model, severity weights and maturity scoring."""

from __future__ import annotations

from collections import OrderedDict
from typing import Any, Dict, Iterable, List, Optional

DOMAINS: "OrderedDict[str, Dict[str, str]]" = OrderedDict([
    ("identity", {"name": "Identity & Access", "caf": "Identity and access management",
                  "blurb": "RBAC model, privileged and standing access, guests, service principals"}),
    ("resource_org", {"name": "Resource Organization", "caf": "Resource organization",
                      "blurb": "Management group hierarchy, subscription placement, naming and tagging"}),
    ("governance", {"name": "Governance & Policy", "caf": "Governance",
                    "blurb": "Azure Policy guardrails, compliance state, exemptions, ALZ policy currency"}),
    ("security", {"name": "Security", "caf": "Security",
                  "blurb": "Defender for Cloud coverage, secure configuration, data exposure"}),
    ("network", {"name": "Network", "caf": "Network topology and connectivity",
                 "blurb": "Topology, segmentation, private connectivity, internet exposure"}),
    ("management", {"name": "Management & Monitoring", "caf": "Management",
                    "blurb": "Logging, alerting, diagnostics, resource locks, backup"}),
    ("resiliency", {"name": "Reliability & Resiliency", "caf": "Business continuity / WAF Reliability",
                    "blurb": "Zone redundancy, replication and DR (APRL and WAF reliability checks)"}),
    ("cost", {"name": "Cost Management", "caf": "Cost management / WAF Cost",
              "blurb": "Budgets, idle and orphaned resources, Advisor cost guidance"}),
    ("performance", {"name": "Performance Efficiency", "caf": "WAF Performance efficiency",
                     "blurb": "Scalability and performance configuration (WAF)"}),
])

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# finding status -> credit (None = excluded from scoring)
FINDING_CREDIT = {"pass": 1.0, "warn": 0.5, "fail": 0.0, "info": None, "not_assessed": None}

LEVELS = [
    (90, 5, "Optimized", "Governance is automated, measured and continuously improved."),
    (75, 4, "Managed", "Guardrails are enforced at scale with only targeted gaps."),
    (60, 3, "Defined", "Core controls exist but coverage and enforcement are inconsistent."),
    (40, 2, "Developing", "Foundational controls are partial; material risks remain."),
    (0, 1, "Initial", "Governance is ad hoc; significant exposure and little enforcement."),
]

ALZ_CATEGORY_DOMAIN = {
    "azure billing and microsoft entra id tenants": "identity",
    "identity and access management": "identity",
    "network topology and connectivity": "network",
    "security": "security",
    "management": "management",
    "resource organization": "resource_org",
    "platform automation and devops": "management",
    "governance": "governance",
    "bc and dr": "resiliency",
}
WAF_PILLAR_DOMAIN = {"reliability": "resiliency", "security": "security", "cost": "cost",
                     "operations": "management", "performance": "performance"}
APRL_CATEGORY_DOMAIN = {
    "high availability": "resiliency", "disaster recovery": "resiliency", "scalability": "performance",
    "business continuity": "resiliency", "service upgrade and retirement": "resiliency",
    "other best practices": "resiliency", "personalized": "resiliency",
    "monitoring and alerting": "management", "security": "security", "governance": "governance",
}


def level_for(score: Optional[float]) -> Dict[str, Any]:
    if score is None:
        return {"level": None, "name": "Not assessed", "description": "Not enough evidence to score."}
    for floor, level, name, desc in LEVELS:
        if score >= floor:
            return {"level": level, "name": name, "description": desc}
    return {"level": 1, "name": "Initial", "description": LEVELS[-1][3]}


def domain_for_checklist_item(checklist_key: str, item: Dict[str, Any]) -> str:
    category = (item.get("category") or "").strip().lower()
    if checklist_key in ("alz", "ai_lz") and category in ALZ_CATEGORY_DOMAIN:
        return ALZ_CATEGORY_DOMAIN[category]
    if category in APRL_CATEGORY_DOMAIN and (checklist_key in ("aprl", "fullwaf") or item.get("mode") == "aprl"):
        return APRL_CATEGORY_DOMAIN[category]
    pillar = (item.get("waf") or "").strip().lower()
    if pillar in WAF_PILLAR_DOMAIN:
        return WAF_PILLAR_DOMAIN[pillar]
    if category in ALZ_CATEGORY_DOMAIN:
        return ALZ_CATEGORY_DOMAIN[category]
    if category in APRL_CATEGORY_DOMAIN:
        return APRL_CATEGORY_DOMAIN[category]
    if "network" in category:
        return "network"
    if "identity" in category or "access" in category:
        return "identity"
    if "cost" in category:
        return "cost"
    if "monitor" in category or "operation" in category:
        return "management"
    return "resiliency" if checklist_key == "aprl" else "governance"


def _item_credit(item: Dict[str, Any]) -> Optional[float]:
    status = item.get("status")
    if status == "compliant":
        return 1.0
    if status == "non_compliant":
        return 0.0
    if status == "partial":
        c = item.get("counts") or {}
        tot = c.get("compliant", 0) + c.get("nonCompliant", 0)
        return c.get("compliant", 0) / tot if tot else 0.5
    return None


def score_domains(findings: Iterable[Dict[str, Any]], checklist_results: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    acc: Dict[str, Dict[str, float]] = {k: {"w": 0.0, "p": 0.0, "fw": 0.0, "fp": 0.0, "cw": 0.0, "cp": 0.0,
                                            "pass": 0, "fail": 0, "warn": 0, "items": 0, "items_fail": 0}
                                        for k in DOMAINS}
    for f in findings:
        credit = FINDING_CREDIT.get(f.get("status"))
        if credit is None or f.get("domain") not in acc:
            continue
        w = SEVERITY_WEIGHT.get((f.get("severity") or "medium").lower(), 2) or 1
        a = acc[f["domain"]]
        a["fw"] += w
        a["fp"] += w * credit
        a[{1.0: "pass", 0.5: "warn", 0.0: "fail"}[credit]] += 1

    seen_guids = set()
    for cl in (checklist_results or {}).get("checklists", []):
        for item in cl.get("items", []):
            credit = _item_credit(item)
            if credit is None:
                continue
            guid = item.get("guid")
            if guid and guid in seen_guids:  # same item in ALZ and WAF -> count once
                continue
            seen_guids.add(guid)
            domain = item.get("domain") or domain_for_checklist_item(cl["key"], item)
            w = SEVERITY_WEIGHT.get((item.get("severity") or "medium").lower(), 2) or 1
            a = acc[domain]
            a["cw"] += w
            a["cp"] += w * credit
            a["items"] += 1
            if credit < 1:
                a["items_fail"] += 1

    domains: List[Dict[str, Any]] = []
    for key, meta in DOMAINS.items():
        a = acc[key]
        # Platform governance findings (AzGovViz) and workload checks (review-checklists) are scored
        # separately and blended 60/40 so thousands of resource checks cannot drown tenant-level controls.
        f_score = 100 * a["fp"] / a["fw"] if a["fw"] else None
        c_score = 100 * a["cp"] / a["cw"] if a["cw"] else None
        if f_score is not None and c_score is not None:
            score = 0.6 * f_score + 0.4 * c_score
        else:
            score = f_score if f_score is not None else c_score
        score = round(score, 1) if score is not None else None  # rate the value that is displayed
        domains.append({
            "key": key, "name": meta["name"], "caf": meta["caf"], "blurb": meta["blurb"],
            "score": score,
            "platformScore": round(f_score, 1) if f_score is not None else None,
            "checklistScore": round(c_score, 1) if c_score is not None else None,
            "checks": {"pass": a["pass"], "warn": a["warn"], "fail": a["fail"],
                       "checklistItems": a["items"], "checklistFailing": a["items_fail"]},
            "rating": level_for(score),
        })
    scored = [d["score"] for d in domains if d["score"] is not None]
    overall = round(sum(scored) / len(scored), 1) if scored else None
    return {"overall": {"score": overall, "rating": level_for(overall), "domainsAssessed": len(scored)},
            "domains": domains}
