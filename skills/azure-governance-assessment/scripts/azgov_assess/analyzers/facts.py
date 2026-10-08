"""Facts, hierarchy tree, subscription table and inventory summary for the report."""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional

from .. import util
from .common import col


def _hierarchy_from_azgovviz(ctx) -> Optional[Dict[str, Any]]:
    rows = ctx.t("")
    if not rows:
        return None
    mgs: Dict[str, Dict[str, Any]] = {}
    subs: Dict[str, Dict[str, Any]] = {}
    for r in rows:
        mg = r.get("mgId")
        if mg and mg not in mgs:
            mgs[mg] = {"id": mg, "name": r.get("mgName") or mg, "parent": r.get("mgParentId") or "",
                       "level": util.to_int(r.get("level"), 0), "type": "mg"}
        sid = r.get("SubscriptionId")
        if sid and sid not in subs:
            subs[sid] = {"id": sid, "name": r.get("Subscription") or sid, "parent": mg, "type": "sub",
                         "state": r.get("SubscriptionState"), "quotaId": r.get("SubscriptionQuotaId"),
                         "secureScore": r.get("SubscriptionASCSecureScore"),
                         "tagsCount": util.to_int(r.get("SubscriptionTagsCount"), 0)}
    return {"mgs": mgs, "subs": subs}


def _hierarchy_from_inventory(ctx) -> Optional[Dict[str, Any]]:
    mg_rows = ctx.inv("managementGroups") or []
    sub_rows = ctx.inv("subscriptions") or []
    if not mg_rows and not sub_rows:
        return None
    mgs: Dict[str, Dict[str, Any]] = {}
    for r in mg_rows:
        mgs[r["name"]] = {"id": r["name"], "name": r.get("displayName") or r["name"], "parent": r.get("parent") or "",
                          "level": len(r.get("chain") or []), "type": "mg"}
    subs = {}
    for r in sub_rows:
        chain = r.get("mgChain") or []
        parent = chain[0].get("name") if chain and isinstance(chain[0], dict) else ""
        if parent and parent not in mgs and isinstance(chain[0], dict):
            mgs[parent] = {"id": parent, "name": chain[0].get("displayName") or parent, "parent": "",
                           "level": len(chain) - 1, "type": "mg"}
        subs[r["subscriptionId"]] = {"id": r["subscriptionId"], "name": r.get("name"), "parent": parent, "type": "sub",
                                     "state": r.get("state"), "quotaId": r.get("quotaId"),
                                     "tagsCount": len(r.get("tags") or {})}
    return {"mgs": mgs, "subs": subs}


def _tree(h: Dict[str, Any], counts: Dict[str, Dict[str, int]], root_id: str) -> Optional[Dict[str, Any]]:
    mgs, subs = h["mgs"], h["subs"]
    if not mgs:
        return None
    nodes = {k: {**v, "children": []} for k, v in mgs.items()}
    for k, v in nodes.items():
        c = counts.get(k, {})
        v.update({"policyAssignments": c.get("policy"), "roleAssignments": c.get("rbac")})
    for sid, s in subs.items():
        c = counts.get(sid, {})
        node = {**s, "children": [], "policyAssignments": c.get("policy"), "roleAssignments": c.get("rbac"),
                "resources": c.get("resources")}
        if s.get("parent") in nodes:
            nodes[s["parent"]]["children"].append(node)
    roots = []
    for k, v in nodes.items():
        parent = v.get("parent")
        if parent and parent in nodes and parent != k:
            nodes[parent]["children"].append(v)
        else:
            roots.append(v)
    for v in nodes.values():
        v["children"].sort(key=lambda n: (n["type"] != "mg", (n.get("name") or "").lower()))
    root = nodes.get(root_id) or (sorted(roots, key=lambda n: n.get("level", 0))[0] if roots else None)
    return root


def _depth(node: Optional[Dict[str, Any]], level: int = 0) -> int:
    if not node:
        return 0
    child_mgs = [c for c in node.get("children", []) if c.get("type") == "mg"]
    return max([level] + [_depth(c, level + 1) for c in child_mgs])


def _max_level(node: Optional[Dict[str, Any]]) -> int:
    """Deepest absolute management-group level (0 = Tenant Root Group), also correct for scoped runs."""
    if not node or node.get("type") != "mg":
        return 0
    return max([util.to_int(node.get("level"), 0) or 0] + [_max_level(c) for c in node.get("children", [])])


def _secure_score_pct(text: Any) -> Optional[float]:
    if text is None:
        return None
    s = str(text).strip()
    if not s or s.startswith(("n/a", "excluded")):
        return None
    try:
        return float(s.split("%")[0].strip())
    except ValueError:
        return util.to_float(s)


def collect(ctx) -> Dict[str, Any]:
    facts: Dict[str, Any] = {}
    root_id = ctx.tenant_id
    h = _hierarchy_from_azgovviz(ctx) or _hierarchy_from_inventory(ctx) or {"mgs": {}, "subs": {}}

    # per-scope counts for the tree
    counts: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    seen_pa = set()
    for r in ctx.t("PolicyAssignments"):
        inh = r.get("Inheritance") or ""
        pid = r.get("PolicyAssignmentId")
        if not inh.startswith("thisScope") or (pid, inh) in seen_pa:
            continue
        seen_pa.add((pid, inh))
        if inh == "thisScope Mg":
            counts[r.get("MgId")]["policy"] += 1
        elif inh == "thisScope Sub":
            counts[r.get("subscriptionId")]["policy"] += 1
    seen_ra = set()
    for r in ctx.t("RoleAssignments"):
        scope = r.get("Scope") or ""
        rid = r.get("RoleAssignmentId")
        if (r.get("AssignmentType") or "direct") != "direct" or rid in seen_ra:
            continue
        if scope == "thisScope MG":
            seen_ra.add(rid)
            counts[r.get("MgId")]["rbac"] += 1
        elif scope == "thisScope Sub":
            seen_ra.add(rid)
            counts[r.get("SubscriptionId")]["rbac"] += 1
    for r in ctx.inv("subscriptionCounts") or []:
        counts[r["subscriptionId"]]["resources"] = int(r.get("n") or 0)

    tree = _tree(h, counts, root_id)
    ctx.hierarchy = tree
    facts["managementGroups"] = len(h["mgs"])
    facts["mgDepth"] = max(_depth(tree), _max_level(tree)) if tree else None
    facts["subscriptions"] = len(h["subs"]) or len(ctx.inv("subscriptions") or [])
    states = Counter((s.get("state") or "").lower() for s in h["subs"].values())
    facts["subscriptionsEnabled"] = states.get("enabled", 0) if h["subs"] else None

    # resources / types / regions
    type_rows = ctx.inv("typeCounts") or []
    loc_rows = ctx.inv("locationCounts") or []
    if type_rows:
        facts["resources"] = sum(int(r["n"]) for r in type_rows)
        facts["resourceTypes"] = len(type_rows)
        facts["regions"] = len([r for r in loc_rows if r.get("location") not in ("", "global")])
    elif ctx.has("ResourcesAll"):
        res = ctx.t("ResourcesAll")
        facts["resources"] = len(res)
        facts["resourceTypes"] = len({r.get("type") for r in res})
        facts["regions"] = len({r.get("location") for r in res if r.get("location") not in ("", "global")})
        type_rows = [{"type": t, "n": n} for t, n in Counter(r.get("type") for r in res).most_common()]
        loc_rows = [{"location": l, "n": n} for l, n in Counter(r.get("location") for r in res).most_common()]
    facts["resourceGroups"] = sum(int(r.get("total") or 0) for r in ctx.inv("resourceGroups") or []) or None

    # policy facts
    pa_unique = {}
    for r in ctx.t("PolicyAssignments"):
        pid = r.get("PolicyAssignmentId")
        if pid and (pid not in pa_unique or (r.get("Inheritance") or "").startswith("thisScope")):
            pa_unique[pid] = r
    if pa_unique:
        facts["policyAssignments"] = len(pa_unique)
        inh = Counter((r.get("Inheritance") or "") for r in pa_unique.values())
        facts["policyAssignmentsMg"] = inh.get("thisScope Mg", 0)
        facts["policyAssignmentsSub"] = inh.get("thisScope Sub", 0)
        facts["policyAssignmentsRg"] = inh.get("thisScope Sub RG", 0)
    daily = {r.get("capability"): util.to_int(r.get("count")) for r in ctx.t("DailySummary")}
    if daily:
        facts.setdefault("policyAssignments", daily.get("PolicyAssignments"))
        facts.setdefault("policyAssignmentsMg", daily.get("PolicyAssignments_ManagementGroups"))
        facts["customPolicyDefinitions"] = daily.get("PolicyDefinitionsCustom")
        facts["customPolicySetDefinitions"] = daily.get("PolicySetDefinitionsCustom")
        facts["customRoles"] = daily.get("RoleDefinitionsCustom")
    else:
        facts["customPolicyDefinitions"] = sum(1 for r in ctx.t("PolicyDefinitions") if r.get("Type") == "Custom") or None
        facts["customPolicySetDefinitions"] = sum(1 for r in ctx.t("PolicySetDefinitions") if r.get("Type") == "Custom") or None
        facts["customRoles"] = sum(1 for r in ctx.t("RoleDefinitions") if r.get("Type") == "Custom") or None
    facts["policyExemptions"] = len(ctx.t("PolicyExemptions")) if ctx.azgv else None

    # rbac facts
    ra_unique: Dict[str, Dict[str, str]] = {}
    for r in ctx.t("RoleAssignments"):
        rid = r.get("RoleAssignmentId")
        if rid and (r.get("AssignmentType") or "direct") == "direct":
            ra_unique.setdefault(rid, r)
    if ra_unique:
        facts["roleAssignments"] = len(ra_unique)
        facts["roleAssignmentsOwner"] = sum(1 for r in ra_unique.values() if (r.get("RoleClear") or "").lower() == "owner")
        facts["principalsWithAccess"] = len({r.get("ObjectId") for r in ra_unique.values()})
    elif daily:
        facts["roleAssignments"] = daily.get("TotalRoleAssignments")

    # security / tags
    scores = [s.get("percentage") for s in ctx.inv("secureScores") or [] if s.get("percentage") is not None]
    if scores:
        facts["secureScoreAvgPct"] = round(100 * sum(scores) / len(scores), 1)
    tags = ctx.inv("tagCoverage") or []
    total = sum(int(r.get("total") or 0) for r in tags)
    tagged = sum(int(r.get("tagged") or 0) for r in tags)
    if total:
        facts["resourceTagCoveragePct"] = round(100 * tagged / total, 1)
    cq = ((ctx.checklists or {}).get("queries") or {})
    facts["checklistQueries"] = cq.get("unique")

    ctx.extra = {
        "hierarchy": tree,
        "subscriptions": _subscription_table(ctx, h),
        "inventorySummary": {
            "types": [{"type": r["type"], "n": int(r["n"])} for r in type_rows[:60]],
            "locations": [{"location": r["location"] or "(none)", "n": int(r["n"])} for r in loc_rows[:40]],
            "advisor": ctx.inv("advisor") or [],
            "securityRecommendations": (ctx.inv("securityRecommendations") or [])[:100],
        },
    }
    return {k: v for k, v in facts.items() if v is not None}


def _subscription_table(ctx, h: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows: Dict[str, Dict[str, Any]] = {}
    for sid, s in h["subs"].items():
        rows[sid] = {"id": sid, "name": s.get("name"), "state": s.get("state"), "offer": s.get("quotaId"),
                     "secureScore": _secure_score_pct(s.get("secureScore")), "tagsCount": s.get("tagsCount")}
    for s in ctx.inv("subscriptions") or []:
        r = rows.setdefault(s["subscriptionId"], {"id": s["subscriptionId"]})
        r.setdefault("name", s.get("name"))
        r["name"] = r.get("name") or s.get("name")
        r["state"] = r.get("state") or s.get("state")
        r["offer"] = r.get("offer") or s.get("quotaId")
        chain = s.get("mgChain") or []
        if chain:
            r["mgPath"] = " / ".join(reversed([c.get("displayName") or c.get("name") for c in chain if isinstance(c, dict)]))
    for d in ctx.t("SubscriptionDetails"):
        sid = d.get("SubscriptionId")
        if sid in rows:
            rows[sid]["mgPath"] = rows[sid].get("mgPath") or (d.get("ManagementGroupPath") or "").replace("/", " / ")
            if rows[sid].get("secureScore") is None:
                rows[sid]["secureScore"] = _secure_score_pct(d.get("MDfCScore"))
    for s in ctx.inv("secureScores") or []:
        if s.get("subscriptionId") in rows and s.get("percentage") is not None:
            rows[s["subscriptionId"]]["secureScore"] = round(100 * float(s["percentage"]), 1)
    for r in ctx.inv("subscriptionCounts") or []:
        if r["subscriptionId"] in rows:
            rows[r["subscriptionId"]]["resources"] = int(r["n"])
    for r in ctx.inv("resourceGroups") or []:
        if r["subscriptionId"] in rows:
            rows[r["subscriptionId"]]["resourceGroups"] = int(r.get("total") or 0)
    plans = defaultdict(int)
    for p in ctx.inv("defenderPlans") or []:
        if (p.get("tier") or "").lower() == "standard" and not p.get("deprecated"):
            plans[p["subscriptionId"]] += 1
    if not plans:
        for p in ctx.t("MDfCCoverage"):
            if (p.get("pricingTier") or "").lower() == "standard":
                plans[p.get("subscriptionId")] += 1
    for sid in rows:
        if plans or ctx.inv("defenderPlans") is not None or ctx.has("MDfCCoverage"):
            rows[sid]["defenderPlansOn"] = plans.get(sid, 0)
    for p in ctx.inv("perSubscription") or []:
        r = rows.get(p["subscriptionId"])
        if not r:
            continue
        if p.get("budgets") is not None:
            r["budget"] = bool(p["budgets"])
        if p.get("activityLogDiagnostics") is not None:
            r["activityLogExport"] = bool(p["activityLogDiagnostics"])
    return sorted(rows.values(), key=lambda r: (r.get("name") or "").lower())
