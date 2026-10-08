"""Cost management findings: budgets, orphaned/idle resources, Advisor cost guidance, consumption."""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import List

from .. import util
from ..analysis import Finding, analyzer, evidence
from .common import ALZ, ref, short_id

DOMAIN = "cost"
REF_BUDGET = ref("Create and manage budgets", "/azure/cost-management-billing/costs/tutorial-acm-create-budgets")
REF_ORPHAN = ref("Azure Orphaned Resources workbook", "https://github.com/dolevshor/azure-orphan-resources")
REF_ADVISOR = ref("Azure Advisor cost recommendations", "/azure/advisor/advisor-cost-recommendations")


@analyzer
def cost_findings(ctx) -> List[Finding]:
    out: List[Finding] = []
    per = ctx.inv("perSubscription") or []

    # CST-001 budgets
    known = [p for p in per if p.get("budgets") is not None]
    if known:
        ok = [p for p in known if p["budgets"]]
        alerting = [p for p in ok if any(int(b.get("notifications") or 0) > 0 for b in p["budgets"])]
        out.append(Finding(
            "CST-001", DOMAIN, "Budgets with alerts on every subscription", "medium",
            "pass" if len(alerting) == len(known) else ("warn" if ok else "fail"),
            f"{len(ok)} of {len(known)} subscriptions have a budget; {len(alerting)} with alert notifications.",
            details="Budgets with actual and forecast alerts are the cheapest control against runaway spend "
                    "(e.g. forgotten GPU VMs or a misconfigured autoscale).",
            recommendation="Create a monthly budget with 80%/100% actual and 110% forecast alerts per subscription "
                           "(deploy with policy or IaC during subscription vending).",
            evidence=evidence(["Subscription", "Budgets", "Amount", "Notifications"],
                              [[ctx.sub_name(p["subscriptionId"]), len(p["budgets"]),
                                ", ".join(str(b.get("amount")) for b in p["budgets"]) or "-",
                                sum(int(b.get("notifications") or 0) for b in p["budgets"])] for p in known]),
            references=[REF_BUDGET], source="ARM Consumption budgets", effort="low",
            alz=[ALZ["budget_alerts"]]))

    # CST-002 orphaned / idle resources (AzGovViz) or unattached disks + public IPs (Resource Graph)
    rows = ctx.t("ResourcesCostOptimizationAndCleanup")
    if rows:
        by_intent = Counter((r.get("Intent") or r.get("intent") or "").strip() for r in rows)
        by_type = Counter((r.get("type") or r.get("Type") or "").lower() for r in rows)
        cost_rows = [r for r in rows if "cost" in (r.get("Intent") or "").lower()]
        costs = sum(util.to_float(r.get("Cost"), 0.0) or 0.0 for r in rows)
        out.append(Finding(
            "CST-002", DOMAIN, "Orphaned and idle resources", "medium" if cost_rows else "low",
            "warn" if rows else "pass",
            f"{len(rows)} orphaned/idle resources: " + ", ".join(f"{k or '?'} {v}" for k, v in by_intent.most_common())
            + (f"; ~{costs:,.2f} in the consumption period." if costs else "."),
            details="Unattached disks, idle public IPs, empty App Service plans and stopped-but-allocated VMs cost "
                    "money, and orphaned NICs/NSGs/route tables add configuration noise and attack surface.",
            recommendation="Review the list with owners, delete what is unused and add a monthly clean-up (Azure "
                           "Orphaned Resources workbook or automation).",
            evidence=evidence(["Type", "Resource", "Intent", "Subscription"],
                              [[r.get("type") or r.get("Type"), short_id(r.get("Resource") or ""), r.get("Intent"),
                                ctx.sub_name(r.get("subscriptionId") or r.get("SubscriptionId") or "")] for r in rows]),
            references=[REF_ORPHAN], source="AzGovViz ResourcesCostOptimizationAndCleanup", effort="low",
            metric={"byType": dict(by_type.most_common(10))}))
    else:
        disks = ctx.inv("unattachedDisks") or []
        pips = [p for p in ctx.inv("publicIps") or [] if not p.get("attached")]
        if ctx.inv("unattachedDisks") is not None:
            items = [["disk", d.get("name"), f"{d.get('sizeGb')} GB {d.get('sku')}", ctx.sub_name(d.get("subscriptionId"))] for d in disks] + \
                    [["public IP", p.get("name"), p.get("sku"), ctx.sub_name(p.get("subscriptionId"))] for p in pips]
            out.append(Finding(
                "CST-002", DOMAIN, "Orphaned and idle resources", "medium",
                "warn" if items else "pass",
                f"{len(disks)} unattached managed disks and {len(pips)} unassociated public IPs." if items else
                "No unattached disks or public IPs.",
                details="Unattached disks and public IPs are billed while doing nothing.",
                recommendation="Snapshot (if needed) and delete unattached disks; release unused public IPs.",
                evidence=evidence(["Kind", "Name", "Detail", "Subscription"], items),
                references=[REF_ORPHAN], source="Resource Graph", effort="low"))

    # CST-003 Advisor cost recommendations
    adv = ctx.inv("advisor")
    if adv is not None:
        cost = [a for a in adv if (a.get("category") or "").lower() == "cost"]
        n = sum(int(a.get("resources") or 0) for a in cost)
        out.append(Finding(
            "CST-003", DOMAIN, "Azure Advisor cost recommendations", "low",
            "warn" if n else "pass",
            f"{n} resources have open Advisor cost recommendations ({len(cost)} distinct recommendations)." if n else
            "No open Advisor cost recommendations.",
            details="Advisor identifies right-sizing, reservations, savings plans and idle resources from actual usage.",
            recommendation="Review Advisor cost recommendations monthly; buy reservations/savings plans for steady "
                           "workloads.",
            evidence=evidence(["Recommendation", "Impact", "Resources"],
                              [[a.get("problem"), a.get("impact"), int(a.get("resources") or 0)] for a in cost]),
            references=[REF_ADVISOR], source="Resource Graph advisorresources", effort="low"))

    # CST-004 consumption summary (only when collected)
    cons = ctx.t("Consumption")
    if cons:
        by_sub = defaultdict(float)
        by_cat = defaultdict(float)
        currency = next((r.get("Currency") for r in cons if r.get("Currency")), "")
        for r in cons:
            c = util.to_float(r.get("PreTaxCost"), 0.0) or 0.0
            by_sub[r.get("SubscriptionName") or r.get("SubscriptionId")] += c
            by_cat[r.get("MeterCategory") or "?"] += c
        total = sum(by_sub.values())
        out.append(Finding(
            "CST-004", DOMAIN, "Consumption in the assessed period", "info", "info",
            f"{total:,.2f} {currency} across {len(by_sub)} subscriptions; top service "
            f"{max(by_cat, key=by_cat.get) if by_cat else '-'}.",
            details="Spend context for prioritising cost findings.",
            recommendation="Use Cost Management views per management group and tag to allocate spend.",
            evidence=evidence(["Meter category", "Cost"], [[k, round(v, 2)] for k, v in sorted(by_cat.items(), key=lambda kv: -kv[1])][:15]),
            references=[REF_BUDGET], source="AzGovViz Consumption", effort="low"))
    return out
