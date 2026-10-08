"""Resource organization findings: management-group structure, subscription placement, tagging, naming."""

from __future__ import annotations

import re
from collections import Counter
from typing import Any, Dict, List, Optional

from .. import util
from ..analysis import Finding, analyzer, evidence
from .common import ALZ, ref

DOMAIN = "resource_org"
REF_MG = ref("ALZ design area: resource organization (management groups)",
             "/azure/cloud-adoption-framework/ready/landing-zone/design-area/resource-org-management-groups")
REF_SETTINGS = ref("Management group hierarchy settings",
                   "/azure/governance/management-groups/how-to/protect-resource-hierarchy")
REF_TAGS = ref("Define your tagging strategy", "/azure/cloud-adoption-framework/ready/azure-best-practices/resource-tagging")
REF_NAMING = ref("Abbreviation recommendations for Azure resources",
                 "/azure/cloud-adoption-framework/ready/azure-best-practices/resource-abbreviations")

PLATFORM = re.compile(r"platform|connectivity|identity|management|mgmt|shared|hub", re.I)
LANDING = re.compile(r"landing|landingzone|\blz\b|corp|online|workload|application|apps|prod|nonprod", re.I)
SANDBOX = re.compile(r"sandbox|sbx|playground|lab|experiment", re.I)
DECOM = re.compile(r"decom|retire|archive", re.I)


def _walk(node: Optional[Dict[str, Any]], depth: int = 0, parent: Optional[Dict[str, Any]] = None):
    if not node:
        return
    yield node, depth, parent
    for c in node.get("children", []):
        yield from _walk(c, depth + 1 if c.get("type") == "mg" else depth, node)


@analyzer
def organization_findings(ctx) -> List[Finding]:
    tree = (getattr(ctx, "extra", {}) or {}).get("hierarchy")
    out: List[Finding] = []
    if not tree:
        out.append(Finding("ORG-000", DOMAIN, "Management group hierarchy", "medium", "not_assessed",
                           "Management group data unavailable (no Reader at tenant root and no AzGovViz output).",
                           source="—"))
    else:
        nodes = list(_walk(tree))
        mgs = [(n, d) for n, d, _ in nodes if n.get("type") == "mg"]
        subs = [(n, p) for n, d, p in nodes if n.get("type") == "sub"]
        root_id = tree.get("id")
        under_root = [n for n, p in subs if p and p.get("id") == root_id]
        child_mgs = [c for c in tree.get("children", []) if c.get("type") == "mg"]
        names = " ".join(f"{n.get('name')} {n.get('id')}" for n, _ in mgs if n.get("id") != root_id)
        # a --management-group run sees a subtree: its top is not the Tenant Root Group
        is_tenant_root = str(root_id or "").lower() == str(ctx.tenant_id or "").lower()
        root_label = "the Tenant Root Group" if is_tenant_root else f"the assessed management group '{tree.get('name') or root_id}'"

        # ORG-001 subscriptions directly under the root
        if is_tenant_root:
            org1_status = "fail" if under_root else "pass"
            org1_summary = (f"{len(under_root)} of {len(subs)} subscriptions sit directly under the Tenant Root Group."
                            if under_root else f"All {len(subs)} subscriptions are placed in child management groups.")
        else:
            org1_status = "info"
            org1_summary = (f"Scoped run: the Tenant Root Group is outside the assessed scope. {len(under_root)} of "
                            f"{len(subs)} subscriptions sit directly under {root_label}.")
        out.append(Finding(
            "ORG-001", DOMAIN, "Subscriptions placed directly under the Tenant Root Group", "medium",
            org1_status, org1_summary,
            details="Subscriptions under the root inherit only root-level policy and RBAC, cannot be governed by "
                    "landing-zone archetypes, and signal an unmanaged hierarchy.",
            recommendation="Create an intermediate-root management group with Platform / Landing zones / Sandbox "
                           "children and move each subscription to the group that matches its workload type.",
            evidence=evidence(["Subscription", "ID"], [[n.get("name"), n.get("id")] for n in under_root]),
            references=[REF_MG], source="AzGovViz hierarchy", effort="low"))

        # ORG-002 intermediate root / hierarchy exists
        has_intermediate = any(any(cc.get("type") == "mg" for cc in c.get("children", [])) or
                               any(cc.get("type") == "sub" for cc in c.get("children", [])) for c in child_mgs)
        out.append(Finding(
            "ORG-002", DOMAIN, "Management group hierarchy beneath the root", "medium",
            "pass" if child_mgs and has_intermediate else ("warn" if child_mgs else "fail"),
            f"{len(mgs)} management groups (including {'the Tenant Root Group' if is_tenant_root else 'the top of the scope'}); "
            f"{len(child_mgs)} directly under {root_label}."
            if child_mgs else f"Only {root_label} exists - no management group hierarchy below it.",
            details="A management group hierarchy is the backbone for scaling policy and RBAC. ALZ uses an intermediate "
                    "root (e.g. 'contoso') so that tenant-wide settings stay separate from your governance.",
            recommendation="Deploy the ALZ management group structure (intermediate root > Platform, Landing zones, "
                           "Sandbox, Decommissioned) - start small, it is cheap to create and hard to retrofit later.",
            evidence=evidence(["Management group", "Depth", "Child MGs", "Subscriptions"],
                              [[n.get("name"), d, sum(1 for c in n.get("children", []) if c.get("type") == "mg"),
                                sum(1 for c in n.get("children", []) if c.get("type") == "sub")] for n, d in mgs]),
            references=[REF_MG], source="AzGovViz hierarchy", effort="medium", alz=[ALZ["workload_mgs"]]))

        # ORG-003 platform / landing zone separation
        has_platform, has_lz = bool(PLATFORM.search(names)), bool(LANDING.search(names))
        out.append(Finding(
            "ORG-003", DOMAIN, "Platform and landing-zone separation", "medium",
            "pass" if has_platform and has_lz else ("warn" if has_platform or has_lz else "fail"),
            f"Platform management group: {'found' if has_platform else 'not found'}; landing-zone management "
            f"group(s): {'found' if has_lz else 'not found'}.",
            details="Separating shared platform services (connectivity, identity, management) from application "
                    "landing zones lets you apply different policy and access models to each.",
            recommendation="Create 'Platform' (Connectivity, Identity, Management) and 'Landing zones' (Corp, Online) "
                           "management groups and place subscriptions by purpose.",
            references=[REF_MG], source="AzGovViz hierarchy", effort="medium", alz=[ALZ["platform_mg"]]))

        # ORG-004 sandbox
        out.append(Finding(
            "ORG-004", DOMAIN, "Sandbox management group for experimentation", "low",
            "pass" if SANDBOX.search(names) else "warn",
            "A sandbox management group exists." if SANDBOX.search(names) else "No sandbox management group found.",
            details="A sandbox lets teams experiment under relaxed policy without touching production landing zones.",
            recommendation="Create a 'Sandbox' management group with its own (looser) policy set and budgets.",
            references=[REF_MG], source="AzGovViz hierarchy", effort="low", alz=[ALZ["sandbox_mg"]]))

        if not is_tenant_root:
            # a subtree cannot show the tenant's platform / landing-zone / sandbox layout: report, do not score,
            # and do not answer the ALZ checklist items with it
            for f in out:
                if f.id in ("ORG-002", "ORG-003", "ORG-004"):
                    f.status, f.alz = "info", []
                    f.summary = f"Scoped run (top: {root_label}) - not scored: {f.summary}"

        # ORG-005 depth
        # absolute level (AzGovViz `level` / ARG ancestor chain) so scoped runs measure from the real root
        depth = max((max(d, util.to_int(n.get("level"), 0) or 0) for n, d in mgs), default=0)
        out.append(Finding(
            "ORG-005", DOMAIN, "Hierarchy depth", "low", "pass" if depth <= 4 else "warn",
            f"The deepest management group is {depth} level(s) below the Tenant Root Group.",
            details="Deep hierarchies make inheritance hard to reason about; ALZ recommends no more than four levels.",
            recommendation="Keep the hierarchy flat (<= 4 levels) and model differences with policy parameters.",
            references=[REF_MG], source="AzGovViz hierarchy", effort="low"))

    # ORG-006 / ORG-007 hierarchy settings (Resource Graph / ARM)
    settings = (ctx.inventory or {}).get("hierarchySettings")
    settings_error = ((ctx.inventory or {}).get("errors") or {}).get("hierarchySettings")
    if settings is None and settings_error:
        # only a 404 means "defaults apply" (stored as {}); any other error leaves the settings unknown
        for fid, title in (("ORG-006", "Default management group for new subscriptions"),
                           ("ORG-007", "Management group creation requires authorization")):
            out.append(Finding(fid, DOMAIN, title, "low" if fid == "ORG-006" else "medium", "not_assessed",
                               f"Hierarchy settings could not be read: {str(settings_error)[:160]}",
                               recommendation="Re-run with Reader on the Tenant Root Group to evaluate this setting.",
                               references=[REF_SETTINGS], source="ARM hierarchy settings"))
    elif settings is not None:
        default_mg = (settings or {}).get("defaultManagementGroup")
        default_is_root = not default_mg or default_mg.rstrip("/").split("/")[-1].lower() == ctx.tenant_id.lower()
        out.append(Finding(
            "ORG-006", DOMAIN, "Default management group for new subscriptions", "low",
            "warn" if default_is_root else "pass",
            "New subscriptions land in the Tenant Root Group (default setting)." if default_is_root else
            f"New subscriptions land in '{default_mg.split('/')[-1]}'.",
            details="Without a default management group, newly created subscriptions start ungoverned at the root.",
            recommendation="Set a default management group (e.g. a 'Sandbox' or 'Onboarding' group) in Management "
                           "groups > Settings.",
            references=[REF_SETTINGS], source="ARM hierarchy settings", effort="low"))
        auth = bool((settings or {}).get("requireAuthorizationForGroupCreation"))
        out.append(Finding(
            "ORG-007", DOMAIN, "Management group creation requires authorization", "medium",
            "pass" if auth else "fail",
            "Only users with management-group write permission at the root can create management groups."
            if auth else "Any user can create management groups (RBAC authorization is not required).",
            details="By default every user can create management groups under the root, bypassing the intended "
                    "structure and its policy assignments.",
            recommendation="Enable 'Require write permissions for creating new management groups' in hierarchy settings.",
            references=[REF_SETTINGS], source="ARM hierarchy settings", effort="low", alz=[ALZ["mg_rbac_auth"]]))

    # ORG-008 resource tagging coverage
    tag_rows = ctx.inv("tagCoverage") or []
    total = sum(int(r.get("total") or 0) for r in tag_rows)
    tagged = sum(int(r.get("tagged") or 0) for r in tag_rows)
    rg = ctx.inv("resourceGroups") or []
    rg_total = sum(int(r.get("total") or 0) for r in rg)
    rg_tagged = sum(int(r.get("tagged") or 0) for r in rg)
    if total:
        share = round(100 * tagged / total, 1)
        rg_share = round(100 * rg_tagged / rg_total, 1) if rg_total else None
        worst = sorted(tag_rows, key=lambda r: (int(r.get("tagged") or 0) / max(1, int(r.get("total") or 0)),
                                                -int(r.get("total") or 0)))
        out.append(Finding(
            "ORG-008", DOMAIN, "Tagging coverage", "medium",
            "pass" if share >= 80 else ("warn" if share >= 50 else "fail"),
            f"{share}% of resources ({tagged:,}/{total:,}) carry at least one tag"
            + (f"; {rg_share}% of resource groups ({rg_tagged}/{rg_total})." if rg_share is not None else "."),
            details="Tags are how cost, ownership and environment are attributed. Untagged resources become "
                    "unowned spend and slow down incident response.",
            recommendation="Define mandatory tags (owner, costCenter, environment, application), enforce them with "
                           "policy on resource groups and inherit them to resources.",
            evidence=evidence(["Resource type", "Resources", "Tagged", "Coverage %"],
                              [[r["type"], int(r["total"]), int(r["tagged"]),
                                round(100 * int(r["tagged"]) / max(1, int(r["total"])), 1)] for r in worst[:30]]),
            references=[REF_TAGS], source="Resource Graph", effort="medium"))

    # ORG-009 subscription tags
    subs_tbl = (getattr(ctx, "extra", {}) or {}).get("subscriptions", [])
    if subs_tbl and any(s.get("tagsCount") is not None for s in subs_tbl):
        untagged = [s for s in subs_tbl if not s.get("tagsCount")]
        out.append(Finding(
            "ORG-009", DOMAIN, "Subscription metadata tags", "low", "warn" if untagged else "pass",
            f"{len(untagged)} of {len(subs_tbl)} subscriptions have no tags." if untagged else
            "All subscriptions carry tags.",
            details="Subscription tags (owner, cost center, environment, criticality) feed cost reports and landing-"
                    "zone automation.",
            recommendation="Tag every subscription with owner, cost center, environment and data classification.",
            evidence=evidence(["Subscription"], [[s.get("name")] for s in untagged]),
            references=[REF_TAGS], source="AzGovViz / Resource Graph", effort="low"))

    # ORG-010 CAF naming (AzGovViz ResourcesAll)
    res = ctx.t("ResourcesAll")
    if res:
        verdicts = Counter((r.get("cafResourceNamingResult") or "n/a").lower() for r in res)
        judged = verdicts.get("passed", 0) + verdicts.get("failed", 0)
        if judged:
            share = round(100 * verdicts.get("passed", 0) / judged, 1)
            failed_types = Counter(r.get("type") for r in res if (r.get("cafResourceNamingResult") or "").lower() == "failed")
            out.append(Finding(
                "ORG-010", DOMAIN, "Naming convention (CAF abbreviations)", "low",
                "pass" if share >= 80 else ("warn" if share >= 40 else "fail"),
                f"{share}% of {judged:,} resources with a CAF abbreviation follow it in their name.",
                details="A consistent naming scheme makes ownership, environment and resource type obvious in logs, "
                        "bills and alerts.",
                recommendation="Adopt the CAF naming convention (type abbreviation, workload, environment, region, "
                               "instance) and enforce it in IaC modules.",
                evidence=evidence(["Resource type", "Names not following CAF"], [[t, n] for t, n in failed_types.most_common(20)]),
                references=[REF_NAMING], source="AzGovViz ResourcesAll", effort="high", alz=[ALZ["naming"]]))

    # ORG-011 subscription states
    if subs_tbl:
        bad = [s for s in subs_tbl if (s.get("state") or "Enabled").lower() not in ("enabled", "")]
        if bad:
            out.append(Finding(
                "ORG-011", DOMAIN, "Subscriptions not in Enabled state", "low", "warn",
                f"{len(bad)} subscriptions are {', '.join(sorted({s.get('state') for s in bad}))}.",
                details="Disabled/warned subscriptions still hold data and role assignments.",
                recommendation="Move them to a Decommissioned management group and delete or re-enable them.",
                evidence=evidence(["Subscription", "State"], [[s.get("name"), s.get("state")] for s in bad]),
                references=[REF_MG], source="Resource Graph", effort="low"))
    return out
