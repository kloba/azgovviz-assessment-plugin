"""Governance & policy findings (AzGovViz PolicyAssignments / definitions / exemptions + Resource Graph states)."""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Dict, List

from .. import util
from ..analysis import Finding, analyzer, evidence
from .common import (ALZ, POLICY_ALLOWED_LOCATIONS, POLICY_RESOURCE_TYPES, POLICY_TAGS, POLICYSET_MCSB, guid_tail,
                     ref)

DOMAIN = "governance"
REF_POLICY = ref("ALZ design area: governance (Azure Policy)",
                 "/azure/cloud-adoption-framework/ready/landing-zone/design-area/governance")
REF_ASSIGN = ref("Azure Policy assignment structure", "/azure/governance/policy/concepts/assignment-structure")
REF_MCSB = ref("Microsoft cloud security benchmark", "/security/benchmark/azure/introduction")
REF_EXEMPT = ref("Azure Policy exemption structure", "/azure/governance/policy/concepts/exemption-structure")
REF_ENFORCE = ref("Enforcement mode", "/azure/governance/policy/concepts/assignment-structure#enforcement-mode")
REF_REMEDIATE = ref("Remediate non-compliant resources", "/azure/governance/policy/how-to/remediate-resources")
REF_ALZ_POLICIES = ref("ALZ default policy assignments",
                       "/azure/cloud-adoption-framework/ready/landing-zone/design-area/governance#azure-landing-zone-policy-assignments")
REF_LOCATIONS = ref("Allowed locations built-in policy", "/azure/governance/policy/samples/built-in-policies#general")


def _unique_assignments(rows: List[Dict[str, str]]) -> Dict[str, Dict[str, str]]:
    out: Dict[str, Dict[str, str]] = {}
    for r in rows:
        pid = r.get("PolicyAssignmentId")
        if pid and (pid not in out or (r.get("Inheritance") or "").startswith("thisScope")):
            out[pid] = r
    return out


def _scope_kind(r: Dict[str, str]) -> str:
    pid = (r.get("PolicyAssignmentId") or "").lower()
    if pid.startswith("/providers/microsoft.management/managementgroups/"):
        return "MG"
    if "/resourcegroups/" in pid:
        return "RG"
    return "Sub" if pid.startswith("/subscriptions/") else "?"


def _enforced(r: Dict[str, str]) -> bool:
    return (r.get("PolicyAssignmentEnforcementMode") or "Default").lower() != "donotenforce"


def _def_guid(r: Dict[str, str]) -> str:
    return guid_tail(r.get("PolicyId") or "")


def _covered_subscriptions(rows: List[Dict[str, str]], predicate) -> set:
    """Subscriptions where an assignment matching predicate applies (at scope or inherited, not RG-only)."""
    subs = set()
    for r in rows:
        if r.get("subscriptionId") and predicate(r) and (r.get("Inheritance") or "") != "thisScope Sub RG" \
                and (r.get("ExcludedScope") or "false").lower() != "true":
            subs.add(r["subscriptionId"])
    return subs


def _all_subscriptions(ctx) -> Dict[str, str]:
    subs = {s["id"]: s.get("name") or s["id"] for s in (getattr(ctx, "extra", {}) or {}).get("subscriptions", [])}
    return subs


@analyzer
def policy_findings(ctx) -> List[Finding]:
    rows = ctx.t("PolicyAssignments")
    out: List[Finding] = []
    subs = _all_subscriptions(ctx)
    if not rows and not ctx.azgv:
        out.append(Finding("GOV-000", DOMAIN, "Azure Policy assignment review", "high", "not_assessed",
                           "Requires AzGovViz policy assignment export - run without --skip-azgovviz.", source="—"))
        return out + _policy_states(ctx)
    uniq = _unique_assignments(rows)
    kinds = Counter(_scope_kind(r) for r in uniq.values())

    # GOV-001 guardrails at management-group scope
    mg = [r for r in uniq.values() if _scope_kind(r) == "MG"]
    out.append(Finding(
        "GOV-001", DOMAIN, "Policy guardrails assigned at management-group scope", "high",
        "pass" if mg else "fail",
        f"{len(mg)} of {len(uniq)} policy assignments are made at management-group scope "
        f"(subscription {kinds.get('Sub', 0)}, resource group {kinds.get('RG', 0)})." if uniq else
        "No policy assignments found at all.",
        details="Assigning policy once at management-group scope applies guardrails to every current and future "
                "subscription. Subscription-by-subscription assignments drift and leave new subscriptions unprotected.",
        recommendation="Assign baseline initiatives (security benchmark, allowed locations, tagging, diagnostics) at "
                       "the intermediate-root or landing-zone management groups; use exclusions/exemptions sparingly.",
        evidence=evidence(["Assignment", "Scope", "Type", "Enforcement"],
                          [[r.get("PolicyAssignmentDisplayName"), r.get("PolicyAssignmentScopeName") or r.get("MgName"),
                            r.get("PolicyVariant") or r.get("PolicyType"), r.get("PolicyAssignmentEnforcementMode")]
                           for r in sorted(uniq.values(), key=lambda x: _scope_kind(x))]),
        references=[REF_POLICY, REF_ASSIGN], source="AzGovViz PolicyAssignments", effort="medium",
        alz=[ALZ["assign_high"]]))

    # GOV-002 security baseline initiative (MCSB) coverage
    mcsb_subs = _covered_subscriptions(rows, lambda r: _def_guid(r) in POLICYSET_MCSB)
    missing = [subs.get(s, s) for s in subs if s not in mcsb_subs]
    status = "pass" if subs and not missing else ("warn" if mcsb_subs else "fail")
    out.append(Finding(
        "GOV-002", DOMAIN, "Security baseline initiative (Microsoft cloud security benchmark)", "high", status,
        f"Microsoft cloud security benchmark applies to {len(mcsb_subs)} of {len(subs)} subscriptions."
        + (f" Missing: {', '.join(missing[:5])}." if missing else ""),
        details="The MCSB initiative powers Defender for Cloud recommendations and the secure score. Without it, "
                "security posture is not continuously evaluated.",
        recommendation="Assign the 'Microsoft cloud security benchmark' initiative at the intermediate-root "
                       "management group (Defender for Cloud does this per subscription by default).",
        evidence=evidence(["Subscription", "MCSB applied"], [[subs.get(s, s), "yes" if s in mcsb_subs else "no"] for s in subs]),
        references=[REF_MCSB], source="AzGovViz PolicyAssignments", effort="low"))

    # GOV-003 allowed locations
    loc_subs = _covered_subscriptions(rows, lambda r: _enforced(r) and (
        _def_guid(r) in POLICY_ALLOWED_LOCATIONS
        or "allowed location" in (r.get("PolicyNameClear") or "").lower()
        or "allowed location" in (r.get("PolicyAssignmentDisplayName") or "").lower()))
    status = "pass" if subs and len(loc_subs) == len(subs) else ("warn" if loc_subs else "fail")
    out.append(Finding(
        "GOV-003", DOMAIN, "Data residency guardrail (allowed locations)", "medium", status,
        f"An allowed-locations policy applies to {len(loc_subs)} of {len(subs)} subscriptions.",
        details="Without a location guardrail, resources (and data) can be deployed to any Azure region, which can "
                "breach data-residency commitments and complicates DR and cost management.",
        recommendation="Assign 'Allowed locations' and 'Allowed locations for resource groups' (Deny) at the "
                       "intermediate-root management group with your approved regions.",
        evidence=evidence(["Subscription", "Allowed locations enforced"],
                          [[subs.get(s, s), "yes" if s in loc_subs else "no"] for s in subs]),
        references=[REF_LOCATIONS], source="AzGovViz PolicyAssignments", effort="low",
        alz=[ALZ["sovereignty_policy"]]))

    # GOV-004 DoNotEnforce
    dne = [r for r in uniq.values() if (r.get("PolicyAssignmentEnforcementMode") or "").lower() == "donotenforce"]
    out.append(Finding(
        "GOV-004", DOMAIN, "Policy assignments not enforced (DoNotEnforce)", "medium",
        "warn" if dne else "pass",
        f"{len(dne)} policy assignments run in DoNotEnforce mode (evaluated but not enforced)." if dne else
        "All policy assignments are enforced.",
        details="DoNotEnforce is useful for what-if testing, but left in place it silently disables Deny and "
                "DeployIfNotExists effects.",
        recommendation="Review each DoNotEnforce assignment: enforce it, or delete it if it is no longer needed.",
        evidence=evidence(["Assignment", "Scope", "Policy"],
                          [[r.get("PolicyAssignmentDisplayName"), r.get("PolicyAssignmentScopeName"), r.get("PolicyNameClear")] for r in dne]),
        references=[REF_ENFORCE], source="AzGovViz PolicyAssignments", effort="low"))

    # GOV-005 deny guardrails
    deny = [r for r in uniq.values() if "deny" in (r.get("Effect") or "").lower() and _enforced(r)]
    sets = [r for r in uniq.values() if _enforced(r) and (
        (r.get("PolicyVariant") or "").lower() in ("policyset", "initiative") or (r.get("Effect") or "").lower() == "n/a")]
    out.append(Finding(
        "GOV-005", DOMAIN, "Preventive (Deny) guardrails", "medium",
        "pass" if deny or len(sets) >= 2 else ("warn" if uniq else "fail"),
        f"{len(deny)} enforced single-policy assignments use Deny; {len(sets)} enforced initiatives assigned "
        "(initiative effects are evaluated per member policy).",
        details="Audit-only policy reports problems after they happen. Deny guardrails (locations, public network "
                "access, SKU restrictions) stop misconfiguration at deployment time.",
        recommendation="Introduce Deny policies for the highest-risk configurations (public IPs on NICs, storage "
                       "public access, allowed locations) after an audit period.",
        evidence=evidence(["Assignment", "Effect", "Scope"],
                          [[r.get("PolicyAssignmentDisplayName"), r.get("Effect"), r.get("PolicyAssignmentScopeName")] for r in deny]),
        references=[REF_POLICY], source="AzGovViz PolicyAssignments", effort="medium",
        alz=[ALZ["deny_policies"]]))

    # GOV-006 initiatives used (E01.01) & built-in first (E01.07)
    custom_assign = [r for r in uniq.values() if (r.get("PolicyType") or "").lower() in ("custom", "likely custom")]
    out.append(Finding(
        "GOV-006", DOMAIN, "Policy strategy: initiatives and built-in definitions", "low",
        "pass" if sets and len(custom_assign) <= max(3, len(uniq) // 2) else ("warn" if uniq else "fail"),
        f"{len(sets)} initiative assignments; {len(custom_assign)} of {len(uniq)} assignments use custom definitions.",
        details="Initiatives group related controls and keep assignment counts manageable; built-in definitions are "
                "maintained by Microsoft and reduce operational overhead.",
        recommendation="Group controls into initiatives aligned to your control framework and prefer built-in "
                       "definitions (see the custom/built-in parity finding).",
        references=[REF_POLICY], source="AzGovViz PolicyAssignments", effort="medium",
        alz=[ALZ["initiatives"], ALZ["builtin_first"]]))

    # GOV-007 root management group assignment count (E01.09)
    root_assign = [r for r in mg if (r.get("PolicyAssignmentId") or "").lower().startswith(
        f"/providers/microsoft.management/managementgroups/{ctx.tenant_id.lower()}/")]
    out.append(Finding(
        "GOV-007", DOMAIN, "Assignments at the Tenant Root Group", "low",
        "warn" if len(root_assign) > 10 else "pass",
        f"{len(root_assign)} policy assignments are made directly at the Tenant Root Group.",
        details="Assignments at the root cannot be scoped away from new subscriptions and invite exclusions. ALZ "
                "keeps them at an intermediate root instead.",
        recommendation="Move broad assignments from the Tenant Root Group to an intermediate-root management group.",
        evidence=evidence(["Assignment", "Policy"], [[r.get("PolicyAssignmentDisplayName"), r.get("PolicyNameClear")] for r in root_assign]),
        references=[REF_POLICY], source="AzGovViz PolicyAssignments", effort="medium",
        alz=[ALZ["root_assignments"]]))

    # GOV-008 resource-type / service restrictions
    rt = [r for r in uniq.values() if _def_guid(r) in POLICY_RESOURCE_TYPES]
    out.append(Finding(
        "GOV-008", DOMAIN, "Control of which services can be deployed", "low",
        "pass" if rt else "warn",
        f"{len(rt)} allowed/not-allowed resource type assignments." if rt else
        "No allowed/not-allowed resource type policy is assigned.",
        details="Restricting resource types keeps unapproved or unsupported services out of landing zones.",
        recommendation="Assign 'Not allowed resource types' for services you do not support (e.g. classic resources).",
        references=[REF_POLICY], source="AzGovViz PolicyAssignments", effort="low",
        alz=[ALZ["allowed_services"]]))

    # GOV-009 tag governance
    tag = [r for r in uniq.values() if _def_guid(r) in POLICY_TAGS or "tag" in (r.get("PolicyNameClear") or "").lower()]
    out.append(Finding(
        "GOV-009", DOMAIN, "Tag governance policies", "low", "pass" if tag else "warn",
        f"{len(tag)} tag-related policy assignments (require / inherit / append tags)." if tag else
        "No tag governance policies are assigned.",
        details="Tags such as owner, cost center and environment drive cost allocation, automation and incident "
                "routing; without policy they decay quickly.",
        recommendation="Assign 'Require a tag on resource groups' and 'Inherit a tag from the resource group' for your "
                       "mandatory tags.",
        evidence=evidence(["Assignment", "Scope"], [[r.get("PolicyAssignmentDisplayName"), r.get("PolicyAssignmentScopeName")] for r in tag]),
        references=[ref("Tag policies", "/azure/azure-resource-manager/management/tag-policies")],
        source="AzGovViz PolicyAssignments", effort="low"))

    # GOV-010 orphaned assignments (definition missing)
    orphan = [r for r in uniq.values() if (r.get("PolicyAvailability") or "").lower() == "na"]
    if orphan:
        out.append(Finding(
            "GOV-010", DOMAIN, "Policy assignments referencing missing definitions", "low", "warn",
            f"{len(orphan)} assignments reference policy definitions that no longer exist.",
            details="Orphaned assignments evaluate nothing yet appear as governance coverage.",
            recommendation="Delete or re-point the orphaned assignments.",
            evidence=evidence(["Assignment", "Scope"], [[r.get("PolicyAssignmentDisplayName"), r.get("PolicyAssignmentScopeName")] for r in orphan]),
            references=[REF_ASSIGN], source="AzGovViz PolicyAssignments", effort="low"))

    # GOV-011 exemptions
    if ctx.azgv:
        ex = ctx.t("PolicyExemptions")
        no_expiry = [r for r in ex if (r.get("ExpiresOn_UTC") or "n/a").lower() in ("n/a", "")]
        expired = [r for r in ex if (r.get("ExpiresOn_UTC") or "").lower().startswith("expired")]
        out.append(Finding(
            "GOV-011", DOMAIN, "Policy exemptions are time-bound", "low",
            "warn" if no_expiry or expired else "pass",
            f"{len(ex)} exemptions: {len(no_expiry)} never expire, {len(expired)} already expired." if ex else
            "No policy exemptions.",
            details="Exemptions without expiry turn temporary waivers into permanent gaps.",
            recommendation="Set an expiry and a 'Mitigated'/'Waiver' category with justification on every exemption; "
                           "remove expired exemptions.",
            evidence=evidence(["Exemption", "Scope", "Category", "Expires"],
                              [[r.get("ExemptionName"), r.get("Scope"), r.get("Category"), r.get("ExpiresOn_UTC")] for r in ex]),
            references=[REF_EXEMPT], source="AzGovViz PolicyExemptions", effort="low"))

        # GOV-012 unused custom definitions + parity with built-ins
        defs = [r for r in ctx.t("PolicyDefinitions") if (r.get("Type") or "") == "Custom"]
        unused = [r for r in defs if util.to_int(r.get("UniqueAssignmentsCount")) == 0
                  and util.to_int(r.get("UsedInPolicySetsCount")) == 0]
        sets_custom = [r for r in ctx.t("PolicySetDefinitions") if (r.get("Type") or "") == "Custom"]
        unused_sets = [r for r in sets_custom if util.to_int(r.get("UniqueAssignmentsCount")) == 0]
        parity = ctx.t("PolicyCustomBuiltInParity")
        if defs or sets_custom:
            out.append(Finding(
                "GOV-012", DOMAIN, "Custom policy hygiene", "low",
                "warn" if (unused or unused_sets or parity) else "pass",
                f"{len(defs)} custom policies ({len(unused)} unused), {len(sets_custom)} custom initiatives "
                f"({len(unused_sets)} unassigned), {len(parity)} duplicate a built-in definition.",
                details="Unused and duplicate custom definitions add maintenance burden and confuse authors.",
                recommendation="Delete unused custom definitions and replace duplicates with the equivalent built-in.",
                evidence=evidence(["Definition", "Kind", "Scope", "Issue"],
                                  [[r.get("PolicyDisplayName"), "policy", r.get("ScopeId"), "unused"] for r in unused]
                                  + [[r.get("PolicySetDisplayName"), "initiative", r.get("ScopeId"), "unassigned"] for r in unused_sets]
                                  + [[r.get("CustomPolicyDisplayName"), "policy", "", "duplicates built-in"] for r in parity]),
                references=[REF_POLICY], source="AzGovViz PolicyDefinitions", effort="low"))

            # GOV-016 where custom definitions live (E01.04: definitions at the intermediate root)
            at_sub = [r for r in defs + sets_custom if (r.get("Scope") or "").lower() == "sub"]
            at_root = [r for r in defs + sets_custom if (r.get("Scope") or "").lower() == "mg"
                       and (r.get("ScopeId") or "").lower() == ctx.tenant_id.lower()]
            out.append(Finding(
                "GOV-016", DOMAIN, "Custom definitions stored at management-group scope", "low",
                "warn" if at_sub or at_root else "pass",
                f"{len(defs) + len(sets_custom) - len(at_sub)} of {len(defs) + len(sets_custom)} custom policy/initiative "
                f"definitions are stored at management-group scope ({len(at_root)} at the Tenant Root Group, "
                f"{len(at_sub)} at subscription scope).",
                details="Definitions stored on a subscription can only be assigned there; storing them at the intermediate "
                        "root makes them reusable across the hierarchy.",
                recommendation="Store custom definitions at the intermediate-root management group (not the Tenant Root "
                               "Group or individual subscriptions) and manage them as code.",
                evidence=evidence(["Definition", "Scope", "Scope ID"],
                                  [[r.get("PolicyDisplayName") or r.get("PolicySetDisplayName"),
                                    "Tenant Root Group" if r in at_root else r.get("Scope"), r.get("ScopeId")]
                                   for r in at_root + at_sub]),
                references=[REF_POLICY], source="AzGovViz PolicyDefinitions", effort="medium",
                alz=[ALZ["defs_intermediate_root"]]))

        # GOV-013 ALZ policy currency
        alzv = ctx.t("ALZPolicyVersionChecker")
        stale = [r for r in alzv if (r.get("InTenant") or "").lower() == "true"
                 and (r.get("ALZState") or "").lower() in ("outdated", "deprecated", "obsolete")]
        if alzv:
            out.append(Finding(
                "GOV-013", DOMAIN, "Azure Landing Zone policy versions", "medium",
                "warn" if stale else "pass",
                f"{len(stale)} ALZ policy/initiative definitions in the tenant are outdated or deprecated." if stale else
                "ALZ policy definitions found in the tenant are current.",
                details="ALZ policies evolve with Azure; outdated definitions miss fixes and new resource types.",
                recommendation="Update ALZ definitions and assignments with the ALZ accelerator/AzOps or the AzAdvertizer "
                               "links in the evidence.",
                evidence=evidence(["Policy", "Scope", "State", "ALZ version"],
                                  [[r.get("PolicyName"), r.get("PolicyScope"), r.get("ALZState"), r.get("ALZVersion")] for r in stale]),
                references=[REF_ALZ_POLICIES], source="AzGovViz ALZPolicyVersionChecker", effort="medium"))

        # GOV-014 pending remediation
        rem = ctx.t("PolicyRemediation")
        total_rem = sum(util.to_int(r.get("nonCompliantResourcesCount")) for r in rem)
        out.append(Finding(
            "GOV-014", DOMAIN, "Pending DeployIfNotExists / Modify remediation", "low",
            "warn" if total_rem else "pass",
            f"{total_rem} non-compliant resources could be fixed by remediation tasks across {len(rem)} policies." if rem else
            "No outstanding DeployIfNotExists/Modify remediation (AzGovViz found no policies to remediate).",
            details="DINE/Modify policies only fix existing resources when a remediation task runs.",
            recommendation="Create remediation tasks for these assignments (portal: Policy > Remediation) and keep the "
                           "assignment identities least-privileged.",
            evidence=evidence(["Assignment", "Policy", "Effect", "Resources"],
                              [[r.get("policyAssignmentDisplayName"), r.get("policyDefinitionDisplayName"), r.get("effect"),
                                util.to_int(r.get("nonCompliantResourcesCount"))] for r in rem]),
            references=[REF_REMEDIATE], source="AzGovViz PolicyRemediation", effort="low"))
    return out + _policy_states(ctx)


def _policy_states(ctx) -> List[Finding]:
    states = ctx.inv("policyStates")
    if states is None:
        return []
    if states and "nonCompliant" in states[0]:
        r = states[0]
        non, comp = int(r.get("nonCompliant") or 0), int(r.get("compliant") or 0)
        ev = evidence(["Measure", "Value"], [["Resources with a policy state", int(r.get("resources") or 0)],
                                             ["Non-compliant (at least one policy)", non],
                                             ["Compliant with every policy", comp],
                                             ["Policy evaluations", int(r.get("evaluations") or 0)]])
    else:  # inventory.json from an earlier engine version: rows per compliance state
        by = {(r.get("state") or "").lower(): r for r in states}
        non = int((by.get("noncompliant") or {}).get("resources") or 0)
        comp = max(int((by.get("compliant") or {}).get("resources") or 0) - non, 0)
        ev = evidence(["State", "Resources", "Evaluations"],
                      [[r.get("state"), int(r.get("resources") or 0), int(r.get("n") or 0)] for r in states])
    total = non + comp
    share = round(100 * non / total, 1) if total else None
    status = "info" if share is None else ("pass" if share < 10 else ("warn" if share < 30 else "fail"))
    return [Finding(
        "GOV-015", DOMAIN, "Policy compliance state", "medium", status,
        f"{non:,} of {total:,} evaluated resources ({share}%) are non-compliant with at least one assigned policy."
        if total else "No policy compliance data returned.",
        details="Non-compliance shows where existing guardrails are already being violated; it is the backlog for "
                "remediation and exemption decisions.",
        recommendation="Triage non-compliance by initiative: remediate, exempt with expiry, or adjust the policy.",
        evidence=ev,
        references=[ref("Get compliance data", "/azure/governance/policy/how-to/get-compliance-data")],
        source="Resource Graph policyresources", effort="medium")]
