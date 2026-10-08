"""Identity & access findings (AzGovViz RoleAssignments / RoleDefinitions / ClassicAdministrators)."""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Dict, List

from ..analysis import Finding, analyzer, evidence
from .common import ALZ, PRIVILEGED_ROLE_NAMES, WRITE_ROLE_NAMES, ref

DOMAIN = "identity"
REF_RBAC = ref("Azure RBAC best practices", "/azure/role-based-access-control/best-practices")
REF_PIM = ref("Privileged Identity Management for Azure resources",
              "/entra/id-governance/privileged-identity-management/pim-resource-roles-assign-roles")
REF_ALZ_IAM = ref("ALZ design area: identity and access management",
                  "/azure/cloud-adoption-framework/ready/landing-zone/design-area/identity-access")
REF_ELEVATE = ref("Elevate access to manage all Azure subscriptions",
                  "/azure/role-based-access-control/elevate-access-global-admin")
REF_CLASSIC = ref("Azure classic subscription administrators (retired)",
                  "/azure/role-based-access-control/classic-administrators")
REF_ORPHAN = ref("Troubleshoot Azure RBAC - identity not found", "/azure/role-based-access-control/troubleshooting")
REF_CUSTOM = ref("Azure custom roles", "/azure/role-based-access-control/custom-roles")
REF_GUEST = ref("Restrict guest access permissions", "/entra/identity/users/users-restrict-guest-permissions")


def _role(r: Dict[str, str]) -> str:
    return (r.get("RoleClear") or "").strip()


def _unique(rows: List[Dict[str, str]]) -> Dict[str, Dict[str, str]]:
    """Unique role assignments (direct rows), preferring the row at the assignment's own scope."""
    out: Dict[str, Dict[str, str]] = {}
    for r in rows:
        rid = r.get("RoleAssignmentId")
        if not rid or (r.get("AssignmentType") or "direct") != "direct":
            continue
        if rid not in out or (r.get("Scope") or "").startswith("thisScope"):
            out[rid] = r
    return out


def _scope_label(r: Dict[str, str]) -> str:
    kind = r.get("ScopeTenOrMgOrSubOrRGOrRes") or ""
    if kind == "Ten":
        return "Root '/' (tenant)"
    if kind == "Mg":
        return f"MG {r.get('RoleAssignmentScopeName') or r.get('MgName') or r.get('MgId')}"
    name = r.get("SubscriptionName") or r.get("SubscriptionId") or ""
    if kind == "Sub":
        return f"Sub {name}"
    if kind == "RG":
        return f"RG {r.get('RoleAssignmentScopeRG')} ({name})"
    if kind == "Res":
        return f"Res {r.get('RoleAssignmentScopeRes')} ({name})"
    return r.get("Scope") or ""


def _principal(r: Dict[str, str]) -> str:
    name = r.get("ObjectDisplayName") or ""
    sign = r.get("ObjectSignInName") or ""
    if sign.lower() in ("n/a", "na", "none"):
        sign = ""
    if sign and sign not in name:
        return f"{name} ({sign})" if name else sign
    return name or r.get("ObjectId") or "?"


@analyzer
def identity_findings(ctx) -> List[Finding]:
    rows = ctx.t("RoleAssignments")
    if not rows:
        if ctx.azgv:
            return [Finding("IAM-000", DOMAIN, "Role assignment data", "info", "not_assessed",
                            "AzGovViz did not export role assignments (no data or -NoCsvExport).", source="AzGovViz")]
        return [Finding("IAM-000", DOMAIN, "Privileged access review", "high", "not_assessed",
                        "Requires AzGovViz (Microsoft Graph enrichment of role assignments) - run without --skip-azgovviz.",
                        source="—")]
    out: List[Finding] = []
    uniq = _unique(rows)
    total = len(uniq)

    # IAM-001 guests with privileged / write roles (direct or through a group). No `thisScope` filter: AzGovViz only
    # writes root '/' assignments as inherited rows; the (ObjectId, RoleAssignmentId) dedup below avoids double counts.
    guest_rows = [r for r in rows if r.get("ObjectType") == "User Guest" and _role(r).lower() in WRITE_ROLE_NAMES]
    seen = set()
    guest_ev = []
    for r in guest_rows:
        key = (r.get("ObjectId"), r.get("RoleAssignmentId"))
        if key in seen:
            continue
        seen.add(key)
        guest_ev.append([_principal(r), _role(r), _scope_label(r),
                         "via group " + (r.get("AssignmentInheritFrom") or "") if r.get("AssignmentType") == "indirect" else "direct"])
    guests_priv = {r.get("ObjectId") for r in guest_rows if _role(r).lower() in PRIVILEGED_ROLE_NAMES}
    out.append(Finding(
        "IAM-001", DOMAIN, "Guest accounts with privileged or write access",
        "critical" if any(r.get("ScopeTenOrMgOrSubOrRGOrRes") in ("Ten", "Mg") and _role(r).lower() in PRIVILEGED_ROLE_NAMES
                          for r in guest_rows) else "high",
        "fail" if guests_priv else ("warn" if guest_ev else "pass"),
        (f"{len({e[0] for e in guest_ev})} guest identities hold Owner/Contributor/User Access Administrator "
         f"({len(guests_priv)} with Owner-level rights)." if guest_ev else
         "No guest (B2B) identities hold Owner, Contributor or User Access Administrator."),
        details="External identities are governed by another organisation's lifecycle and security controls. "
                "Privileged access for guests is a common lateral-movement and data-exfiltration path.",
        recommendation="Remove or downgrade guest privileged assignments; if external admins are required use Azure "
                       "Lighthouse or PIM-eligible, time-bound assignments with access reviews.",
        evidence=evidence(["Principal", "Role", "Scope", "Assignment"], guest_ev),
        references=[REF_GUEST, REF_RBAC], source="AzGovViz RoleAssignments", effort="low"))

    # IAM-002 service principals with Owner / UAA (excluding policy-assignment managed identities)
    sp_rows = [r for r in uniq.values() if (r.get("ObjectType") or "").startswith("SP")
               and _role(r).lower() in PRIVILEGED_ROLE_NAMES
               and (r.get("RbacRelatedPolicyAssignmentClear") or "none") == "none"]
    broad = [r for r in sp_rows if r.get("ScopeTenOrMgOrSubOrRGOrRes") in ("Ten", "Mg", "Sub")]
    out.append(Finding(
        "IAM-002", DOMAIN, "Service principals with Owner or User Access Administrator",
        "high", "fail" if broad else ("warn" if sp_rows else "pass"),
        (f"{len(broad)} service principal/managed identity assignments grant Owner-level rights at subscription "
         f"or higher scope ({len(sp_rows)} in total)." if sp_rows else
         "No service principal or managed identity holds Owner/User Access Administrator."),
        details="A compromised automation credential with Owner can change RBAC and policy, disable logging and "
                "exfiltrate data. Pipelines rarely need more than Contributor on a narrow scope.",
        recommendation="Replace Owner with least-privilege roles (Contributor or custom) scoped to the target "
                       "resource groups; use workload identity federation instead of secrets; review regularly.",
        evidence=evidence(["Principal", "Type", "Role", "Scope"],
                          [[_principal(r), r.get("ObjectType"), _role(r), _scope_label(r)] for r in sp_rows]),
        references=[REF_RBAC], source="AzGovViz RoleAssignments", effort="medium"))

    # IAM-003 orphaned assignments
    orphans = [r for r in uniq.values() if (r.get("ObjectType") or "") == "Unknown"]
    out.append(Finding(
        "IAM-003", DOMAIN, "Orphaned role assignments (deleted identities)", "medium",
        "fail" if orphans else "pass",
        f"{len(orphans)} role assignments point to identities that no longer exist." if orphans else
        "No orphaned role assignments found.",
        details="Orphaned assignments clutter access reviews, count against the 4,000 assignments-per-subscription "
                "limit and can be confusing during incident response.",
        recommendation="Delete assignments whose principal is 'Identity not found' (Access control (IAM) > Role "
                       "assignments > filter Unknown) and automate the clean-up after identity deletion.",
        evidence=evidence(["Object ID", "Role", "Scope"], [[r.get("ObjectId"), _role(r), _scope_label(r)] for r in orphans]),
        references=[REF_ORPHAN], source="AzGovViz RoleAssignments", effort="low"))

    # IAM-004 owners per subscription (effective: at subscription scope + inherited)
    owners: Dict[str, set] = defaultdict(set)
    sub_names: Dict[str, str] = {}
    for r in rows:
        sid = r.get("SubscriptionId")
        scope = r.get("Scope") or ""
        if not sid or _role(r).lower() != "owner" or (r.get("AssignmentType") or "direct") != "direct":
            continue
        if scope == "thisScope Sub" or scope.startswith("inherited"):
            owners[sid].add((r.get("ObjectId"), r.get("ObjectType")))
            sub_names[sid] = r.get("SubscriptionName") or sid
    subs_all = {s["id"]: s.get("name") for s in (getattr(ctx, "extra", {}) or {}).get("subscriptions", [])}
    owner_rows = []
    too_many = single = 0
    for sid in sorted(set(owners) | set(subs_all)):
        principals = owners.get(sid, set())
        users = sum(1 for _, t in principals if (t or "").startswith("User"))
        groups = sum(1 for _, t in principals if t == "Group")
        sps = sum(1 for _, t in principals if (t or "").startswith("SP"))
        n = len(principals)
        if n > 3:
            too_many += 1
        if n == 1:
            single += 1
        owner_rows.append([sub_names.get(sid) or subs_all.get(sid) or sid, n, users, groups, sps])
    status = "fail" if too_many else ("warn" if single else "pass")
    out.append(Finding(
        "IAM-004", DOMAIN, "Number of Owners per subscription", "medium", status,
        (f"{too_many} of {len(owner_rows)} subscriptions have more than 3 Owner principals (direct + inherited)"
         + (f"; {single} have a single Owner" if single else "") + ".") if owner_rows else "No Owner data.",
        details="Microsoft recommends at most three Owners per subscription (and more than one to avoid lock-out). "
                "Every additional Owner widens the blast radius of a compromised account.",
        recommendation="Keep 2-3 Owners per subscription, preferably a PIM-eligible group; move day-to-day "
                       "administrators to Contributor or narrower custom roles.",
        evidence=evidence(["Subscription", "Owner principals", "Users", "Groups", "Service principals"],
                          sorted(owner_rows, key=lambda r: -r[1])),
        references=[REF_RBAC], source="AzGovViz RoleAssignments", effort="low",
        metric={"subscriptionsOverLimit": too_many}))

    # IAM-005 direct user assignments vs groups
    scoped = [r for r in uniq.values() if r.get("ScopeTenOrMgOrSubOrRGOrRes") in ("Ten", "Mg", "Sub", "RG")]
    users = [r for r in scoped if (r.get("ObjectType") or "").startswith("User")]
    groups = [r for r in scoped if r.get("ObjectType") == "Group"]
    share = round(100 * len(users) / len(scoped), 1) if scoped else 0
    status = "pass" if share <= 25 or len(users) <= 3 else ("warn" if share <= 50 else "fail")
    out.append(Finding(
        "IAM-005", DOMAIN, "Access granted to individual users instead of groups", "medium", status,
        f"{len(users)} of {len(scoped)} role assignments ({share}%) target individual users; {len(groups)} target groups.",
        details="User-by-user assignments do not scale, are hard to review and survive role changes. "
                "Group-based access aligns permissions with team membership and enables PIM for groups.",
        recommendation="Create Entra ID groups per role and scope (e.g. 'sub-prod-contributors'), assign roles to "
                       "the groups and remove direct user assignments.",
        evidence=evidence(["User", "Role", "Scope"], [[_principal(r), _role(r), _scope_label(r)] for r in users]),
        references=[REF_RBAC, REF_ALZ_IAM], source="AzGovViz RoleAssignments", effort="medium"))

    # IAM-006 elevated access at root scope '/'
    root_rows = [r for r in uniq.values() if r.get("ScopeTenOrMgOrSubOrRGOrRes") == "Ten"]
    root_priv = [r for r in root_rows if _role(r).lower() in PRIVILEGED_ROLE_NAMES | {"contributor"}]
    out.append(Finding(
        "IAM-006", DOMAIN, "Standing access at the root scope '/' (elevated access)", "high",
        "fail" if root_priv else "pass",
        f"{len(root_priv)} assignments at root scope '/' (e.g. elevated Global Administrator access) remain active."
        if root_priv else "No standing role assignments at root scope '/'.",
        details="'Elevate access' grants User Access Administrator over every subscription and management group. "
                "It is meant for break-glass use and should be removed immediately afterwards.",
        recommendation="Remove root-scope assignments (Entra ID > Properties > 'Access management for Azure "
                       "resources' = No) and alert on 'elevateAccess' events in the Entra ID audit log.",
        evidence=evidence(["Principal", "Type", "Role"], [[_principal(r), r.get("ObjectType"), _role(r)] for r in root_rows]),
        references=[REF_ELEVATE], source="AzGovViz RoleAssignments", effort="low"))

    # IAM-007 privileged assignments at management-group scope held by individuals / SPs
    mg_priv = [r for r in uniq.values() if r.get("ScopeTenOrMgOrSubOrRGOrRes") == "Mg"
               and _role(r).lower() in PRIVILEGED_ROLE_NAMES and r.get("ObjectType") != "Group"
               and (r.get("RbacRelatedPolicyAssignmentClear") or "none") == "none"]
    mg_principals = {r.get("ObjectId") for r in mg_priv}
    out.append(Finding(
        "IAM-007", DOMAIN, "Owner-level rights granted to individuals at management-group scope", "high",
        "fail" if len(mg_priv) > 2 else ("warn" if mg_priv else "pass"),
        f"{len(mg_priv)} Owner/User Access Administrator assignments at management-group scope are held by "
        f"{len(mg_principals)} individual users or service principals (not groups)." if mg_priv else
        "Management-group Owner-level rights are only granted through groups (or not at all).",
        details="Management-group assignments inherit to every child subscription. Individual standing Owners at this "
                "level are the highest-value target in the estate.",
        recommendation="Grant management-group Owner only through a small, PIM-eligible platform-admin group; keep "
                       "break-glass accounts excluded from Conditional Access only as documented.",
        evidence=evidence(["Principal", "Type", "Role", "Scope"],
                          [[_principal(r), r.get("ObjectType"), _role(r), _scope_label(r)] for r in mg_priv]),
        references=[REF_ALZ_IAM, REF_PIM], source="AzGovViz RoleAssignments", effort="medium"))

    # IAM-008 PIM usage for privileged roles
    priv = [r for r in uniq.values() if _role(r).lower() in PRIVILEGED_ROLE_NAMES]
    priv_users = [r for r in priv if (r.get("ObjectType") or "").startswith("User")]
    priv_groups = [r for r in priv if (r.get("ObjectType") or "").startswith("Group")]
    pim_rows = [r for r in rows if (r.get("RoleAssignmentPIMRelated") or "").lower() == "true"
                or (r.get("RoleAssignmentPIMAssignmentType") or "") in ("Eligible", "Activated")]

    def _standing(rs: List[Dict[str, str]]) -> List[Dict[str, str]]:
        return [r for r in rs if (r.get("RoleAssignmentPIMRelated") or "").lower() != "true"]

    permanent, permanent_groups = _standing(priv_users), _standing(priv_groups)
    if pim_rows:
        status = "warn" if permanent else "pass"
        summary = (f"PIM is in use ({len({r.get('RoleAssignmentId') for r in pim_rows})} PIM-managed assignments)"
                   + (f" but {len(permanent)} privileged user assignments are still permanent." if permanent
                      else " and no privileged user assignment is permanent."))
    elif permanent:
        status = "fail"
        summary = (f"No PIM-managed Azure role assignments detected; {len(permanent)} privileged user assignments "
                   "are permanent (standing access).")
    elif permanent_groups:
        # PIM for Groups (eligible membership) is invisible here, so this is a prompt to verify, not a failure
        status = "warn"
        summary = (f"No PIM-managed Azure role assignments detected; Owner-level rights are granted to "
                   f"{len(permanent_groups)} group assignment(s) - confirm group membership is PIM-eligible (PIM for Groups).")
    else:
        status = "pass"
        summary = "No standing Owner or User Access Administrator assignments to users or groups were found."
    out.append(Finding(
        "IAM-008", DOMAIN, "Just-in-time access with Privileged Identity Management", "high", status, summary,
        details="Standing Owner/User Access Administrator rights are exploitable 24x7. PIM makes privileged roles "
                "eligible, time-bound, approved and audited. (PIM requires Microsoft Entra ID P2 / Governance.)",
        recommendation="Convert permanent privileged assignments to PIM-eligible assignments (prefer PIM for "
                       "groups), require MFA + justification on activation, and run quarterly access reviews.",
        evidence=evidence(["Principal", "Role", "Scope", "PIM"],
                          [[_principal(r), _role(r), _scope_label(r), r.get("RoleAssignmentPIMRelated")]
                           for r in priv_users + priv_groups]),
        references=[REF_PIM, REF_ALZ_IAM], source="AzGovViz RoleAssignments", effort="medium",
        alz=[ALZ["pim"]]))

    # IAM-009 custom roles
    roles = ctx.t("RoleDefinitions")
    custom = [r for r in roles if (r.get("Type") or "").lower() == "custom"]
    wildcard = [r for r in custom if "*" in [a.strip() for a in (r.get("Actions") or "").replace(";", ",").split(",")]]
    rbac_writers = [r for r in custom if (r.get("RoleAssWriteCapable") or "").lower() == "true" and r not in wildcard]
    owner_like = {r.get("RoleId") for r in rows if (r.get("RoleSecurityCustomRoleOwner") or "0") == "1"}
    if roles:
        status = "fail" if wildcard else ("warn" if rbac_writers else "pass")
        out.append(Finding(
            "IAM-009", DOMAIN, "Custom roles with wildcard or role-assignment permissions", "high", status,
            (f"{len(custom)} custom roles; {len(wildcard)} grant '*' (Owner-equivalent), {len(rbac_writers)} can write "
             "role assignments.") if custom else "No custom roles defined.",
            details="A custom role with '*' actions is an unreviewed Owner. Roles that can write role assignments can "
                    "escalate their own privileges.",
            recommendation="Replace wildcard actions with explicit operations, add NotActions for "
                           "Microsoft.Authorization/*/write where escalation is not intended, and limit assignable scopes.",
            evidence=evidence(["Role", "Assignments", "Assignable scopes", "Issue"],
                              [[r.get("Name"), r.get("AssignmentsCount"), r.get("AssignableScopesCount"),
                                "'*' actions" if r in wildcard else "roleAssignments/write"] for r in wildcard + rbac_writers]),
            references=[REF_CUSTOM], source="AzGovViz RoleDefinitions", effort="medium",
            metric={"ownerEquivalentAssigned": len(owner_like)}))

    # IAM-010 classic administrators
    if ctx.azgv:
        classic = ctx.t("ClassicAdministrators")
        co = [r for r in classic if "coadministrator" in (r.get("Role") or "").lower()]
        out.append(Finding(
            "IAM-010", DOMAIN, "Classic subscription administrators", "low",
            "warn" if co else "pass",
            f"{len(co)} co-administrators remain on {len({r.get('SubscriptionId') for r in co})} subscriptions." if co else
            "No classic co-administrators found.",
            details="Classic administrator roles were retired on 31 August 2024; leftover entries signal unmanaged "
                    "legacy access and should be converted to Azure RBAC.",
            recommendation="Remove co-administrators and grant equivalent Azure RBAC roles (prefer groups + PIM).",
            evidence=evidence(["Subscription", "Identity", "Role"], [[r.get("Subscription"), r.get("Identity"), r.get("Role")] for r in classic]),
            references=[REF_CLASSIC], source="AzGovViz ClassicAdministrators", effort="low"))

    # IAM-011 policy identities with Owner
    pol_owner = [r for r in uniq.values() if (r.get("RbacRelatedPolicyAssignmentClear") or "none") != "none"
                 and _role(r).lower() == "owner"]
    if any((r.get("RbacRelatedPolicyAssignmentClear") or "none") != "none" for r in uniq.values()):
        out.append(Finding(
            "IAM-011", DOMAIN, "Policy remediation identities with Owner", "medium",
            "warn" if pol_owner else "pass",
            f"{len(pol_owner)} policy-assignment managed identities hold Owner." if pol_owner else
            "Policy-assignment managed identities use least-privilege roles.",
            details="DeployIfNotExists/Modify assignments need only the roles listed in the policy definition "
                    "(roleDefinitionIds). Owner on a policy identity is unnecessary privilege.",
            recommendation="Re-create the assignment identities with the minimum roles from the policy definitions.",
            evidence=evidence(["Identity", "Policy assignment", "Scope"],
                              [[_principal(r), r.get("RbacRelatedPolicyAssignmentClear"), _scope_label(r)] for r in pol_owner]),
            references=[REF_RBAC], source="AzGovViz RoleAssignments", effort="low"))

    # IAM-012 executing identity least privilege (from AzGovViz console log)
    log_path = ctx.azgv.dir / "azgovviz-console.log" if ctx.azgv else None
    if log_path and log_path.exists():
        text = log_path.read_text(encoding="utf-8", errors="replace")
        if "LEAST PRIVILEGE ADVICE" in text:
            lines = [l.strip(" -!") for l in text.split("LEAST PRIVILEGE ADVICE", 1)[1].splitlines()[1:12]
                     if l.strip().startswith("- ")]
            out.append(Finding(
                "IAM-012", DOMAIN, "Assessment identity has more than Reader", "low", "warn",
                "The identity used for this assessment holds " + (", ".join(lines) or "non-Reader roles") +
                " at the assessed management group.",
                details="Governance tooling only needs Reader. Running it with Owner means a leaked token or a "
                        "compromised workstation could change the whole estate.",
                recommendation="Run scheduled assessments with a dedicated service principal or managed identity that "
                               "has Reader (plus the documented Graph permissions) only.",
                references=[ref("AzGovViz setup guide",
                                "https://github.com/Azure/Azure-Governance-Visualizer/blob/master/setup.md")],
                source="AzGovViz console log", effort="low"))

    # IAM-013 role-assignment volume / sprawl (resource-level assignments)
    kinds = Counter(r.get("ScopeTenOrMgOrSubOrRGOrRes") for r in uniq.values())
    res_level = kinds.get("Res", 0)
    out.append(Finding(
        "IAM-013", DOMAIN, "Role assignment sprawl at resource scope", "low",
        "warn" if total and res_level / total > 0.3 and res_level > 10 else "pass",
        f"{total} unique role assignments: " + ", ".join(f"{k or '?'} {v}" for k, v in sorted(kinds.items())) + ".",
        details="Assignments on individual resources are hard to audit and usually indicate missing role design "
                "at resource-group or subscription level.",
        recommendation="Consolidate repetitive resource-level assignments into group-based assignments at the "
                       "resource group or landing-zone subscription.",
        evidence=evidence(["Scope type", "Assignments"], [[k or "?", v] for k, v in kinds.most_common()]),
        references=[REF_RBAC], source="AzGovViz RoleAssignments", effort="medium"))

    # IAM-014 redundant assignments: same principal + role already inherited from a parent scope
    inherited = set()
    for r in rows:
        if (r.get("AssignmentType") or "direct") != "direct" or not (r.get("Scope") or "").startswith("inherited"):
            continue
        pos = ("sub", r.get("SubscriptionId")) if r.get("SubscriptionId") else ("mg", r.get("MgId"))
        inherited.add((pos, r.get("ObjectId"), r.get("RoleId")))
    redundant = []
    for r in uniq.values():
        scope = r.get("Scope") or ""
        if scope == "thisScope MG":
            pos = ("mg", r.get("MgId"))
        elif scope == "thisScope Sub":
            pos = ("sub", r.get("SubscriptionId"))
        else:
            continue
        if (pos, r.get("ObjectId"), r.get("RoleId")) in inherited:
            redundant.append(r)
    out.append(Finding(
        "IAM-014", DOMAIN, "Redundant role assignments (already inherited)", "low",
        "warn" if redundant else "pass",
        f"{len(redundant)} assignments duplicate the same role for the same principal that is already inherited "
        f"from a parent scope ({len({r.get('ObjectId') for r in redundant})} principals)." if redundant else
        "No assignment duplicates an inherited one.",
        details="Duplicate assignments do not add access but make reviews noisy and keep access alive when the "
                "parent assignment is removed.",
        recommendation="Remove the child-scope duplicates and keep the single assignment at the intended scope.",
        evidence=evidence(["Principal", "Role", "Duplicated at"],
                          [[_principal(r), _role(r), _scope_label(r)] for r in redundant]),
        references=[REF_RBAC], source="AzGovViz RoleAssignments", effort="low"))
    return out
