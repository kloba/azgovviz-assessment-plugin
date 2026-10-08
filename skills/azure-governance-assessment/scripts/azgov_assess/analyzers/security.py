"""Security findings: Defender for Cloud coverage and posture, data-store exposure (Resource Graph + AzGovViz)."""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List

from .. import util
from ..analysis import Finding, analyzer, evidence
from .common import ALZ, DEFENDER_PLAN_LABELS, DEFENDER_PLAN_TYPES, ref, short_id

DOMAIN = "security"
REF_MDC = ref("Defender for Cloud plans", "/azure/defender-for-cloud/defender-for-cloud-introduction")
REF_CSPM = ref("Defender CSPM", "/azure/defender-for-cloud/concept-cloud-security-posture-management")
REF_CONTACTS = ref("Configure email notifications for alerts", "/azure/defender-for-cloud/configure-email-notifications")
REF_SCORE = ref("Secure score", "/azure/defender-for-cloud/secure-score-security-controls")
REF_BLOB = ref("Prevent anonymous read access to blobs", "/azure/storage/blobs/anonymous-read-access-prevent")
REF_TLS = ref("Enforce a minimum TLS version for storage", "/azure/storage/common/transport-layer-security-configure-minimum-version")
REF_KV = ref("Key Vault soft-delete and purge protection", "/azure/key-vault/general/soft-delete-overview")
REF_KV_RBAC = ref("Key Vault Azure RBAC permission model", "/azure/key-vault/general/rbac-guide")
REF_NET = ref("Configure Azure Storage firewalls and virtual networks", "/azure/storage/common/storage-network-security")


def _plans(ctx) -> Dict[str, Dict[str, str]]:
    """subscriptionId -> plan -> tier (Resource Graph first, AzGovViz MDfCCoverage as fallback)."""
    out: Dict[str, Dict[str, str]] = defaultdict(dict)
    for p in ctx.inv("defenderPlans") or []:
        if not p.get("deprecated"):
            out[p["subscriptionId"]][p["plan"]] = p.get("tier") or ""
    if not out:
        for p in ctx.t("MDfCCoverage"):
            if p.get("subscriptionId") and p.get("plan"):
                out[p["subscriptionId"]][p["plan"]] = p.get("pricingTier") or ""
    return out


def _sub_types(ctx) -> Dict[str, set]:
    """subscriptionId -> resource types present (Resource Graph, AzGovViz ResourcesAll as fallback)."""
    out: Dict[str, set] = defaultdict(set)
    for r in ctx.inv("subscriptionTypeCounts") or []:
        out[r.get("subscriptionId")].add((r.get("type") or "").lower())
    if not out:
        for r in ctx.t("ResourcesAll"):
            out[r.get("subscriptionId")].add((r.get("type") or "").lower())
    return out


@analyzer
def security_findings(ctx) -> List[Finding]:
    out: List[Finding] = []
    subs = {s["id"]: s.get("name") or s["id"] for s in (getattr(ctx, "extra", {}) or {}).get("subscriptions", [])}
    plans = _plans(ctx)
    sub_types = _sub_types(ctx)

    if plans:
        def on(sid: str, plan: str) -> bool:
            return (plans.get(sid, {}).get(plan) or "").lower() == "standard"

        # SEC-001 CSPM
        cspm = [s for s in subs if on(s, "CloudPosture")]
        out.append(Finding(
            "SEC-001", DOMAIN, "Defender Cloud Security Posture Management (CSPM)", "high",
            "pass" if subs and len(cspm) == len(subs) else ("warn" if cspm else "fail"),
            f"Defender CSPM is enabled on {len(cspm)} of {len(subs)} subscriptions.",
            details="Foundational CSPM only gives the secure score. Defender CSPM adds attack-path analysis, the "
                    "cloud security explorer, agentless scanning and governance rules.",
            recommendation="Enable Defender CSPM on all subscriptions (assign the Defender for Cloud plan policies at "
                           "the intermediate-root management group).",
            evidence=evidence(["Subscription", "Defender CSPM"], [[subs.get(s, s), "on" if on(s, "CloudPosture") else "off"] for s in subs]),
            references=[REF_CSPM], source="Resource Graph securityresources", effort="low", alz=[ALZ["defender_cspm"]]))

        # SEC-002 Servers on subscriptions that have compute
        compute = set(DEFENDER_PLAN_TYPES["VirtualMachines"])
        relevant = [s for s in subs if sub_types.get(s, set()) & compute]
        if relevant:
            covered = [s for s in relevant if on(s, "VirtualMachines")]
            out.append(Finding(
                "SEC-002", DOMAIN, "Defender for Servers on subscriptions with machines", "high",
                "pass" if len(covered) == len(relevant) else ("warn" if covered else "fail"),
                f"Defender for Servers is on for {len(covered)} of {len(relevant)} subscriptions that host VMs, "
                "scale sets or Arc machines.",
                details="Defender for Servers provides EDR (Defender for Endpoint), vulnerability assessment, "
                        "just-in-time VM access and file integrity monitoring.",
                recommendation="Enable Defender for Servers Plan 2 (or Plan 1 at minimum) wherever machines run.",
                evidence=evidence(["Subscription", "Defender for Servers"],
                                  [[subs.get(s, s), (plans.get(s, {}).get("VirtualMachines") or "?")] for s in relevant]),
                references=[REF_MDC], source="Resource Graph securityresources", effort="low",
                alz=[ALZ["defender_servers"]]))

        # SEC-003 workload plan coverage where the workload exists
        rows, gaps = [], 0
        for plan, types in DEFENDER_PLAN_TYPES.items():
            if plan == "VirtualMachines":
                continue
            relevant = [s for s in subs if sub_types.get(s, set()) & set(types)]
            if not relevant:
                continue
            off = [s for s in relevant if not on(s, plan)]
            gaps += len(off)
            rows.append([DEFENDER_PLAN_LABELS.get(plan, plan), len(relevant), len(relevant) - len(off),
                         ", ".join(subs.get(s, s) for s in off[:4])])
        if rows:
            total = sum(r[1] for r in rows)
            out.append(Finding(
                "SEC-003", DOMAIN, "Defender workload protection for deployed services", "high",
                "pass" if not gaps else ("warn" if gaps < total else "fail"),
                f"{total - gaps} of {total} relevant plan/subscription combinations are protected "
                f"({gaps} gaps across {len([r for r in rows if r[1] != r[2]])} plans).",
                details="Workload plans detect threats specific to storage (malware upload, anomalous access), Key "
                        "Vault, SQL, containers, App Service and Resource Manager operations.",
                recommendation="Enable the Defender plans that match deployed services; Resource Manager and Key Vault "
                               "plans are low-cost and protect the control plane.",
                evidence=evidence(["Plan", "Subscriptions with workload", "Protected", "Unprotected (sample)"], rows),
                references=[REF_MDC], source="Resource Graph securityresources", effort="low",
                alz=[ALZ["defender_cwp"]]))
        arm_on = [s for s in subs if on(s, "Arm")]
        out.append(Finding(
            "SEC-004", DOMAIN, "Defender for Resource Manager (control-plane threat detection)", "medium",
            "pass" if subs and len(arm_on) == len(subs) else ("warn" if arm_on else "fail"),
            f"Defender for Resource Manager is on for {len(arm_on)} of {len(subs)} subscriptions.",
            details="Detects suspicious management operations (e.g. mass deletion, unusual role assignment, operations "
                    "from malicious IPs) across every resource in the subscription.",
            recommendation="Enable Defender for Resource Manager on every subscription.",
            references=[REF_MDC], source="Resource Graph securityresources", effort="low"))

    # SEC-005 security contacts / notifications
    per = ctx.inv("perSubscription") or []
    contacts_known = [p for p in per if p.get("securityContacts") is not None]
    if contacts_known:
        ok = [p for p in contacts_known if any((c.get("emails") or "") and
                                                 (str(c.get("alertNotifications") or "").lower() in ("on", "true")
                                                  or c.get("isEnabled")) for c in p["securityContacts"])]
        out.append(Finding(
            "SEC-005", DOMAIN, "Security alert contacts and notifications", "medium",
            "pass" if len(ok) == len(contacts_known) else ("warn" if ok else "fail"),
            f"{len(ok)} of {len(contacts_known)} subscriptions send Defender for Cloud alerts to a security contact.",
            details="High-severity alerts are only useful if someone receives them; by default only subscription "
                    "owners may be notified.",
            recommendation="Configure a security operations distribution list as security contact with alert "
                           "notifications on (minimum severity: Medium) on every subscription - via policy at scale.",
            evidence=evidence(["Subscription", "Contact configured"],
                              [[subs.get(p["subscriptionId"], p["subscriptionId"]), "yes" if p in ok else "no"] for p in contacts_known]),
            references=[REF_CONTACTS], source="ARM securityContacts", effort="low"))
    elif ctx.has("MDfCEmailNotifications"):
        rows = ctx.t("MDfCEmailNotifications")
        ok = [r for r in rows if (r.get("emails") or "none") not in ("none", "n/a", "")]
        out.append(Finding(
            "SEC-005", DOMAIN, "Security alert contacts and notifications", "medium",
            "pass" if len(ok) == len(rows) else ("warn" if ok else "fail"),
            f"{len(ok)} of {len(rows)} subscriptions have a Defender for Cloud email contact.",
            recommendation="Configure security contacts with alert notifications on every subscription.",
            evidence=evidence(["Subscription", "Emails", "Alert state"],
                              [[r.get("subscriptionName"), r.get("emails"), r.get("alertNotificationsState")] for r in rows]),
            references=[REF_CONTACTS], source="AzGovViz MDfCEmailNotifications", effort="low"))

    # SEC-006 secure score
    scores = [s for s in ctx.inv("secureScores") or [] if s.get("percentage") is not None]
    if scores:
        avg = round(100 * sum(float(s["percentage"]) for s in scores) / len(scores), 1)
        out.append(Finding(
            "SEC-006", DOMAIN, "Defender for Cloud secure score", "medium",
            "pass" if avg >= 75 else ("warn" if avg >= 50 else "fail"),
            f"Average secure score {avg}% across {len(scores)} subscriptions "
            f"(lowest {round(100 * min(float(s['percentage']) for s in scores), 1)}%).",
            details="The secure score aggregates the Microsoft cloud security benchmark recommendations; each point "
                    "represents a closed attack surface.",
            recommendation="Work the recommendations with the highest score impact first; assign owners and due dates "
                           "with Defender for Cloud governance rules.",
            evidence=evidence(["Subscription", "Score %", "Points"],
                              [[subs.get(s["subscriptionId"], s["subscriptionId"]), round(100 * float(s["percentage"]), 1),
                                f"{s.get('current')} / {s.get('max')}"] for s in scores]),
            references=[REF_SCORE], source="Resource Graph securityresources", effort="medium",
            metric={"averagePct": avg}))

    # SEC-007 high-severity unhealthy recommendations
    recs = ctx.inv("securityRecommendations")
    if recs is not None:
        high = [r for r in recs if (r.get("severity") or "").lower() == "high"]
        n_high = sum(int(r.get("resources") or 0) for r in high)
        out.append(Finding(
            "SEC-007", DOMAIN, "Open high-severity Defender for Cloud recommendations", "high",
            "fail" if n_high > 10 else ("warn" if n_high else "pass"),
            f"{len(high)} high-severity recommendations are open on {n_high} resources "
            f"({len(recs)} recommendations open in total)." if recs else "No unhealthy Defender for Cloud assessments.",
            details="High-severity recommendations map to directly exploitable weaknesses (e.g. missing MFA for "
                    "owners, internet-exposed management ports, vulnerable software).",
            recommendation="Remediate high-severity recommendations first; use 'Fix' or policy-driven remediation and "
                           "track progress in the secure score.",
            evidence=evidence(["Recommendation", "Severity", "Unhealthy resources"],
                              [[r.get("title"), r.get("severity"), int(r.get("resources") or 0)] for r in recs[:25]]),
            references=[REF_SCORE], source="Resource Graph securityresources", effort="medium"))

    # SEC-008 public blob access
    sa = ctx.inv("storageAccounts") or []
    anon_rows = []
    for r in ctx.t("StorageAccountAccessAnalysis"):
        c = util.to_int(r.get("containersAnonymousContainerCount")) + util.to_int(r.get("containersAnonymousBlobCount"))
        if c:
            anon_rows.append([r.get("storageAccount"), r.get("SubscriptionName"), c, r.get("staticWebsitesState")])
    allowed = [s for s in sa if s.get("allowBlobPublicAccess") is True]
    if sa or anon_rows:
        status = "fail" if anon_rows else ("warn" if allowed else "pass")
        out.append(Finding(
            "SEC-008", DOMAIN, "Anonymous (public) blob access", "high" if anon_rows else "medium", status,
            (f"{len(anon_rows)} storage accounts expose containers anonymously; " if anon_rows else "")
            + f"{len(allowed)} of {len(sa)} storage accounts allow anonymous blob access to be enabled.",
            details="Anonymous containers are readable by anyone on the internet who guesses the URL - a frequent "
                    "cause of data leaks.",
            recommendation="Set 'Allow Blob anonymous access' to Disabled on every account (policy: 'Storage account "
                           "public access should be disallowed', Deny) and use SAS/Entra ID for sharing.",
            evidence=evidence(["Storage account", "Subscription", "Anonymous containers/blobs", "Static website"], anon_rows)
            if anon_rows else evidence(["Storage account", "Resource group"], [[s.get("name"), short_id(s.get("id"))] for s in allowed]),
            references=[REF_BLOB], source="Resource Graph / AzGovViz StorageAccountAccessAnalysis", effort="low"))

    # SEC-009 insecure transport
    if sa:
        weak = [s for s in sa if s.get("httpsOnly") is False or (s.get("minTls") or "TLS1_2") in ("TLS1_0", "TLS1_1")]
        out.append(Finding(
            "SEC-009", DOMAIN, "Storage accounts accepting HTTP or TLS < 1.2", "medium",
            "fail" if weak else "pass",
            f"{len(weak)} of {len(sa)} storage accounts allow HTTP or TLS 1.0/1.1." if weak else
            f"All {len(sa)} storage accounts require HTTPS with TLS 1.2+.",
            details="Legacy TLS versions are deprecated (Azure Storage retires TLS 1.0/1.1) and HTTP exposes data and "
                    "keys in transit.",
            recommendation="Set 'Secure transfer required' and minimum TLS 1.2 on all accounts and enforce with policy.",
            evidence=evidence(["Storage account", "HTTPS only", "Minimum TLS"],
                              [[s.get("name"), s.get("httpsOnly"), s.get("minTls")] for s in weak]),
            references=[REF_TLS], source="Resource Graph", effort="low",
            alz=[ALZ["storage_secure_transfer"]]))

    # SEC-010 network exposure of data stores (storage accounts and/or key vaults)
    kv = ctx.inv("keyVaults") or []
    if sa or kv:
        open_sa = [s for s in sa if (s.get("publicNetworkAccess") or "Enabled") != "Disabled"
                   and (s.get("defaultAction") or "Allow") == "Allow"]
        # a vault behind its firewall (networkAcls.defaultAction = Deny) is not reachable from all networks; older
        # inventories lack the column (None), which keeps the previous behaviour
        open_kv = [k for k in kv if (k.get("publicNetworkAccess") or "Enabled") != "Disabled"
                   and (k.get("defaultAction") or "Allow") == "Allow"]
        total = len(sa) + len(kv)
        exposed = len(open_sa) + len(open_kv)
        out.append(Finding(
            "SEC-010", DOMAIN, "Data stores reachable from all networks", "medium",
            "pass" if not exposed else ("warn" if exposed < total else "fail"),
            f"{len(open_sa)} of {len(sa)} storage accounts and {len(open_kv)} of {len(kv)} key vaults accept traffic "
            "from any network.",
            details="Public endpoints rely solely on identity controls. Private endpoints or firewall rules add a "
                    "network boundary and stop credential-stuffing and token replay from the internet.",
            recommendation="Use private endpoints (or at least firewall + trusted services) for storage and Key Vault; "
                           "set publicNetworkAccess to Disabled where possible.",
            evidence=evidence(["Resource", "Type", "Public network access"],
                              [[s.get("name"), "storage", f"{s.get('publicNetworkAccess')} / default {s.get('defaultAction')}"] for s in open_sa]
                              + [[k.get("name"), "key vault", k.get("publicNetworkAccess")] for k in open_kv]),
            references=[REF_NET], source="Resource Graph", effort="medium", alz=[ALZ["kv_private"]] if kv else []))

    # SEC-011 Key Vault recoverability + RBAC model
    kv = ctx.inv("keyVaults") or []
    if kv:
        no_purge = [k for k in kv if not k.get("purgeProtection")]
        out.append(Finding(
            "SEC-011", DOMAIN, "Key Vault purge protection", "medium",
            "pass" if not no_purge else "warn",
            f"{len(no_purge)} of {len(kv)} key vaults have purge protection disabled." if no_purge else
            f"All {len(kv)} key vaults have purge protection.",
            details="Without purge protection a malicious or accidental purge permanently destroys keys, secrets and "
                    "certificates - including keys used for encryption at rest.",
            recommendation="Enable purge protection (irreversible by design) on all production key vaults.",
            evidence=evidence(["Key vault", "Soft delete", "Purge protection"],
                              [[k.get("name"), k.get("softDelete"), k.get("purgeProtection")] for k in kv]),
            references=[REF_KV], source="Resource Graph", effort="low", alz=[ALZ["kv_purge"]]))
        legacy = [k for k in kv if not k.get("rbac")]
        out.append(Finding(
            "SEC-012", DOMAIN, "Key Vault permission model", "low",
            "pass" if not legacy else "warn",
            f"{len(legacy)} of {len(kv)} key vaults still use access policies instead of Azure RBAC." if legacy else
            "All key vaults use the Azure RBAC permission model.",
            details="Access policies cannot be governed with PIM, conditional role assignment or management-group "
                    "scoped reviews; Azure RBAC can.",
            recommendation="Migrate key vaults to the Azure RBAC permission model.",
            evidence=evidence(["Key vault"], [[k.get("name")] for k in legacy]),
            references=[REF_KV_RBAC], source="Resource Graph", effort="medium", alz=[ALZ["rbac_data_plane"]]))
    return out
