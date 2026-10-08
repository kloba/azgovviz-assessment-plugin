"""Management & monitoring findings: logging, alerting, locks, backup (Resource Graph / ARM + AzGovViz)."""

from __future__ import annotations

from typing import List

from ..analysis import Finding, analyzer, evidence
from .common import ALZ, ref, short_id

DOMAIN = "management"
REF_ACTIVITY = ref("Create diagnostic settings for the activity log",
                   "/azure/azure-monitor/essentials/activity-log?tabs=powershell#send-to-log-analytics-workspace")
REF_LA = ref("Design a Log Analytics workspace architecture", "/azure/azure-monitor/logs/workspace-design")
REF_SH = ref("Create Service Health alerts", "/azure/service-health/alerts-activity-log-service-notifications-portal")
REF_AMBA = ref("Azure Monitor Baseline Alerts (AMBA) for ALZ", "https://azure.github.io/azure-monitor-baseline-alerts/patterns/alz/")
REF_LOCKS = ref("Lock your resources", "/azure/azure-resource-manager/management/lock-resources")
REF_BACKUP = ref("Azure Backup overview", "/azure/backup/backup-overview")


@analyzer
def management_findings(ctx) -> List[Finding]:
    out: List[Finding] = []
    per = ctx.inv("perSubscription") or []

    # MGT-001 activity log export
    known = [p for p in per if p.get("activityLogDiagnostics") is not None]
    if known:
        ok = [p for p in known if p["activityLogDiagnostics"]]
        out.append(Finding(
            "MGT-001", DOMAIN, "Subscription activity logs exported", "medium",
            "pass" if len(ok) == len(known) else ("warn" if ok else "fail"),
            f"{len(ok)} of {len(known)} subscriptions export the activity log (diagnostic settings).",
            details="The activity log is the audit trail of every control-plane change. It is kept for only 90 days "
                    "and cannot be correlated with other signals unless exported.",
            recommendation="Send every subscription's activity log to the central Log Analytics workspace (policy: "
                           "'Configure Azure Activity logs to stream to specified Log Analytics workspace').",
            evidence=evidence(["Subscription", "Exported", "Destination"],
                              [[ctx.sub_name(p["subscriptionId"]), "yes" if p["activityLogDiagnostics"] else "no",
                                ", ".join(filter(None, [short_id(d.get("workspace") or "") or None for d in p["activityLogDiagnostics"]]))]
                               for p in known]),
            references=[REF_ACTIVITY], source="ARM diagnosticSettings", effort="low",
            alz=[ALZ["activity_log_export"]]))

    # MGT-002 central workspace
    ws = ctx.inv("logAnalytics")
    if ws is not None:
        n = len(ws)
        status = "fail" if n == 0 else ("pass" if n <= 2 else "warn")
        out.append(Finding(
            "MGT-002", DOMAIN, "Centralised Log Analytics", "medium", status,
            "No Log Analytics workspace exists." if n == 0 else
            f"{n} Log Analytics workspace(s) across {len({w.get('subscriptionId') for w in ws})} subscription(s).",
            details="A central workspace (one per region or sovereignty boundary) enables correlation, Sentinel and "
                    "consistent retention; many small workspaces fragment visibility and cost.",
            recommendation="Consolidate platform logs into a central workspace in the management subscription and use "
                           "resource-context RBAC for application teams.",
            evidence=evidence(["Workspace", "Subscription", "Region", "Retention (days)", "SKU"],
                              [[w.get("name"), ctx.sub_name(w.get("subscriptionId")), w.get("location"),
                                w.get("retentionDays"), w.get("sku")] for w in ws]),
            references=[REF_LA], source="Resource Graph", effort="medium", alz=[ALZ["single_workspace"]]))

    # MGT-003 service health alerts
    alerts = ctx.inv("activityLogAlerts")
    subs = (getattr(ctx, "extra", {}) or {}).get("subscriptions", [])
    if alerts is not None and subs:
        with_sh = {a["subscriptionId"] for a in alerts if int(a.get("serviceHealth") or 0) > 0}
        with_rh = {a["subscriptionId"] for a in alerts if int(a.get("resourceHealth") or 0) > 0}
        out.append(Finding(
            "MGT-003", DOMAIN, "Service Health and Resource Health alerts", "medium",
            "pass" if len(with_sh) == len(subs) else ("warn" if with_sh else "fail"),
            f"{len(with_sh)} of {len(subs)} subscriptions have Service Health alerts; {len(with_rh)} have Resource Health alerts.",
            details="Service Health alerts tell you about Azure incidents, planned maintenance and retirements "
                    "affecting your resources before users do.",
            recommendation="Deploy Service Health and Resource Health activity-log alerts with action groups on every "
                           "subscription (Azure Monitor Baseline Alerts for ALZ automates this).",
            evidence=evidence(["Subscription", "Service Health", "Resource Health"],
                              [[s.get("name"), "yes" if s["id"] in with_sh else "no", "yes" if s["id"] in with_rh else "no"] for s in subs]),
            references=[REF_SH, REF_AMBA], source="Resource Graph", effort="low",
            alz=[ALZ["service_health_alerts"], ALZ["health_events"]]))

    # MGT-004 resource locks
    if ctx.azgv:
        locks = ctx.t("ResourceLocks")
        out.append(Finding(
            "MGT-004", DOMAIN, "Resource locks on critical resources", "low",
            "pass" if locks else "warn",
            f"{len(locks)} resource locks ({sum(1 for l in locks if l.get('Lock') == 'CannotDelete')} CannotDelete)."
            if locks else "No resource locks found.",
            details="Locks prevent accidental deletion of shared platform resources (hub networks, DNS zones, Log "
                    "Analytics, Key Vaults) even by Owners.",
            recommendation="Apply CannotDelete locks to shared platform resource groups and protect them with policy.",
            evidence=evidence(["Scope", "Lock", "Resource", "Subscription"],
                              [[l.get("ScopeType"), l.get("Lock"), short_id(l.get("Id") or ""), l.get("SubscriptionName")] for l in locks]),
            references=[REF_LOCKS], source="AzGovViz ResourceLocks", effort="low", alz=[ALZ["locks"]]))

    # MGT-005 VM backup coverage
    vms = ctx.inv("vms")
    protected = ctx.inv("backupProtected")
    if vms and protected is not None:
        prot = {p.get("src") for p in protected}
        unprotected = [v for v in vms if (v.get("id") or "").lower() not in prot]
        out.append(Finding(
            "MGT-005", DOMAIN, "Backup coverage for virtual machines", "medium",
            "pass" if not unprotected else ("warn" if len(unprotected) < len(vms) else "fail"),
            f"{len(vms) - len(unprotected)} of {len(vms)} virtual machines are protected by Azure Backup.",
            details="Unprotected VMs cannot be restored after ransomware, corruption or accidental deletion.",
            recommendation="Protect stateful VMs with Azure Backup (enforce with 'Configure backup on virtual machines' "
                           "policy per region/tag) and test restores; stateless VMs should be rebuildable from IaC.",
            evidence=evidence(["VM", "Subscription", "Region", "Power state"],
                              [[v.get("name"), ctx.sub_name(v.get("subscriptionId")), v.get("location"), v.get("power")] for v in unprotected]),
            references=[REF_BACKUP], source="Resource Graph", effort="medium", alz=[ALZ["backup"]]))
    return out
