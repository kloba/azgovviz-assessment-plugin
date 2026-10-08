"""Resource Graph / ARM inventory used by the report and by checklist applicability logic.

Every probe is independent and best-effort: a failing probe is recorded under ``errors`` and the
rest of the assessment continues (common causes: missing Reader on a scope, preview tables).
"""

from __future__ import annotations

import concurrent.futures as cf
from typing import Any, Dict, List, Optional

from . import util
from .arg import ArgError, ResourceGraphClient

QUERIES: Dict[str, str] = {
    "subscriptions": (
        "resourcecontainers | where type =~ 'microsoft.resources/subscriptions' "
        "| project subscriptionId, name, state=tostring(properties.state), "
        "quotaId=tostring(properties.subscriptionPolicies.quotaId), "
        "spendingLimit=tostring(properties.subscriptionPolicies.spendingLimit), "
        "mgChain=properties.managementGroupAncestorsChain, tags"),
    "managementGroups": (
        "resourcecontainers | where type =~ 'microsoft.management/managementgroups' "
        "| project id, name, displayName=tostring(properties.displayName), "
        "parent=tostring(properties.details.parent.name), chain=properties.details.managementGroupAncestorsChain"),
    "resourceGroups": (
        "resourcecontainers | where type =~ 'microsoft.resources/subscriptions/resourcegroups' "
        "| extend tagged = array_length(bag_keys(tags)) > 0 "
        "| summarize total=count(), tagged=countif(tagged == true) by subscriptionId"),
    "typeCounts": "resources | summarize n=count() by type=tolower(type) | order by n desc",
    "locationCounts": "resources | summarize n=count() by location=tolower(location) | order by n desc",
    "subscriptionCounts": "resources | summarize n=count() by subscriptionId",
    "subscriptionTypeCounts": "resources | summarize n=count() by subscriptionId, type=tolower(type)",
    "tagCoverage": (
        "resources | extend tagged = array_length(bag_keys(tags)) > 0 "
        "| summarize total=count(), tagged=countif(tagged == true) by type=tolower(type) | order by total desc"),
    "defenderPlans": (
        "securityresources | where type =~ 'microsoft.security/pricings' "
        "| project subscriptionId, plan=name, tier=tostring(properties.pricingTier), "
        "subPlan=tostring(properties.subPlan), deprecated=tobool(properties.deprecated)"),
    "secureScores": (
        "securityresources | where type =~ 'microsoft.security/securescores' and name == 'ascScore' "
        "| project subscriptionId, current=todouble(properties.score.current), "
        "max=todouble(properties.score.max), percentage=todouble(properties.score.percentage)"),
    "securityRecommendations": (
        "securityresources | where type =~ 'microsoft.security/assessments' "
        "| extend status=tostring(properties.status.code), severity=tostring(properties.metadata.severity), "
        "title=tostring(properties.displayName) "
        "| where status =~ 'Unhealthy' "
        "| summarize resources=count() by title, severity | order by resources desc"),
    "advisor": (
        "advisorresources | where type =~ 'microsoft.advisor/recommendations' "
        "| extend category=tostring(properties.category), impact=tostring(properties.impact), "
        "problem=tostring(properties.shortDescription.problem), "
        "solution=tostring(properties.shortDescription.solution), "
        "impactedType=tostring(properties.impactedField) "
        "| summarize resources=count() by category, impact, problem, solution, impactedType "
        "| order by resources desc"),
    # one row: a resource counts as non-compliant if any of its policy states is NonCompliant
    "policyStates": (
        "policyresources | where type =~ 'microsoft.policyinsights/policystates' "
        "| extend rid=tolower(tostring(properties.resourceId)), st=tostring(properties.complianceState) "
        "| summarize nc=countif(st =~ 'NonCompliant'), c=countif(st =~ 'Compliant'), n=count() by rid "
        "| summarize evaluations=sum(n), resources=count(), nonCompliant=countif(nc > 0), "
        "compliant=countif(nc == 0 and c > 0)"),
    "keyVaults": (
        "resources | where type =~ 'microsoft.keyvault/vaults' "
        "| project id, name, subscriptionId, resourceGroup, location, "
        "softDelete=tobool(properties.enableSoftDelete), purgeProtection=tobool(properties.enablePurgeProtection), "
        "rbac=tobool(properties.enableRbacAuthorization), publicNetworkAccess=tostring(properties.publicNetworkAccess), "
        "defaultAction=tostring(properties.networkAcls.defaultAction)"),
    "storageAccounts": (
        "resources | where type =~ 'microsoft.storage/storageaccounts' "
        "| project id, name, subscriptionId, resourceGroup, location, kind, replication=tostring(sku.name), "
        "httpsOnly=tobool(properties.supportsHttpsTrafficOnly), minTls=tostring(properties.minimumTlsVersion), "
        "allowBlobPublicAccess=tobool(properties.allowBlobPublicAccess), "
        "publicNetworkAccess=tostring(properties.publicNetworkAccess), "
        "sharedKey=tobool(properties.allowSharedKeyAccess), "
        "defaultAction=tostring(properties.networkAcls.defaultAction)"),
    "logAnalytics": (
        "resources | where type =~ 'microsoft.operationalinsights/workspaces' "
        "| project id, name, subscriptionId, location, retentionDays=toint(properties.retentionInDays), "
        "sku=tostring(properties.sku.name)"),
    "activityLogAlerts": (
        "resources | where type =~ 'microsoft.insights/activitylogalerts' "
        "| extend cond=tostring(properties.condition), enabled=tobool(properties.enabled) "
        "| summarize total=count(), serviceHealth=countif(cond contains 'ServiceHealth' and enabled), "
        "resourceHealth=countif(cond contains 'ResourceHealth' and enabled) by subscriptionId"),
    "publicIps": (
        "resources | where type =~ 'microsoft.network/publicipaddresses' "
        "| project id, name, subscriptionId, location, sku=tostring(sku.name), "
        "attached=isnotempty(properties.ipConfiguration) or isnotempty(properties.natGateway), "
        "ddos=tostring(properties.ddosSettings.protectionMode)"),
    "unattachedDisks": (
        "resources | where type =~ 'microsoft.compute/disks' and properties.diskState =~ 'Unattached' "
        "| project id, name, subscriptionId, location, sku=tostring(sku.name), sizeGb=toint(properties.diskSizeGB)"),
    # every inbound Allow rule from the internet; port ranges ("3389-3390", "0-65535") are matched in the analyzer
    "nsgOpenInbound": (
        "resources | where type =~ 'microsoft.network/networksecuritygroups' "
        "| mv-expand rule = properties.securityRules "
        "| extend access=tostring(rule.properties.access), direction=tostring(rule.properties.direction), "
        "src=tostring(rule.properties.sourceAddressPrefix), srcs=tostring(rule.properties.sourceAddressPrefixes), "
        "port=tostring(rule.properties.destinationPortRange), ports=tostring(rule.properties.destinationPortRanges) "
        "| where access =~ 'Allow' and direction =~ 'Inbound' "
        "| where src in~ ('*', '0.0.0.0/0', 'Internet', 'Any') or (isnotempty(srcs) and srcs != '[]') "
        "| where port in ('*', '22', '3389') or port contains '-' or ports contains '22' or ports contains '3389' "
        "or ports contains '-' or ports contains '*' "
        "| project id, nsg=name, subscriptionId, rule=tostring(rule.name), port=iff(isempty(port), ports, port), "
        "src=iff(isempty(src), srcs, src)"),
    "vms": (
        "resources | where type =~ 'microsoft.compute/virtualmachines' "
        "| project id, name, subscriptionId, location, size=tostring(properties.hardwareProfile.vmSize), "
        "zones=tostring(zones), availabilitySet=tostring(properties.availabilitySet.id), "
        "os=tostring(properties.storageProfile.osDisk.osType), "
        "power=tostring(properties.extended.instanceView.powerState.code)"),
    "backupProtected": (
        "recoveryservicesresources | where type =~ 'microsoft.recoveryservices/vaults/backupfabrics/protectioncontainers/protecteditems' "
        "| extend src=tolower(tostring(properties.sourceResourceId)) | summarize by src"),
}

ARM_PROBES = {
    "hierarchySettings": "/providers/Microsoft.Management/managementGroups/{root}/settings/default",
}


def collect(client: ResourceGraphClient, tenant_id: Optional[str], subscription_ids: List[str],
            workers: int = 4, per_subscription_cap: int = 200) -> Dict[str, Any]:
    started = util.utcnow()
    data: Dict[str, Any] = {"schema": "azgov-assess/inventory@1", "generatedAt": util.iso(started),
                            "scope": client.scope.describe(), "errors": {}}

    def probe(name: str, kql: str) -> None:
        try:
            res = client.query(kql, max_rows=10000)
            data[name] = res.rows
            if res.truncated:
                data.setdefault("truncated", []).append(name)
        except Exception as exc:  # one failed probe must not abort the inventory
            data["errors"][name] = str(exc) if isinstance(exc, ArgError) else f"{type(exc).__name__}: {exc}"
            data[name] = None

    with cf.ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(lambda kv: probe(*kv), QUERIES.items()))

    # ARM probes (hierarchy settings + per-subscription budgets / activity-log diagnostic settings)
    if tenant_id:
        try:
            data["hierarchySettings"] = client.arm_get(
                ARM_PROBES["hierarchySettings"].format(root=tenant_id), "2021-04-01").get("properties") or {}
        except ArgError as exc:
            if exc.status == 404:  # never configured: the defaults apply
                data["hierarchySettings"] = {}
            else:  # unknown (e.g. no read permission at the root) - analyzers must not assume defaults
                data["hierarchySettings"] = None
                data["errors"]["hierarchySettings"] = str(exc)
        except Exception as exc:
            data["hierarchySettings"] = None
            data["errors"]["hierarchySettings"] = f"{type(exc).__name__}: {exc}"

    subs = subscription_ids or [s["subscriptionId"] for s in (data.get("subscriptions") or [])]
    subs = subs[:per_subscription_cap]

    def per_sub(sub: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {"subscriptionId": sub}
        for key, path, ver in (
                ("budgets", f"/subscriptions/{sub}/providers/Microsoft.Consumption/budgets", "2023-05-01"),
                ("activityLogDiagnostics", f"/subscriptions/{sub}/providers/Microsoft.Insights/diagnosticSettings",
                 "2021-05-01-preview"),
                ("securityContacts", f"/subscriptions/{sub}/providers/Microsoft.Security/securityContacts",
                 "2023-12-01-preview")):
            try:
                value = client.arm_get(path, ver).get("value", [])
                out[key] = [_slim_arm(key, v) for v in value]
            except Exception as exc:
                out[key] = None
                out.setdefault("errors", {})[key] = (str(exc) if isinstance(exc, ArgError)
                                                     else f"{type(exc).__name__}: {exc}")[:300]
        return out

    with cf.ThreadPoolExecutor(max_workers=workers) as pool:
        data["perSubscription"] = list(pool.map(per_sub, subs))

    data["typeCountMap"] = type_count_map(data)
    data["durationSec"] = round((util.utcnow() - started).total_seconds(), 1)
    return data


def _slim_arm(kind: str, value: Dict[str, Any]) -> Dict[str, Any]:
    props = value.get("properties") or {}
    if kind == "budgets":
        return {"name": value.get("name"), "amount": props.get("amount"), "timeGrain": props.get("timeGrain"),
                "notifications": len(props.get("notifications") or {}),
                "currentSpend": (props.get("currentSpend") or {}).get("amount")}
    if kind == "activityLogDiagnostics":
        return {"name": value.get("name"), "workspace": props.get("workspaceId"),
                "storage": props.get("storageAccountId"), "eventHub": props.get("eventHubAuthorizationRuleId"),
                "categories": [l.get("category") for l in props.get("logs") or [] if l.get("enabled")]}
    if kind == "securityContacts":
        return {"name": value.get("name"), "emails": props.get("emails") or props.get("email"),
                "isEnabled": props.get("isEnabled"),
                "notificationsByRole": (props.get("notificationsByRole") or {}).get("state"),
                "alertNotifications": (props.get("alertNotifications") or {}).get("state")
                if isinstance(props.get("alertNotifications"), dict) else props.get("alertNotifications")}
    return value


def type_count_map(data: Dict[str, Any]) -> Optional[Dict[str, int]]:
    rows = data.get("typeCounts")
    if rows is None:
        return None
    counts = {r["type"]: int(r["n"]) for r in rows}
    counts["microsoft.resources/subscriptions"] = len(data.get("subscriptions") or [])
    counts["microsoft.resources/subscriptions/resourcegroups"] = sum(
        int(r.get("total") or 0) for r in (data.get("resourceGroups") or []))
    return counts


def load_type_counts(inventory: Optional[Dict[str, Any]]) -> Optional[Dict[str, int]]:
    if not inventory:
        return None
    return inventory.get("typeCountMap") or type_count_map(inventory)

