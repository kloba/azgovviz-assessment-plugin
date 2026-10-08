"""Builds a synthetic assessment run folder (no Azure access) to exercise analysis + report rendering.

Usage:  python3 tests/fake_run.py <output-dir>     -> prints the run folder path
"""

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "azure-governance-assessment" / "scripts"))

from azgov_assess import checklists as cl, inventory, util  # noqa: E402
from azgov_assess.arg import QueryResult, Scope  # noqa: E402

TENANT = "00000000-1111-2222-3333-444444444444"
SUBS = [("aaaaaaaa-0000-0000-0000-000000000001", "Contoso-Prod"),
        ("aaaaaaaa-0000-0000-0000-000000000002", "Contoso-Dev"),
        ("aaaaaaaa-0000-0000-0000-000000000003", "Contoso-Sandbox")]
TYPES = {"microsoft.compute/virtualmachines": 6, "microsoft.storage/storageaccounts": 9,
         "microsoft.network/virtualnetworks": 4, "microsoft.network/networksecuritygroups": 7,
         "microsoft.keyvault/vaults": 3, "microsoft.web/sites": 5, "microsoft.network/publicipaddresses": 4,
         "microsoft.compute/disks": 8, "microsoft.operationalinsights/workspaces": 2,
         "microsoft.containerservice/managedclusters": 1, "microsoft.network/applicationgateways": 1}


class FakeClient:
    def __init__(self):
        self.scope = Scope(management_groups=[TENANT])
        self.calls = 0

    def query(self, kql, max_rows=None):
        self.calls += 1
        h = int(hashlib.sha1(kql.encode()).hexdigest(), 16)
        low = kql.lower()
        typ = next((t for t in TYPES if t in low), None)
        if typ is None and h % 3:
            return QueryResult(rows=[])
        n = (TYPES.get(typ) or 2)
        rows = []
        for i in range(n):
            rid = f"/subscriptions/{SUBS[i % 3][0]}/resourceGroups/rg-{i % 2}/providers/{typ or 'microsoft.x/y'}/res{i}"
            if "recommendationid" in low or "param1" in low:
                if (h >> i) % 4 == 0:
                    rows.append({"recommendationId": "x", "name": f"res{i}", "id": rid})
            elif "compliant" in low:
                rows.append({"id": rid, "name": f"res{i}", "compliant": int((h >> i) % 3 != 0)})
            else:
                rows.append({"id": rid, "name": f"res{i}"})
        return QueryResult(rows=rows)


def write_azgovviz(run_dir: Path) -> None:
    """Minimal AzGovViz 6.7.x CSV set with the real column names (see references/azgovviz-outputs.md)."""
    import csv
    out = run_dir / "azgovviz"
    out.mkdir(parents=True, exist_ok=True)
    prefix = f"AzGovViz_6.7.2_20261008_101010_{TENANT}"
    root, lz, sbx = TENANT, "contoso-landingzones", "contoso-sandbox"

    def w(suffix, cols, rows):
        name = f"{prefix}{'_' + suffix if suffix else ''}.csv"
        with open(out / name, "w", newline="", encoding="utf-8") as fh:
            wr = csv.writer(fh, delimiter=";", quoting=csv.QUOTE_ALL)
            wr.writerow(cols)
            for r in rows:
                wr.writerow([r.get(c, "") for c in cols])

    w("", ["level", "mgName", "mgId", "mgParentId", "mgParentName", "Subscription", "SubscriptionId",
           "SubscriptionQuotaId", "SubscriptionState", "SubscriptionASCSecureScore", "SubscriptionTagsCount"], [
        {"level": 0, "mgName": "Tenant Root Group", "mgId": root, "mgParentId": "TenantRoot"},
        {"level": 1, "mgName": "Landing zones", "mgId": lz, "mgParentId": root, "mgParentName": "Tenant Root Group"},
        {"level": 1, "mgName": "Sandbox", "mgId": sbx, "mgParentId": root},
        {"level": 1, "mgName": "Landing zones", "mgId": lz, "mgParentId": root, "Subscription": SUBS[0][1],
         "SubscriptionId": SUBS[0][0], "SubscriptionState": "Enabled", "SubscriptionASCSecureScore": "36% (18 of 50 points)",
         "SubscriptionTagsCount": 2},
        {"level": 1, "mgName": "Landing zones", "mgId": lz, "mgParentId": root, "Subscription": SUBS[1][1],
         "SubscriptionId": SUBS[1][0], "SubscriptionState": "Enabled", "SubscriptionTagsCount": 0},
        {"level": 0, "mgName": "Tenant Root Group", "mgId": root, "mgParentId": "TenantRoot", "Subscription": SUBS[2][1],
         "SubscriptionId": SUBS[2][0], "SubscriptionState": "Enabled", "SubscriptionTagsCount": 0},
    ])
    ra_cols = ["Level", "RoleAssignmentId", "RoleAssignmentPIMRelated", "RoleAssignmentPIMAssignmentType", "MgId",
               "MgName", "SubscriptionId", "SubscriptionName", "Scope", "ScopeTenOrMgOrSubOrRGOrRes",
               "RoleAssignmentScopeName", "RoleAssignmentScopeRG", "RoleAssignmentScopeRes", "RoleClear", "RoleId",
               "RoleType", "AssignmentType", "AssignmentInheritFrom", "ObjectDisplayName", "ObjectSignInName",
               "ObjectId", "ObjectType", "RbacRelatedPolicyAssignmentClear", "RoleSecurityCustomRoleOwner",
               "RoleSecurityOwnerAssignmentSP", "RoleCanDoRoleAssignments"]
    ra = []

    def assign(rid, scope_kind, role, otype, name, oid, sub=None, mg=None, scope="thisScope Sub", atype="direct",
               policy="none", pim="False"):
        ra.append({"RoleAssignmentId": rid, "ScopeTenOrMgOrSubOrRGOrRes": scope_kind, "RoleClear": role,
                   "ObjectType": otype, "ObjectDisplayName": name, "ObjectId": oid, "SubscriptionId": sub or "",
                   "SubscriptionName": dict(SUBS).get(sub, ""), "MgId": mg or "", "Scope": scope,
                   "AssignmentType": atype, "RbacRelatedPolicyAssignmentClear": policy, "RoleAssignmentPIMRelated": pim,
                   "RoleType": "Builtin", "RoleAssignmentScopeName": mg or ""})

    s0, s1, s2 = SUBS[0][0], SUBS[1][0], SUBS[2][0]
    mgra = f"/providers/Microsoft.Management/managementGroups/{root}/providers/Microsoft.Authorization/roleAssignments/"
    assign(mgra + "1", "Mg", "Owner", "User Member", "Alice Admin", "u1", mg=root, scope="thisScope MG")
    for s in (s0, s1, s2):
        assign(mgra + "1", "Mg", "Owner", "User Member", "Alice Admin", "u1", sub=s, mg=root, scope=f"inherited {root}")
    for i, s in enumerate((s0, s1, s2)):
        base = f"/subscriptions/{s}/providers/Microsoft.Authorization/roleAssignments/"
        assign(base + "a", "Sub", "Owner", "User Member", f"Owner{i}a", f"o{i}a", sub=s)
        assign(base + "b", "Sub", "Owner", "User Member", f"Owner{i}b", f"o{i}b", sub=s)
        assign(base + "c", "Sub", "Owner", "User Member", f"Owner{i}c", f"o{i}c", sub=s)
        assign(base + "d", "Sub", "Contributor", "User Guest", f"Guest{i}", f"g{i}", sub=s)
    assign(f"/subscriptions/{s0}/providers/Microsoft.Authorization/roleAssignments/sp", "Sub", "Owner", "SP APP INT",
           "deploy-pipeline", "sp1", sub=s0)
    assign(f"/subscriptions/{s1}/providers/Microsoft.Authorization/roleAssignments/orph", "Sub", "Reader", "Unknown",
           "", "deadbeef", sub=s1)
    assign("/providers/Microsoft.Authorization/roleAssignments/root1", "Ten", "User Access Administrator", "User Member",
           "Global Admin", "ga", scope="inherited Tenant")
    assign(f"/subscriptions/{s0}/providers/Microsoft.Authorization/roleAssignments/pol", "Sub", "Owner", "SP MI Sys",
           "policy-mi", "mi1", sub=s0, policy="/providers/x (Deploy diag)")
    w("RoleAssignments", ra_cols, ra)
    w("RoleDefinitions", ["Name", "Id", "Type", "AssignmentsCount", "AssignableScopesCount", "RoleAssWriteCapable", "Actions"], [
        {"Name": "Custom Owner", "Id": "c1", "Type": "Custom", "AssignmentsCount": 0, "AssignableScopesCount": 1,
         "RoleAssWriteCapable": "True", "Actions": "*"},
        {"Name": "Reader", "Id": "r", "Type": "Builtin", "Actions": "*/read", "RoleAssWriteCapable": "False"}])
    w("ClassicAdministrators", ["Subscription", "SubscriptionId", "SubscriptionMgPath", "Identity", "Role"],
      [{"Subscription": SUBS[0][1], "SubscriptionId": s0, "Identity": "old@contoso.com", "Role": "CoAdministrator"}])
    pa_cols = ["Level", "MgId", "MgName", "subscriptionId", "subscriptionName", "PolicyAssignmentId",
               "PolicyAssignmentScopeName", "PolicyAssignmentDisplayName", "PolicyAssignmentEnforcementMode", "Effect",
               "PolicyNameClear", "PolicyAvailability", "PolicyId", "PolicyVariant", "PolicyType", "Inheritance",
               "ExcludedScope", "NonCompliantResources", "CompliantResources"]
    pa = []
    mcsb = f"/providers/Microsoft.Management/managementGroups/{lz}/providers/Microsoft.Authorization/policyAssignments/mcsb"
    pa.append({"PolicyAssignmentId": mcsb, "MgId": lz, "PolicyAssignmentScopeName": "Landing zones",
               "PolicyAssignmentDisplayName": "Microsoft cloud security benchmark", "PolicyAssignmentEnforcementMode": "Default",
               "Effect": "n/a", "PolicyId": "/providers/Microsoft.Authorization/policySetDefinitions/1f3afdf9-d0c9-4c3d-847f-89da613e70a8",
               "PolicyVariant": "PolicySet", "PolicyType": "BuiltIn", "Inheritance": "thisScope Mg"})
    for s in (s0, s1):
        pa.append({**pa[0], "subscriptionId": s, "Inheritance": f"inherited {lz}"})
    loc = f"/subscriptions/{s0}/providers/Microsoft.Authorization/policyAssignments/loc"
    pa.append({"PolicyAssignmentId": loc, "subscriptionId": s0, "PolicyAssignmentScopeName": SUBS[0][1],
               "PolicyAssignmentDisplayName": "Allowed locations", "PolicyAssignmentEnforcementMode": "DoNotEnforce",
               "Effect": "deny", "PolicyId": "/providers/Microsoft.Authorization/policyDefinitions/e56962a6-4747-49cd-b67b-bf8b01975c4c",
               "PolicyVariant": "Policy", "PolicyType": "BuiltIn", "Inheritance": "thisScope Sub", "PolicyNameClear": "Allowed locations"})
    w("PolicyAssignments", pa_cols, pa)
    w("PolicyExemptions", ["Scope", "ExemptionName", "Category", "ExpiresOn_UTC"],
      [{"Scope": "Sub", "ExemptionName": "legacy-app", "Category": "Waiver", "ExpiresOn_UTC": "n/a"}])
    w("PolicyDefinitions", ["Type", "Scope", "ScopeId", "PolicyDisplayName", "UniqueAssignmentsCount", "UsedInPolicySetsCount"],
      [{"Type": "Custom", "Scope": "Mg", "ScopeId": root, "PolicyDisplayName": "Old custom", "UniqueAssignmentsCount": 0,
        "UsedInPolicySetsCount": 0}])
    w("PolicySetDefinitions", ["Type", "PolicySetDisplayName", "UniqueAssignmentsCount"], [])
    w("ResourcesAll", ["subscriptionId", "subscriptionName", "type", "id", "name", "location", "cafResourceNamingResult"],
      [{"subscriptionId": s0, "type": "microsoft.storage/storageaccounts", "id": f"/subscriptions/{s0}/x/st{i}",
        "name": f"st{i}", "location": "westeurope", "cafResourceNamingResult": "passed" if i % 3 == 0 else "failed"}
       for i in range(9)])
    w("ResourceLocks", ["SubscriptionId", "SubscriptionName", "MGPath", "ScopeType", "Lock", "Id", "ResourceType"], [])
    w("ResourcesCostOptimizationAndCleanup", ["type", "subscriptionId", "Resource", "Intent"], [
        {"type": "microsoft.compute/disks", "subscriptionId": s1, "Resource": f"/subscriptions/{s1}/resourceGroups/rg/providers/Microsoft.Compute/disks/d1", "Intent": "cost savings"},
        {"type": "microsoft.resources/subscriptions/resourcegroups", "subscriptionId": s2, "Resource": f"/subscriptions/{s2}/resourceGroups/empty", "Intent": "clean up"}])
    w("VirtualNetworks", ["SubscriptionName", "Subscription", "VNet", "AddressSpaceAddressPrefixes", "PeeringsCount", "DdosProtection"], [
        {"SubscriptionName": SUBS[0][1], "VNet": "vnet-hub", "PeeringsCount": 2, "DdosProtection": "false", "AddressSpaceAddressPrefixes": "10.0.0.0/16"},
        {"SubscriptionName": SUBS[0][1], "VNet": "vnet-spoke1", "PeeringsCount": 1, "DdosProtection": "false"},
        {"SubscriptionName": SUBS[1][1], "VNet": "vnet-spoke2", "PeeringsCount": 1, "DdosProtection": "false"},
        {"SubscriptionName": SUBS[2][1], "VNet": "vnet-lab", "PeeringsCount": 0, "DdosProtection": "false"}])
    w("VirtualNetworkSubnets", ["SubscriptionName", "VNet", "SubnetName", "SubnetPrefix", "UsedIPAddressesPercent",
                                "AvailableIPAddresses", "SubnetIPAddressUsageCritical", "NetworkSecurityGroup"], [
        {"VNet": "vnet-hub", "SubnetName": "AzureFirewallSubnet", "SubnetPrefix": "10.0.0.0/26"},
        {"VNet": "vnet-spoke1", "SubnetName": "app", "SubnetPrefix": "10.1.0.0/24", "NetworkSecurityGroup": "nsg-app"},
        {"VNet": "vnet-spoke2", "SubnetName": "data", "SubnetPrefix": "10.2.0.0/28", "UsedIPAddressesPercent": "91 %",
         "SubnetIPAddressUsageCritical": "true"}])
    w("PrivateEndpoints", ["PEName", "ResourceType", "Resource", "PESubscriptionName"],
      [{"PEName": "pe-kv0", "ResourceType": "microsoft.keyvault/vaults", "Resource": "kv0", "PESubscriptionName": SUBS[0][1]}])
    w("DailySummary", ["capability", "count"], [{"capability": "ManagementGroups", "count": 3},
                                                {"capability": "PolicyDefinitionsCustom", "count": 1},
                                                {"capability": "RoleDefinitionsCustom", "count": 1}])
    w("PolicyRemediation", ["policyAssignmentDisplayName", "policyDefinitionDisplayName", "effect", "nonCompliantResourcesCount"],
      [{"policyAssignmentDisplayName": "Deploy diag", "policyDefinitionDisplayName": "Diag to LA", "effect": "deployIfNotExists",
        "nonCompliantResourcesCount": 7}])
    w("StorageAccountAccessAnalysis", ["storageAccount", "SubscriptionName", "containersAnonymousContainerCount",
                                       "containersAnonymousBlobCount", "staticWebsitesState"],
      [{"storageAccount": "st0", "SubscriptionName": SUBS[0][1], "containersAnonymousContainerCount": 1,
        "containersAnonymousBlobCount": 0, "staticWebsitesState": "false"}])
    (out / f"{prefix}.html").write_text("<html>AzGovViz</html>", encoding="utf-8")
    (out / "azgovviz-console.log").write_text(
        "* * * LEAST PRIVILEGE ADVICE\nThe Azure Governance Visualizer script is executed with more permissions than required.\n"
        " - Owner (BuiltInRole) !!!\nThe required Azure RBAC role ...\n", encoding="utf-8")
    util.write_json(out / "azgovviz-prepare.json", {"azGovVizVersion": "6.7.2", "account": "admin@contoso.com"})


def main(out_root: str, with_azgovviz: bool = False, with_checklists: bool = True) -> Path:
    run_dir = Path(out_root) / ("contoso_fake_full" if with_azgovviz else "contoso_fake")
    run_dir.mkdir(parents=True, exist_ok=True)
    if with_azgovviz:
        write_azgovviz(run_dir)
    util.write_json(run_dir / "run.json", {
        "schema": "azgov-assess/run@1", "tenant": {"tenantId": TENANT, "displayName": "Contoso (synthetic)",
                                                   "defaultDomain": "contoso.onmicrosoft.com"},
        "scope": {"description": "management group " + TENANT, "tokenProvider": "fake"},
        "stages": {"azgovviz": {"status": "skipped"}}, "startedAt": util.iso()})
    inv = {
        "schema": "azgov-assess/inventory@1", "generatedAt": util.iso(), "errors": {},
        "subscriptions": [{"subscriptionId": s, "name": n, "state": "Enabled", "quotaId": "MSDN_2014-09-01",
                           "mgChain": [{"name": TENANT, "displayName": "Tenant Root Group"}], "tags": {}}
                          for s, n in SUBS],
        "managementGroups": [{"id": f"/providers/Microsoft.Management/managementGroups/{TENANT}", "name": TENANT,
                              "displayName": "Tenant Root Group", "parent": ""}],
        "resourceGroups": [{"subscriptionId": s, "total": 4, "tagged": 1} for s, _ in SUBS],
        "typeCounts": [{"type": t, "n": n} for t, n in TYPES.items()],
        "locationCounts": [{"location": "westeurope", "n": 30}, {"location": "northeurope", "n": 12},
                           {"location": "eastus", "n": 8}],
        "subscriptionCounts": [{"subscriptionId": s, "n": 17} for s, _ in SUBS],
        "tagCoverage": [{"type": t, "total": n, "tagged": n // 3} for t, n in TYPES.items()],
        "defenderPlans": [{"subscriptionId": s, "plan": p, "tier": "Standard" if (i + j) % 3 == 0 else "Free",
                           "subPlan": "", "deprecated": False}
                          for i, (s, _) in enumerate(SUBS)
                          for j, p in enumerate(["VirtualMachines", "StorageAccounts", "KeyVaults", "Arm",
                                                 "CloudPosture", "SqlServers", "AppServices", "Containers"])],
        "secureScores": [{"subscriptionId": s, "current": 18.0 + i * 5, "max": 50.0, "percentage": (18 + i * 5) / 50}
                         for i, (s, _) in enumerate(SUBS)],
        "securityRecommendations": [{"title": "Storage accounts should restrict network access", "severity": "Medium", "resources": 6},
                                    {"title": "MFA should be enabled on accounts with owner permissions", "severity": "High", "resources": 2}],
        "advisor": [{"category": "Security", "impact": "High", "problem": "Enable soft delete for blobs", "solution": "x", "impactedType": "storage", "resources": 5},
                    {"category": "Cost", "impact": "Medium", "problem": "Right-size underutilized VMs", "solution": "x", "impactedType": "vm", "resources": 2}],
        "policyStates": [{"evaluations": 160, "resources": 50, "nonCompliant": 22, "compliant": 28}],
        "keyVaults": [{"id": f"/subscriptions/{SUBS[0][0]}/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv{i}",
                       "name": f"kv{i}", "subscriptionId": SUBS[0][0], "softDelete": True, "purgeProtection": i == 0,
                       "rbac": i != 2, "publicNetworkAccess": "Enabled"} for i in range(3)],
        "storageAccounts": [{"id": f"/subscriptions/{SUBS[i % 3][0]}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/st{i}",
                             "name": f"st{i}", "subscriptionId": SUBS[i % 3][0], "replication": "Standard_LRS",
                             "httpsOnly": True, "minTls": "TLS1_2" if i % 3 else "TLS1_0",
                             "allowBlobPublicAccess": i % 4 == 0, "publicNetworkAccess": "Enabled",
                             "sharedKey": True, "defaultAction": "Allow"} for i in range(9)],
        "logAnalytics": [{"id": "/subscriptions/x/la1", "name": "la-central", "subscriptionId": SUBS[0][0],
                          "location": "westeurope", "retentionDays": 30, "sku": "PerGB2018"}],
        "activityLogAlerts": [{"subscriptionId": SUBS[0][0], "total": 2, "serviceHealth": 1, "resourceHealth": 0}],
        "publicIps": [{"id": f"/subscriptions/{SUBS[0][0]}/pip{i}", "name": f"pip{i}", "subscriptionId": SUBS[0][0],
                       "location": "westeurope", "sku": "Standard", "attached": i != 3, "ddos": ""} for i in range(4)],
        "unattachedDisks": [{"id": f"/subscriptions/{SUBS[1][0]}/disk{i}", "name": f"disk{i}", "subscriptionId": SUBS[1][0],
                             "location": "westeurope", "sku": "Premium_LRS", "sizeGb": 128} for i in range(2)],
        "nsgOpenInbound": [{"id": f"/subscriptions/{SUBS[2][0]}/nsg1", "nsg": "nsg-jump", "subscriptionId": SUBS[2][0],
                            "rule": "allow-rdp", "port": "3389", "src": "*"}],
        "vms": [], "backupProtected": [],
        "hierarchySettings": {"requireAuthorizationForGroupCreation": False, "defaultManagementGroup": None},
        "perSubscription": [{"subscriptionId": s, "budgets": [] if i else [{"name": "monthly", "amount": 500}],
                             "activityLogDiagnostics": [] if i else [{"name": "toLA", "workspace": "x", "categories": ["Administrative"]}],
                             "securityContacts": [{"name": "default", "emails": "secops@contoso.com", "isEnabled": True,
                                                   "alertNotifications": "On"}] if i == 0 else []}
                            for i, (s, _) in enumerate(SUBS)],
    }
    inv["typeCountMap"] = inventory.type_count_map(inv)
    util.write_json(run_dir / "inventory.json", inv)
    if not with_checklists:
        return run_dir
    src = cl.ChecklistSource()
    src.resolve_commit()
    ev = cl.ChecklistEvaluator(FakeClient(), src, inv["typeCountMap"], workers=1)
    results = ev.evaluate(["alz", "waf", "aprl"], progress=False)
    for c in results["checklists"]:  # same order as the CLI: workbook export first, then the stripped results
        util.write_json(run_dir / "checklists" / f"graph_results_{c['key']}.json", cl.official_graph_results(results, c["key"]))
    util.write_json(run_dir / "checklists" / "results.json", cl.strip_private(results))
    return run_dir


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    print(main(args[0] if args else "/tmp/azgov-fake", with_azgovviz="--with-azgovviz" in sys.argv))
