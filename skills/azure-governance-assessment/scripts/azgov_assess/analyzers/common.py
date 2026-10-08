"""Helpers shared by analyzers."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

ROLE_OWNER = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
ROLE_CONTRIBUTOR = "b24988ac-6180-42a0-ab88-20f7382dd24c"
ROLE_UAA = "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"
ROLE_RBAC_ADMIN = "f58310d9-a9f6-439a-9e8d-f62e7b41a168"
PRIVILEGED_ROLE_IDS = {ROLE_OWNER, ROLE_UAA, ROLE_RBAC_ADMIN}
PRIVILEGED_ROLE_NAMES = {"owner", "user access administrator", "role based access control administrator",
                         "role based access control administrator (preview)"}
WRITE_ROLE_NAMES = PRIVILEGED_ROLE_NAMES | {"contributor"}

POLICY_ALLOWED_LOCATIONS = {"e56962a6-4747-49cd-b67b-bf8b01975c4c", "e765b5de-1225-4ba3-bd56-1ac6695af988"}
POLICYSET_MCSB = {"1f3afdf9-d0c9-4c3d-847f-89da613e70a8"}
POLICY_RESOURCE_TYPES = {"6c112d4e-5bc7-47ae-a041-ea2d9dccd749", "a08ec900-254a-4555-9bf5-e42af04b5c5c"}
POLICY_TAGS = {"871b6d14-10aa-478d-b590-94f262ecfa99", "96670d01-0a4d-4649-9c89-2d3abc0a5025",
               "cd3aa116-8754-49c9-a813-ad46512ece54", "b27a0cbd-a167-4dfa-ae64-4337be671140",
               "ea3f2387-9b95-492a-a190-fcdc54f7b070", "40df99da-1232-49b1-a39a-6da8d878f469",
               "726aca4c-86e9-4b04-b0c5-073027359532", "4f9dc7db-30c1-420c-b61a-e1d640128d26"}

DEFENDER_PLAN_LABELS = {
    "CloudPosture": "Defender CSPM", "VirtualMachines": "Servers", "StorageAccounts": "Storage",
    "KeyVaults": "Key Vault", "Arm": "Resource Manager", "SqlServers": "Azure SQL",
    "SqlServerVirtualMachines": "SQL on VMs", "OpenSourceRelationalDatabases": "Open-source DBs",
    "CosmosDbs": "Cosmos DB", "AppServices": "App Service", "Containers": "Containers", "Api": "APIs",
    "AI": "AI services", "Dns": "DNS (retired)", "KubernetesService": "Kubernetes (legacy)",
    "ContainerRegistry": "Container registry (legacy)",
}
# plan -> resource types that make the plan relevant
DEFENDER_PLAN_TYPES = {
    "VirtualMachines": ["microsoft.compute/virtualmachines", "microsoft.compute/virtualmachinescalesets",
                        "microsoft.hybridcompute/machines"],
    "StorageAccounts": ["microsoft.storage/storageaccounts"],
    "KeyVaults": ["microsoft.keyvault/vaults"],
    "SqlServers": ["microsoft.sql/servers"],
    "AppServices": ["microsoft.web/sites"],
    "Containers": ["microsoft.containerservice/managedclusters", "microsoft.containerregistry/registries"],
    "OpenSourceRelationalDatabases": ["microsoft.dbforpostgresql/flexibleservers", "microsoft.dbformysql/flexibleservers"],
    "CosmosDbs": ["microsoft.documentdb/databaseaccounts"],
    "Api": ["microsoft.apimanagement/service"],
    "AI": ["microsoft.cognitiveservices/accounts"],
}

LEARN = "https://learn.microsoft.com"

# Azure Landing Zone review checklist GUIDs (Azure/review-checklists, alz_checklist.en.json) that platform
# findings can answer. Used to mark otherwise-manual ALZ items as "assessed via finding".
ALZ = {
    "pim": "14658d35-58fd-4772-99b8-21112df27ee4",              # B03.07
    "naming": "cacf55bc-e4e4-46be-96bc-57a5f23a269a",           # C01.01
    "sandbox_mg": "667313b4-f566-44b5-b984-a859c773e7d2",       # C02.02
    "platform_mg": "61623a76-5a91-47e1-b348-ef254c27d42e",      # C02.03
    "mg_rbac_auth": "74d00018-ac6a-49e0-8e6a-83de5de32c19",     # C02.06
    "workload_mgs": "92481607-d5d1-4e4e-9146-58d3558fd772",     # C02.07
    "initiatives": "5c986cb2-9131-456a-8247-6e49f541acdc",      # E01.01
    "defs_intermediate_root": "223ace8c-b123-408c-a501-7f154e3ab369",  # E01.04
    "assign_high": "3829e7e3-1618-4368-9a04-77a209945bda",      # E01.05
    "allowed_services": "43334f24-9116-4341-a2ba-527526944008", # E01.06
    "builtin_first": "be7d7e48-4327-46d8-adc0-55bcf619e8a1",    # E01.07
    "root_assignments": "19048384-5c98-46cb-8913-156a12476e49", # E01.09
    "budget_alerts": "29fd366b-a180-452b-9bd7-954b7700c667",    # E02.01
    "sovereignty_policy": "5a917e1f-348e-4f25-9c27-d42e8bbac757",  # E03.01
    "single_workspace": "67e7a8ed-4b30-4e38-a3f2-9812b2363cef", # F01.01
    "locks": "541acdce-9793-477b-adb3-751ab2ab13ad",            # F01.08
    "deny_policies": "a6e55d7d-8a2a-4db1-87d6-326af625ca44",    # F01.09
    "health_events": "e5695f22-23ac-4e8c-a123-08ca5017f154",    # F01.10
    "service_health_alerts": "d5f345bf-97ab-41a7-819c-6104baa7d48c",  # F01.11
    "backup": "f625ca44-e569-45f2-823a-ce8cb12308ca",           # F04.02
    "kv_purge": "2ba52752-6944-4008-ae7d-7e4843276d8b",         # G02.03
    "kv_private": "cdb3751a-b2ab-413a-ba6e-55d7d8a2adb1",       # G02.07
    "activity_log_export": "4e3ab369-3829-4e7e-9161-83687a0477a2",  # G03.02
    "defender_cspm": "09945bda-4333-44f2-9911-634182ba5275",    # G03.03
    "defender_servers": "36a72a48-fffe-4c40-9747-0ab5064355ba", # G03.04
    "defender_cwp": "77425f48-ecba-43a0-aeac-a3ac733ccc6a",     # G03.05
    "storage_secure_transfer": "b03ed428-4617-4067-a787-85468b9ccf3f",  # G04.01
    "tls_policy": "31e77d70-f001-455b-93aa-6d05eea10968",       # G04.03
    "rbac_data_plane": "d4d1ad54-1abc-4919-b267-3f342d3b49e4",  # B04.02
}


def ref(title: str, path: str) -> Dict[str, str]:
    return {"title": title, "url": path if path.startswith("http") else LEARN + path}


def col(row: Dict[str, Any], *names: str, default: str = "") -> str:
    """First non-empty value among candidate column names (AzGovViz renamed columns across versions)."""
    for n in names:
        v = row.get(n)
        if v not in (None, ""):
            return str(v)
    return default


def lower_set(values: Iterable[Optional[str]]) -> set:
    return {str(v).lower() for v in values if v}


def guid_tail(resource_id: str) -> str:
    return (resource_id or "").rstrip("/").split("/")[-1].lower()


def pct(part: float, whole: float) -> Optional[float]:
    return round(100.0 * part / whole, 1) if whole else None


def short_id(resource_id: str) -> str:
    """'/subscriptions/x/resourceGroups/rg/providers/T/name' -> 'rg/name'."""
    parts = (resource_id or "").split("/")
    try:
        rg = parts[parts.index("resourceGroups") + 1]
        return f"{rg}/{parts[-1]}"
    except (ValueError, IndexError):
        return parts[-1] if parts else resource_id


def scope_kind(scope: str) -> str:
    s = (scope or "").lower()
    if "/providers/microsoft.management/managementgroups/" in s:
        return "Management group"
    if s in ("/", ""):
        return "Root"
    if "/resourcegroups/" in s:
        return "Resource" if "/providers/" in s.split("/resourcegroups/", 1)[1] else "Resource group"
    if s.startswith("/subscriptions/"):
        return "Subscription"
    return "Other"


def sub_from_id(resource_id: str) -> str:
    parts = (resource_id or "").split("/")
    try:
        return parts[parts.index("subscriptions") + 1]
    except (ValueError, IndexError):
        return ""
