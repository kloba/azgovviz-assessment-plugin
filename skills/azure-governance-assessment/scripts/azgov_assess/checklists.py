"""Azure/review-checklists integration.

Downloads checklist JSON files from https://github.com/Azure/review-checklists (cached), runs every
item's Azure Resource Graph query against the assessment scope and classifies the outcome.

Query conventions found in the checklists (and how they are interpreted):

* ``compliant`` column  - rows carry ``compliant`` = 1/0/true/false  -> per-resource verdicts
* APRL convention       - rows are the *non-compliant* resources (``recommendationId``/``param1``)
                          -> combined with the resource-type inventory to derive compliant counts
* plain listing         - rows are evidence for a reviewer (status ``info``)
"""

from __future__ import annotations

import concurrent.futures as cf
import hashlib
import json
import re
import time
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from . import util
from .arg import ArgError, ResourceGraphClient

REPO = "Azure/review-checklists"
RAW_BASE = "https://raw.githubusercontent.com/Azure/review-checklists/{ref}/{path}"
API_COMMIT = "https://api.github.com/repos/Azure/review-checklists/commits/{ref}"
API_TREE = "https://api.github.com/repos/Azure/review-checklists/git/trees/{ref}?recursive=1"

# Friendly catalogue of the checklists most relevant to a governance assessment.
# Any other "<key>_checklist.en.json" in checklists/ or checklists-ext/ can be requested by key.
CATALOG: Dict[str, Dict[str, str]] = {
    "alz": {"path": "checklists/alz_checklist.en.json", "title": "Azure Landing Zone (ALZ) Review"},
    "waf": {"path": "checklists/waf_checklist.en.json", "title": "Well-Architected Framework (WAF) Review"},
    "aprl": {"path": "checklists-ext/aprl_checklist.en.json", "title": "Azure Proactive Resiliency Library (APRL)"},
    "fullwaf": {"path": "checklists-ext/fullwaf_checklist.en.json", "title": "Full WAF (WAF + APRL + service guides)"},
    "ai_lz": {"path": "checklists/ai_lz_checklist.en.json", "title": "AI Landing Zone Review"},
    "aks": {"path": "checklists/aks_checklist.en.json", "title": "AKS Review"},
    "avd": {"path": "checklists/avd_checklist.en.json", "title": "Azure Virtual Desktop Review"},
    "apim": {"path": "checklists/apim_checklist.en.json", "title": "API Management Review"},
    "appsvc": {"path": "checklists/appsvc_checklist.en.json", "title": "App Service Review"},
    "network_appdelivery": {"path": "checklists/network_appdelivery_checklist.en.json",
                            "title": "Application Delivery Networking Review"},
    "afd": {"path": "checklists/afd_checklist.en.json", "title": "Azure Front Door Review"},
    "acr": {"path": "checklists/acr_checklist.en.json", "title": "Container Registry Security Review"},
    "azure_storage": {"path": "checklists/azure_storage_checklist.en.json", "title": "Azure Storage Review"},
    "keyvault": {"path": "checklists/keyvault_checklist.en.json", "title": "Key Vault Review"},
    "sap": {"path": "checklists/sap_checklist.en.json", "title": "SAP on Azure Review"},
    "avs": {"path": "checklists/avs_checklist.en.json", "title": "Azure VMware Solution Design Review"},
    "azure_arc": {"path": "checklists/azure_arc_checklist.en.json", "title": "Azure Arc Review"},
    "servicebus": {"path": "checklists/servicebus_checklist.en.json", "title": "Service Bus Review"},
    "servicefabric": {"path": "checklists/servicefabric_checklist.en.json", "title": "Service Fabric Review"},
    "cost": {"path": "checklists/cost_checklist.en.json", "title": "Cost Optimization Review"},
    "security": {"path": "checklists/security_checklist.en.json", "title": "Azure Security Review (deprecated)"},
    "identity": {"path": "checklists/identity_checklist.en.json", "title": "Identity Review"},
    "multitenancy": {"path": "checklists/multitenancy_checklist.en.json", "title": "Multitenancy Review"},
    "resiliency": {"path": "checklists/resiliency_checklist.en.json", "title": "Resiliency Review"},
}
DEFAULT_SET = ["alz", "waf", "aprl"]

STATUSES = ["compliant", "partial", "non_compliant", "not_applicable", "no_data", "info", "error", "manual"]
STATUS_LABEL = {
    "compliant": "Compliant", "partial": "Partially compliant", "non_compliant": "Non-compliant",
    "not_applicable": "Not applicable", "no_data": "No matching resources", "info": "Evidence (review)",
    "error": "Query error", "manual": "Manual review",
}
SEVERITY_WEIGHT = {"high": 3, "medium": 2, "low": 1}

# ALZ items whose "service" names a resource family; used to decide applicability when a
# compliant-column query returns no rows.
SERVICE_TYPES = {
    "aks": ["microsoft.containerservice/managedclusters"],
    "acr": ["microsoft.containerregistry/registries"],
    "front door": ["microsoft.cdn/profiles", "microsoft.network/frontdoors"],
    "firewall": ["microsoft.network/azurefirewalls"],
    "app gateway": ["microsoft.network/applicationgateways"],
    "apim": ["microsoft.apimanagement/service"],
    "expressroute": ["microsoft.network/expressroutecircuits", "microsoft.network/expressroutegateways"],
    "storage": ["microsoft.storage/storageaccounts"],
    "vnet": ["microsoft.network/virtualnetworks"],
    "nsg": ["microsoft.network/networksecuritygroups"],
    "load balancer": ["microsoft.network/loadbalancers"],
    "vwan": ["microsoft.network/virtualwans", "microsoft.network/virtualhubs"],
    "key vault": ["microsoft.keyvault/vaults"],
    "bastion": ["microsoft.network/bastionhosts"],
    "vpn": ["microsoft.network/vpngateways", "microsoft.network/virtualnetworkgateways"],
    "service bus": ["microsoft.servicebus/namespaces"],
    "app services": ["microsoft.web/sites"],
    "azure openai": ["microsoft.cognitiveservices/accounts"],
    "public ip addresses": ["microsoft.network/publicipaddresses"],
    "sap": ["microsoft.workloads/sapvirtualinstances"],
    "avs": ["microsoft.avs/privateclouds"],
    "azure service fabric": ["microsoft.servicefabric/clusters", "microsoft.servicefabric/managedclusters"],
    "ars": ["microsoft.recoveryservices/vaults"],
    "vm": ["microsoft.compute/virtualmachines"],
    "entra": [],
}

CONTAINER_TYPES = {
    "microsoft.subscription/subscriptions": "microsoft.resources/subscriptions",
    "microsoft.resources/subscriptions": "microsoft.resources/subscriptions",
    "microsoft.resources/resourcegroups": "microsoft.resources/subscriptions/resourcegroups",
}

# Upstream queries that do not test what their item says (each replacement query was run against a live tenant).
# A correction applies only while the upstream query still contains the defect (`defect` regex), so a fix in
# Azure/review-checklists takes over automatically. With `query` the corrected query runs instead, `replace`
# ([regex, text]) edits the upstream query; with neither the item is set aside for manual review. Every
# correction is listed in results.json and the report.
QUERY_CORRECTIONS: Dict[str, Dict[str, Any]] = {
    # "Require HTTPS, i.e. disable port 80 on the storage account"
    "e7a8dc4a-20e2-47c3-b297-11b1352beee0": {
        "defect": r"compliant\s*=\s*\(\s*properties\.supportsHttpsTrafficOnly\s*==\s*false\s*\)",
        "reason": "The upstream query is inverted: it marks storage accounts that accept only HTTPS as non-compliant.",
        "query": "resources | where type =~ 'Microsoft.Storage/StorageAccounts' "
                 "| extend compliant = coalesce(tobool(properties.supportsHttpsTrafficOnly), true) | distinct id, compliant",
    },
    # "Enable Microsoft Defender for all of your storage accounts"
    "fc5972cd-4cd2-41b0-a803-7f5e6b4bfd3d": {
        "defect": r"resourceContainers\s*\|\s*where\s+type\s*==\s*'microsoft\.security/pricings'",
        "reason": "The upstream query looks for the Defender plan in the wrong table and joins it on the storage account "
                  "ID, so every storage account fails. The corrected query checks the subscription's Defender for "
                  "Storage plan.",
        "query": "resources | where type =~ 'Microsoft.Storage/StorageAccounts' | project id, subscriptionId "
                 "| join kind=leftouter (securityresources | where type =~ 'microsoft.security/pricings' "
                 "and name =~ 'StorageAccounts' | project subscriptionId, pricingTier = tostring(properties.pricingTier)) "
                 "on subscriptionId | extend compliant = (pricingTier =~ 'Standard') | distinct id, compliant",
    },
    # ALZ D03.02 "Use IP addresses from the address allocation ranges for private internets (RFC 1918)"
    "3f630472-2dd6-49c5-a5c2-622f54b69bad": {
        "defect": r"matches\s+regex\s+@'[^']*\\\\\.",  # `\\.` inside a verbatim @'...' string
        "reason": "The upstream regular expression is escaped twice inside a verbatim string, so no address range "
                  "ever matches and every virtual network fails.",
        "query": "resources | where type =~ 'microsoft.network/virtualnetworks' "
                 "| mv-expand addressPrefix = properties.addressSpace.addressPrefixes "
                 "| extend cidr = tostring(addressPrefix) | where cidr !contains ':' "
                 "| extend compliant = (cidr matches regex @'^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.)') "
                 "| project id, compliant, cidr",
    },
    # "Public IP assignment to VM running SAP Workload is not recommended."
    "82734c88-6ba2-4802-8459-11475e39e530": {
        "defect": r"publicIPAddresses'\s+and\s+sku\.tier\s*=~\s*'Regional'",
        "reason": "The upstream query lists public IP addresses that are not zone-redundant; it does not look at VMs "
                  "running SAP, so its result says nothing about this item.",
    },
    # "Deploy both VMs in the high-availability pair in an availability set or in availability zones." (SAP)
    "f656e745-0cfb-453e-8008-0528fa21c933": {
        "defect": r"Microsoft\.Storage/storageAccounts'\s*\|\s*where\s+sku\.name\s+in~\s*\(\s*'Standard_LRS'",
        "reason": "The upstream query lists locally redundant storage accounts; it does not look at SAP "
                  "high-availability VM pairs.",
    },
    # SAP: "Leverage Azure resource tag for cost categorization and resource grouping (...)"
    "4e138115-2318-41aa-9174-26943ff8ae7d": {
        "defect": r"resources\s*\|\s*extend\s+compliant\s*=\s*isnotnull\(\s*\['tags'\]\s*\)",
        "reason": "The upstream query checks whether every resource in the scope has any tag; it is not limited to SAP "
                  "resources and does not look for the tags the item names.",
    },
    # SAP: "Azure tagging can be leveraged to logically group and track resources, ..."
    "579266bc-ca27-45fa-a1ab-fe9d55d04c3c": {
        "defect": r"resources\s*\|\s*extend\s+compliant\s*=\s*isnotnull\(\s*\['tags'\]\s*\)",
        "reason": "The upstream query checks whether every resource in the scope has any tag; it is not limited to SAP "
                  "resources.",
    },
    # "Ensure that APIs and endpoints used by the LLM application are properly secured with authentication ..."
    "1102cac6-eae0-41e6-b842-e52f4721d928": {
        "defect": r"compliant\s*=\s*\(\s*isnotnull\(\s*identity\s*\)\s*\)",
        "reason": "The upstream query checks whether the AI or Search resource has a managed identity of its own, which "
                  "says nothing about how endpoints are secured. Azure AI and Search endpoints always require a key or "
                  "Microsoft Entra ID; the application's own API is not visible in Resource Graph.",
    },
    # "Use Premium and Standard tiers for staging slots and automated backups."
    "e4b31c6a-2e3f-4df1-8e8b-9c3aa5a27820": {
        "defect": r"sku\.tier\s*==\s*'Premium'\s+or\s+sku\.tier\s*==\s*'Standard'",
        "reason": "The upstream query accepts only the exact tier names 'Premium' and 'Standard', so PremiumV2/V3, "
                  "Isolated and Elastic Premium plans, which support slots and backups, fail.",
        "query": "resources | where type =~ 'microsoft.web/serverfarms' | extend tier = tostring(sku.tier) "
                 "| extend compliant = (tier startswith 'Premium' or tier startswith 'Standard' or tier startswith "
                 "'Isolated' or tier in~ ('ElasticPremium', 'WorkflowStandard')) | distinct id, tier, compliant",
    },
    # ALZ D07.08 "For subnets in VNets not connected to Virtual WAN, attach a route table ..."
    "a3784907-9836-4271-aafc-93535f8ec08b": {
        "defect": r"kind\s*=\s*fullouter[\s\S]*remotevnettohubpeering",
        "reason": "For peered virtual networks the upstream query adds the gateway, firewall and Bastion subnets back "
                  "through a full outer join, so a peered hub network fails even when every other subnet has a route "
                  "table.",
        "query": "resources | where type =~ 'microsoft.network/virtualnetworks' "
                 "| extend isVWANpeer = tolower(tostring(properties.virtualNetworkPeerings)) contains 'remotevnettohubpeering' "
                 "| mv-expand subnet = properties.subnets "
                 "| extend subnetId = tostring(subnet.id), subnetName = tostring(subnet.name) "
                 "| where isnotempty(subnetId) and subnetName !in~ ('GatewaySubnet', 'AzureFirewallSubnet', "
                 "'AzureFirewallManagementSubnet', 'RouteServerSubnet', 'AzureBastionSubnet') "
                 "| project id, subnetId, compliant = (isnotempty(tostring(subnet.properties.routeTable.id)) or isVWANpeer)",
    },
    # APRL "Deploy Network Watcher in all regions where you have networking services"
    "4e133bd0-8762-bc40-a95b-b29142427d73": {
        "defect": r'where\s+location\s*!=\s*"global"\s*\|\s*union',
        "reason": "The upstream query counts every resource type in every location, so a resource in a geography such "
                  "as 'unitedstates' (an Entra tenant, for example) shows up as a region without Network Watcher. The "
                  "corrected query checks network resources per subscription and region.",
        "query": "resources | where type startswith 'microsoft.network/' and type !~ 'microsoft.network/networkwatchers' "
                 "and isnotempty(location) and location !~ 'global' | distinct subscriptionId, location "
                 "| join kind=leftouter (resources | where type =~ 'microsoft.network/networkwatchers' "
                 "| project subscriptionId, location, watcher = id) on subscriptionId, location "
                 "| where isempty(watcher) "
                 "| project recommendationId = '4e133bd0-8762-bc40-a95b-b29142427d73', name = location, "
                 "id = strcat('/subscriptions/', subscriptionId, '/locations/', location), "
                 "param1 = strcat('LocationMissingNetworkWatcher:', location)",
    },
    # APRL "Configure network access restrictions" (App Service)
    "aab6b4a4-9981-43a4-8728-35c7ecbb746d": {
        "defect": r"join\s+kind\s*=\s*inner[\s\S]*isnotnull\(\s*IpSecurityRestrictions\s*\)",
        "reason": "The upstream query flags every app that has any access-restriction entry, so apps with real "
                  "restrictions fail too (App Service always returns at least the default 'Allow all' rule). The "
                  "corrected query flags apps open to public traffic with no rule other than 'Allow all'.",
        "query": "resources | where type =~ 'microsoft.web/sites' and properties.kind has 'app' "
                 "| project name, id, tags, subscriptionId, publicAccess = tostring(properties.publicNetworkAccess) "
                 "| join kind=leftouter (appserviceresources | where type =~ 'microsoft.web/sites/config' "
                 "| mv-expand rule = properties.IpSecurityRestrictions "
                 "| extend ip = tostring(rule.IpAddress), action = tostring(rule.Action) "
                 "| summarize rules = countif(isnotnull(rule) and not(ip =~ 'Any' and action =~ 'Allow')), "
                 "defaultAction = take_any(tostring(properties.IpSecurityRestrictionsDefaultAction)) by name, subscriptionId) "
                 "on name, subscriptionId "
                 "| where publicAccess !~ 'Disabled' and defaultAction !~ 'Deny' and coalesce(rules, 0) == 0 "
                 "| project recommendationId = 'aab6b4a4-9981-43a4-8728-35c7ecbb746d', name, id, tags, "
                 "param1 = 'No network restrictions set'",
    },
    # APRL "Set minimum instance count to 2 for app service"
    "9e6682ac-31bc-4635-9959-ab74b52454e6": {
        "defect": r"PreWarmedInstanceCount\s*<\s*2",
        "reason": "The upstream query reads the pre-warmed instance count, which only Elastic Premium plans use, so "
                  "every web app fails. The corrected query checks the instance count of the app's App Service plan.",
        "query": "resources | where type =~ 'microsoft.web/sites' and properties.kind has 'app' "
                 "| extend planId = tolower(tostring(properties.serverFarmId)) "
                 "| join kind=leftouter (resources | where type =~ 'microsoft.web/serverfarms' "
                 "| project planId = tolower(id), instances = toint(sku.capacity)) on planId "
                 "| where instances < 2 "
                 "| project recommendationId = '9e6682ac-31bc-4635-9959-ab74b52454e6', name, id, tags, "
                 "param1 = strcat('App Service plan instances: ', instances)",
    },
    # APRL "Configure NSG Flow Logs"
    "da1a3c06-d1d5-a940-9a99-fcc05966fe7c": {
        "defect": r"on\s+\$left\.lowerCaseNsgId\s*==\s*\$right\.lowerCaseTargetNsgId",
        "reason": "The upstream query accepts only NSG flow logs, which can no longer be created (virtual network flow "
                  "logs replace them). The corrected query also accepts an enabled flow log on the network interface, "
                  "subnet or virtual network the NSG protects.",
        "query": "resources | where type =~ 'microsoft.network/networksecuritygroups' "
                 "| project name, id, nsgId = tolower(id), subnets = properties.subnets, nics = properties.networkInterfaces "
                 "| mv-expand subnet = iff(array_length(subnets) > 0, subnets, dynamic([{}])) "
                 "| mv-expand nic = iff(array_length(nics) > 0, nics, dynamic([{}])) "
                 "| extend subnetId = tolower(tostring(subnet.id)), nicId = tolower(tostring(nic.id)) "
                 "| join kind=leftouter (resources | where type =~ 'microsoft.network/networkinterfaces' "
                 "| mv-expand ipc = properties.ipConfigurations "
                 "| project nicId = tolower(id), nicSubnetId = tolower(tostring(ipc.properties.subnet.id))) on nicId "
                 "| extend vnetId = iff(isempty(subnetId), '', strcat_array(array_slice(split(subnetId, '/'), 0, 8), '/')), "
                 "nicVnetId = iff(isempty(nicSubnetId), '', strcat_array(array_slice(split(nicSubnetId, '/'), 0, 8), '/')) "
                 "| mv-expand target = pack_array(nsgId, subnetId, vnetId, nicId, nicSubnetId, nicVnetId) to typeof(string) "
                 "| where isnotempty(target) "
                 "| join kind=leftouter (resources | where type =~ 'microsoft.network/networkwatchers/flowlogs' "
                 "and properties.enabled == true | project target = tolower(tostring(properties.targetResourceId)), "
                 "flowLog = name) on target "
                 "| summarize covered = countif(isnotempty(flowLog)) by name, id "
                 "| where covered == 0 "
                 "| project recommendationId = 'da1a3c06-d1d5-a940-9a99-fcc05966fe7c', name, id, "
                 "param1 = 'Flow logs (NSG, network interface, subnet or virtual network): not configured or disabled'",
    },
    # APRL "Configure monitoring for all Azure Virtual Machines"
    "4a9d8973-6dba-0042-b3aa-07924877ebd5": {
        "defect": r"properties\.publisher\s*=~\s*\"Microsoft\.Azure\.Diagnostics\"",
        "reason": "The upstream query recognises only the Azure Diagnostics extension, which Azure retired on "
                  "31 March 2026, so VMs monitored with the Azure Monitor Agent fail. The corrected query checks for the "
                  "Azure Monitor Agent and data collection rules that collect performance counters and event logs or "
                  "syslog.",
        "query": "resources | where type =~ 'microsoft.compute/virtualmachines' "
                 "| project name, id, tags, idVm = tolower(id) "
                 "| join kind=leftouter (insightsresources | where type =~ 'microsoft.insights/datacollectionruleassociations' "
                 "| extend lid = tolower(id) | where lid contains '/providers/microsoft.compute/virtualmachines/' "
                 "| project idVm = substring(lid, 0, indexof(lid, '/providers/microsoft.insights/datacollectionruleassociations/')), "
                 "idDcr = tolower(tostring(properties.dataCollectionRuleId)) "
                 "| join kind=inner (resources | where type =~ 'microsoft.insights/datacollectionrules' "
                 "| project idDcr = tolower(id), perf = toint(array_length(properties.dataSources.performanceCounters) > 0), "
                 "logs = toint(array_length(properties.dataSources.windowsEventLogs) > 0 "
                 "or array_length(properties.dataSources.syslog) > 0)) "
                 "on idDcr | summarize hasPerf = max(perf), hasLogs = max(logs) by idVm) on idVm "
                 "| join kind=leftouter (resources | where type =~ 'microsoft.compute/virtualmachines/extensions' "
                 "and tostring(properties.type) in~ ('AzureMonitorWindowsAgent', 'AzureMonitorLinuxAgent') "
                 "| extend lid = tolower(id) | summarize agents = count() by idVm = substring(lid, 0, indexof(lid, '/extensions/'))) "
                 "on idVm "
                 "| where coalesce(agents, 0) == 0 or coalesce(hasPerf, 0) == 0 or coalesce(hasLogs, 0) == 0 "
                 "| project recommendationId = '4a9d8973-6dba-0042-b3aa-07924877ebd5', name, id, tags, "
                 "param1 = strcat('Azure Monitor Agent: ', iff(coalesce(agents, 0) > 0, 'installed', 'missing')), "
                 "param2 = strcat('Performance counters collected: ', iff(coalesce(hasPerf, 0) > 0, 'yes', 'no')), "
                 "param3 = strcat('Event logs or syslog collected: ', iff(coalesce(hasLogs, 0) > 0, 'yes', 'no'))",
    },
    # APRL "Enable zone redundancy" (Container Registry)
    "63491f70-22e4-3b4a-8b0c-845450e46fac": {
        "defect": r"properties\.zoneRedundancy\s*!=\s*\"Enabled\"",
        "reason": "Container registries are zone-redundant by default in every region with availability zones, whatever "
                  "the legacy zoneRedundancy property says, so the upstream query flags protected registries. Resource "
                  "Graph cannot tell which regions have availability zones.",
    },
    # APRL "Public IP addresses should have DDoS protection enabled" - a false pass
    "c4254c66-b8a5-47aa-82f6-e7d7fb418f47": {
        "defect": r'protectionMode\s*!in~\s*\(\s*"Enabled"\s*,\s*"VirtualNetworkInherited"\s*\)',
        "reason": "The upstream query counts the default 'VirtualNetworkInherited' mode as protected, but a public IP only "
                  "inherits DDoS protection from a virtual network with a DDoS Network Protection plan. The corrected "
                  "query accepts inherited protection only when a virtual network in scope has such a plan.",
        "query": "resources | where type =~ 'Microsoft.Network/publicIPAddresses' "
                 "| extend mode = tostring(properties.ddosSettings.protectionMode), joinKey = 1 "
                 "| join kind=leftouter (resources | where type =~ 'microsoft.network/virtualnetworks' "
                 "and tobool(properties.enableDdosProtection) == true "
                 "| summarize protectedVnets = count() | extend joinKey = 1) on joinKey "
                 "| where not(mode =~ 'Enabled' or (mode =~ 'VirtualNetworkInherited' and coalesce(protectedVnets, 0) > 0)) "
                 "| project recommendationId = 'c4254c66-b8a5-47aa-82f6-e7d7fb418f47', name, id, tags, "
                 "param1 = strcat('DDoS protection mode: ', iff(isempty(mode), 'not set', mode), "
                 "iff(mode =~ 'VirtualNetworkInherited', ' (no virtual network has DDoS Network Protection)', ''))",
    },
    # ALZ C02.14 "Ensure tags are used for billing and cost management." - a false pass
    "5de32c19-9248-4160-9d5d-1e4e614658d3": {
        "defect": r"resources\s*\|\s*extend\s+compliant\s*=\s*isnotnull\(\s*\['tags'\]\s*\)",
        "reason": "The upstream query treats an empty tag set as tagged, so resources without any tag pass.",
        "query": "resources | extend compliant = tostring(tags) !in ('', '{}') "
                 "| project name, id, subscriptionId, resourceGroup, tags, compliant",
    },
    # "Azure AI Services are properly tagged for better management" - a false pass
    "e1d7aaab-3571-4449-ab80-53d89f89dc7b": {
        "defect": r"compliant\s*=\s*\(\s*tags\s*!=\s*'\{\}'\s*\)",
        "reason": "The upstream query compares the tags with '{}', which is also true when a resource has no tags at "
                  "all, so untagged AI and Search resources pass.",
        "query": "resources | where type =~ 'microsoft.cognitiveservices/accounts' or type =~ 'microsoft.search/searchservices' "
                 "| project id, compliant = (tostring(tags) !in ('', '{}'))",
    },
    # ALZ C02.01 "Enforce reasonably flat management group hierarchy with no more than four levels." - a false pass
    "2df27ee4-12e7-4f98-9f63-04722dd69c5b": {
        "defect": r"compliant\s*=\s*\(\s*array_length\(mgmtChain\)\s*<=\s*4\s+and\s+array_length\(mgmtChain\)\s*>\s*1\s*\)\s*$",
        "reason": "The upstream query measures depth only through subscriptions, so a management-group branch deeper "
                  "than four levels that holds no subscription is never checked. The corrected query also checks every "
                  "management group.",
        "query": "resourcecontainers | where type =~ 'microsoft.resources/subscriptions' "
                 "| extend mgmtChain = properties.managementGroupAncestorsChain "
                 "| project id, name, compliant = (array_length(mgmtChain) <= 4 and array_length(mgmtChain) > 1) "
                 "| union (resourcecontainers | where type =~ 'microsoft.management/managementgroups' "
                 "| project id, name, compliant = (coalesce(array_length(properties.details.managementGroupAncestorsChain), 0) < 4))",
    },
    # ALZ D01.14 "Use Standard Load Balancer SKU with a zone-redundant deployment ..." - a false pass
    "9dcd6250-9c4a-4382-aa9b-5b84c64fc1fe": {
        "defect": r"tolower\(sku\.name\)\s*!=\s*'basic'(?![\s\S]*SKU: Basic)",
        "reason": "The upstream query leaves out Basic SKU load balancers, which meet neither part of the item (Standard "
                  "SKU, zone redundancy), so they count as compliant.",
        "replace": [r"\Z", " | union (resources | where type =~ 'microsoft.network/loadbalancers' "
                           "and tolower(tostring(sku.name)) == 'basic' | project name, id, tags, param1 = 'SKU: Basic', "
                           "param2 = 'Basic SKU does not support availability zones')"],
    },
    # ALZ D09.02 "Don't rely on the NSG inbound default rules using the VirtualNetwork service tag ..."
    "11deb39d-8299-4e47-bbe0-0fb5a36318a8": {
        "defect": r"by\s+id\s*,\s*tostring\(ruleDirection\)\s*\|\s*where\s+ruleDirection\s*==\s*'Inbound'",
        "reason": "The upstream query drops NSGs whose custom rules are all outbound, so an NSG that relies entirely on "
                  "the default inbound rules is never evaluated.",
        "query": "resources | where type =~ 'microsoft.network/networksecuritygroups' | project id, rules = properties.securityRules "
                 "| mv-expand rule = iff(array_length(rules) > 0, rules, dynamic([{}])) "
                 "| summarize StarDenies = countif(tostring(rule.properties.direction) =~ 'Inbound' "
                 "and tostring(rule.properties.access) =~ 'Deny' and tostring(rule.properties.sourceAddressPrefix) == '*' "
                 "and tostring(rule.properties.destinationAddressPrefix) == '*' and tostring(rule.properties.protocol) == '*' "
                 "and tostring(rule.properties.destinationPortRange) == '*') by id "
                 "| project id, compliant = (StarDenies > 0)",
    },
    # "Use HTTPS only and consider enabling HTTP Strict Transport Security (HSTS)." (App Service)
    "475ba18f-dbf5-490c-b65d-e8e03f9bcbd4": {
        "defect": r"kind\s*==\s*'app'\s+or\s+kind\s*==\s*'app,linux'",
        "reason": "The upstream query looks only at apps whose kind is exactly 'app' or 'app,linux', so container and "
                  "other web apps are never checked.",
        "query": "resources | where type =~ 'microsoft.web/sites' and kind has 'app' "
                 "| extend compliant = (properties.httpsOnly == true) | distinct id, compliant",
    },
    # SAP: "The CIDR for the primary virtual network (VNet) shouldn't conflict or overlap with the CIDR of the DR site"
    "6561f847-3db5-4ff8-9200-5ad3c3b436ad": {
        "defect": r"compliant\s*=\s*\(\s*cidr\s+matches\s+regex",
        "reason": "The upstream query only checks that each virtual network uses private address ranges; it never "
                  "compares the primary and the DR network, so it says nothing about overlapping ranges.",
    },
    # SAP: "enforce existing Management Group policies to SAP Subscriptions"
    "6ba28021-4591-4147-9e39-e5309cccd979": {
        "defect": r"compliant\s*=\s*\(\s*array_length\(mgmtChain\)\s*<=\s*4",
        "reason": "The upstream query checks management-group depth for every subscription; it does not look at SAP "
                  "subscriptions or the policies assigned to them.",
    },
    # APRL "Replicate VMs using Azure Site Recovery" - a false pass
    "cfe22a65-b1db-fd41-9e8e-d573922709ae": {
        "defect": r'\|\s*where\s+securityType\s*!in~\s*\(\s*"TrustedLaunch"\s*,\s*"ConfidentialVM"\s*\)',
        "reason": "The upstream query skips Trusted launch VMs, which Site Recovery supports (Windows, and Linux VMs "
                  "created after 1 April 2024), so they pass without being checked.",
        "replace": [r'\|\s*where\s+securityType\s*!in~\s*\(\s*"TrustedLaunch"\s*,\s*"ConfidentialVM"\s*\)',
                    '| where tostring(securityType) !~ "ConfidentialVM" | where not(tostring(securityType) =~ "TrustedLaunch" '
                    'and tostring(properties.storageProfile.osDisk.osType) =~ "Linux" '
                    'and todatetime(properties.timeCreated) < datetime(2024-04-01))'],
    },
    # APRL "Backup VMs with Azure Backup service" - a false pass
    "1981f704-97b9-b645-9c57-33f8ded9261a": {
        "defect": r"extend\s+name\s*=\s*strcat_array\(array_slice\(split\(idBackupEnabled",
        "reason": "The upstream query matches backups to VMs by name only, so a VM without backup passes when a VM with "
                  "the same name elsewhere is backed up.",
        "query": "resources | where type =~ 'Microsoft.Compute/virtualMachines' | project name, id, tags, vmId = tolower(id) "
                 "| join kind=leftouter (recoveryservicesresources "
                 "| where type =~ 'Microsoft.RecoveryServices/vaults/backupFabrics/protectionContainers/protectedItems' "
                 "| where properties.dataSourceInfo.datasourceType =~ 'Microsoft.Compute/virtualMachines' "
                 "| project vmId = tolower(tostring(properties.sourceResourceId)), backedUp = 1) on vmId "
                 "| where isnull(backedUp) | project recommendationId = '1981f704-97b9-b645-9c57-33f8ded9261a', name, id, tags",
    },
    # APRL "VM network interfaces and associated subnets both have a Network Security Group associated" - a false pass
    "82b3cf6b-9ae2-2e44-b193-10793213f676": {
        "defect": r"project\s+subnetId\s*=\s*tostring\(subnet\.id\)",
        "reason": "The upstream query joins subnet IDs case-sensitively, and Azure reports them in different casing, so "
                  "VMs whose network interface and subnet both have an NSG are not found.",
        "query": "resources | where type =~ 'Microsoft.Network/networkInterfaces' | where isnotnull(properties.networkSecurityGroup) "
                 "| mv-expand ipc = properties.ipConfigurations "
                 "| project nicId = tolower(tostring(id)), subnetId = tolower(tostring(ipc.properties.subnet.id)) "
                 "| join kind=inner (resources | where type =~ 'Microsoft.Network/networkSecurityGroups' "
                 "and isnotnull(properties.subnets) | mv-expand subnet = properties.subnets "
                 "| project subnetId = tolower(tostring(subnet.id))) on subnetId "
                 "| distinct nicId "
                 "| join kind=inner (resources | where type =~ 'Microsoft.Compute/virtualMachines' "
                 "| mv-expand nic = properties.networkProfile.networkInterfaces "
                 "| project name, id, tags, nicId = tolower(tostring(nic.id)), nicName = tostring(split(nic.id, '/')[8])) "
                 "on nicId "
                 "| project recommendationId = '82b3cf6b-9ae2-2e44-b193-10793213f676', name, id, tags, "
                 "param1 = strcat('nic-name=', nicName)",
    },
    # APRL "Ensure Resource Group and its Resources are located in the same Region" - a false pass
    "98bd7098-49d6-491b-86f1-b143d6b1a0ff": {
        "defect": r"\|\s*join\s*\(\s*resourcecontainers\s*\|\s*project\s+containerid",
        "reason": "The upstream join keeps one arbitrary resource per resource group (Kusto's default innerunique join), so "
                  "most mismatched resources are never reported, and it compares IDs case-sensitively. The corrected "
                  "query lists every resource group that holds resources in another region.",
        "query": (
                 'resources'
                 " | where location != 'global' and resourceGroup != 'networkwatcherrg' and split(id, '/', "
                 "3)[0] =~ 'resourceGroups'"
                 " | extend rgId = strcat_array(array_slice(split(id, '/'), 0, 4), '/'), "
                 "rgKey = tolower(strcat_array(array_slice(split(id, '/'), 0, 4), '/'))"
                 ' | join kind=inner (resourcecontainers'
                 " | where type =~ 'microsoft.resources/subscriptions/resourcegroups'"
                 ' | project rgKey = tolower(id), '
                 'containerlocation = location) on $left.rgKey == $right.rgKey'
                 ' | where location != containerlocation'
                 ' | summarize mismatched = count(), example = take_any(name) by rgId, containerlocation'
                 " | project recommendationId = '98bd7098-49d6-491b-86f1-b143d6b1a0ff', "
                 "name = tostring(split(rgId, '/')[4]), id = rgId, tags = '', param1 = strcat(mismatched, "
                 "' resource(s) outside the resource group region ', containerlocation, ', e.g. ', "
                 'example)'),
    },
    # APRL "Store configuration as app settings" (App Service)
    "0b80b67c-afbe-4988-ad58-a85a146b681e": {
        "defect": r"extend\s+AppSettings\s*=\s*iif\(\s*isempty\(properties\.AppSettings\)\s*,\s*true\s*,\s*false\s*\)",
        "reason": "The upstream query is inverted and reads app settings that Resource Graph does not expose, so it never "
                  "reports an app.",
    },
    # APRL "Use Azure Disks with Zone Redundant Storage for higher resiliency and availability" - a false pass
    "fa0cf4f5-0b21-47b7-89a9-ee936f193ce1": {
        "defect": r"where\s+sku\.name\s+has_cs\s+'ZRS'\s+or\s+array_length\(zones\)\s*>\s*0",
        "reason": "The upstream filter keeps only disks that are already zonal or zone-redundant, so the locally redundant "
                  "disks it is meant to find are never reported. The corrected query lists every Premium and Standard SSD "
                  "LRS disk (in a region without availability zones ZRS disks are not an option).",
        "query": (
                 'resources'
                 " | where type =~ 'microsoft.compute/disks' and tostring(sku.name) in~ ('Premium_LRS', "
                 "'StandardSSD_LRS')"
                 " | project recommendationId = 'fa0cf4f5-0b21-47b7-89a9-ee936f193ce1', name, id, tags, "
                 "param1 = tostring(sku.name), param2 = iff(array_length(zones) > 0, 'Zonal LRS disk', "
                 "'Non-zonal LRS disk')"),
    },
    # APRL "Configure one or more read replicas" (PostgreSQL flexible server) - a false pass
    "2ab85a67-26be-4ed2-a0bb-101b2513ec63": {
        "defect": r'where\s+properties\.replicationRole\s*==\s*"AsyncReplica"',
        "reason": "The upstream query reports the servers that are themselves read replicas, which meet the item, so a "
                  "server without any replica is never reported.",
        "query": (
                 'resources'
                 " | where type =~ 'microsoft.dbforpostgresql/flexibleservers'"
                 " | where tostring(properties.replicationRole) !in~ ('AsyncReplica', 'GeoAsyncReplica')"
                 ' | extend lid = tolower(id)'
                 ' | join kind=leftouter (resources'
                 " | where type =~ 'microsoft.dbforpostgresql/flexibleservers'"
                 ' | where isnotempty(tostring(properties.sourceServerResourceId))'
                 ' | summarize replicas = count() by lid = tolower(tostring(properties.sourceServerResourceId))) on lid'
                 ' | where isnull(replicas)'
                 " | project recommendationId = '2ab85a67-26be-4ed2-a0bb-101b2513ec63', name, id, tags, "
                 "param1 = strcat('replicationRole:', tostring(properties.replicationRole), "
                 "' (no read replica)')"),
    },
    # APRL "Configure continuous backup mode" (Cosmos DB) - a false pass
    "e544520b-8505-7841-9e77-1f1974ee86ec": {
        "defect": r"properties\.enableMultipleWriteLocations\s*==\s*false",
        "reason": "The upstream query skips accounts with multi-region writes, which support continuous backup, and "
                  "accounts that do not report the analytical-store setting.",
        "query": (
                 'resources'
                 " | where type =~ 'Microsoft.DocumentDb/databaseAccounts' and tostring(properties.backupPolicy.type) =~ 'Periodic' and coalesce(tobool(properties.enableAnalyticalStorage), "
                 'false) == false'
                 " | project recommendationId = 'e544520b-8505-7841-9e77-1f1974ee86ec', name, id, tags"),
    },
    # APRL "Convert Classic Deployments" (Application Insights) - a false pass
    "dac421ec-2832-4c37-839e-b6dc5a38f2fa": {
        "defect": r"where\s+IngestionMode\s*=~\s*'ApplicationInsights'",
        "reason": "The upstream query misses classic components that export with diagnostic settings "
                  "('ApplicationInsightsWithDiagnosticSettings'); only 'LogAnalytics' is workspace-based.",
        "query": (
                 'resources'
                 " | where type =~ 'microsoft.insights/components'"
                 " | where tostring(properties.IngestionMode) in~ ('ApplicationInsights', "
                 "'ApplicationInsightsWithDiagnosticSettings')"
                 " | project recommendationId = 'dac421ec-2832-4c37-839e-b6dc5a38f2fa', name, id, tags, "
                 "param1 = 'ApplicationInsightsDeploymentType: Classic'"),
    },
    # WAF / AVS "Ensure alerts are configured for Azure Service Health alerts and notifications"
    "64b0d934-a348-4726-be79-d6b5c3a36495": {
        "defect": r"^\s*resources\s*\|\s*distinct\s+subscriptionId\s*\|\s*join",
        "reason": "The upstream query checks every subscription, although the item belongs to the Azure VMware Solution "
                  "guide. The corrected query checks only subscriptions with an Azure VMware Solution private cloud "
                  "(Service Health alerting in general is a separate finding).",
        "replace": [r"^\s*resources\s*\|\s*distinct\s+subscriptionId",
                    "resources | where type =~ 'microsoft.avs/privateclouds' | distinct subscriptionId"],
    },
}


# ----------------------------------------------------------------------------------------------
# Download / cache
# ----------------------------------------------------------------------------------------------
def _http_get(url: str, timeout: float = 60) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "azgovviz-assessment-plugin",
                                               "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


class ChecklistSource:
    """Resolves checklist files from a local clone (--checklists-path) or GitHub (cached)."""

    def __init__(self, ref: str = "main", local_path: Optional[str] = None, max_age_hours: float = 24):
        self.ref = ref
        self.local = Path(local_path).expanduser() if local_path else None
        self.cache = util.cache_dir() / "review-checklists" / util.slug(ref)
        self.max_age = max_age_hours * 3600
        self.commit: Optional[str] = None
        self.commit_date: Optional[str] = None

    def resolve_commit(self) -> None:
        if self.local:
            git = util.which("git")
            if git and (self.local / ".git").exists():
                proc = util.run([git, "-C", str(self.local), "log", "-1", "--format=%H|%cI"], timeout=30)
                if proc.returncode == 0 and "|" in proc.stdout:
                    self.commit, self.commit_date = proc.stdout.strip().split("|", 1)
            return
        meta_file = self.cache / "_commit.json"
        meta = util.read_json(meta_file, {})
        if meta and time.time() - meta.get("fetched", 0) < self.max_age:
            self.commit, self.commit_date = meta.get("sha"), meta.get("date")
            return
        try:
            data = json.loads(_http_get(API_COMMIT.format(ref=self.ref), timeout=20))
            self.commit = data.get("sha")
            self.commit_date = ((data.get("commit") or {}).get("committer") or {}).get("date")
            util.write_json(meta_file, {"sha": self.commit, "date": self.commit_date, "fetched": time.time()})
        except Exception as exc:  # GitHub API rate limit / offline: provenance is best effort
            util.debug(f"could not resolve review-checklists commit: {exc}")
            self.commit, self.commit_date = meta.get("sha"), meta.get("date")

    def path_for(self, key: str) -> str:
        if key in CATALOG:
            return CATALOG[key]["path"]
        if key.endswith(".json"):
            return key
        return f"checklists/{key}_checklist.en.json"

    def load(self, key: str) -> Dict[str, Any]:
        rel = self.path_for(key)
        if self.local:
            candidates = [self.local / rel, self.local / rel.replace("checklists/", "checklists-ext/")]
            for c in candidates:
                if c.exists():
                    return json.loads(c.read_text(encoding="utf-8-sig"))
            raise FileNotFoundError(f"checklist '{key}' not found under {self.local}")
        target = self.cache / rel
        fresh = target.exists() and time.time() - target.stat().st_mtime < self.max_age
        if not fresh:
            ref = self.commit or self.ref
            for path in (rel, rel.replace("checklists/", "checklists-ext/")):
                try:
                    raw = _http_get(RAW_BASE.format(ref=ref, path=path))
                    target = self.cache / path
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(raw)
                    break
                except urllib.error.HTTPError as exc:
                    if exc.code != 404:
                        raise
                except urllib.error.URLError as exc:
                    if (self.cache / rel).exists():
                        util.warn(f"offline - using cached copy of {rel} ({exc})")
                        target = self.cache / rel
                        break
                    raise
            else:
                raise FileNotFoundError(f"checklist '{key}' ({rel}) does not exist in {REPO}@{ref}")
        return json.loads(target.read_text(encoding="utf-8-sig"))

    def list_remote(self) -> List[str]:
        """All '*_checklist.en.json' keys available in the repo (falls back to the catalogue)."""
        try:
            data = json.loads(_http_get(API_TREE.format(ref=self.ref), timeout=30))
            keys = []
            for entry in data.get("tree", []):
                m = re.match(r"checklists(?:-ext)?/(.+)_checklist\.en\.json$", entry.get("path", ""))
                if m:
                    keys.append(m.group(1))
            return sorted(set(keys))
        except Exception:
            return sorted(CATALOG)


# ----------------------------------------------------------------------------------------------
# Evaluation
# ----------------------------------------------------------------------------------------------
def runnable_query(graph: Optional[str]) -> Optional[str]:
    if not graph or not isinstance(graph, str):
        return None
    code = "\n".join(l for l in graph.splitlines() if not l.strip().startswith("//")).strip()
    if not code:
        return None
    return graph.strip()


def corrected_query(item: Dict[str, Any], query: Optional[str]) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    """(query to run, correction applied). The correction is None when the upstream query is used as is;
    a correction without a query means the item is set aside for manual review."""
    fix = QUERY_CORRECTIONS.get(str(item.get("guid") or "").lower())
    if not query or not fix or not re.search(fix["defect"], query, re.I):
        return query, None
    if fix.get("replace"):  # a targeted edit of the upstream query
        pattern, repl = fix["replace"]
        return re.sub(pattern, lambda _: repl, query, count=1, flags=re.I), fix
    return fix.get("query"), fix


# `//` comments, but not the `//` of a URL inside a string literal (https://...)
_KQL_COMMENT = re.compile(r"(?<![:'\"])//.*$", re.M)


def query_mode(item: Dict[str, Any], query: str, rows: Optional[List[Dict[str, Any]]] = None) -> str:
    """How rows are interpreted: per-row `compliant` verdicts, APRL (rows = non-compliant resources) or a listing."""
    if rows:
        columns = {str(k).lower() for k in rows[0]}
        if "compliant" in columns:
            return "compliant"
        if columns & {"recommendationid", "param1"}:
            return "aprl"
    code = _KQL_COMMENT.sub("", query)  # comments such as `// Find "Non-compliant" VMs` must not decide the mode
    if item.get("aprlGuid") or re.search(r"\brecommendationId\b", code, re.I):
        return "aprl"
    if re.search(r"\bcompliant\b", code):
        return "compliant"
    if re.search(r"\bparam1\b", code, re.I):  # ALZ/WAF items written APRL-style (`Param1=...`)
        return "aprl"
    return "listing"


def _row_verdict(row: Dict[str, Any]) -> Optional[bool]:
    for key, value in row.items():
        if str(key).lower() == "compliant":
            return util.truthy(value)
    return None


def _phantom(row: Dict[str, Any]) -> bool:
    """A row that names nothing but a verdict: `summarize arg_max(id, *)` without `by` returns one even when no
    resource matched, which must not count as a non-compliant resource. (A lone `compliant` column is a real
    tenant-level verdict.)"""
    others = [v for k, v in row.items() if str(k).lower() != "compliant"]
    return bool(others) and all(v is None or v == "" for v in others)


def _row_id(row: Dict[str, Any]) -> str:
    for key in ("id", "resourceId", "ResourceId", "resource_id", "acrId", "vaultId", "Id"):
        if row.get(key):
            return str(row[key])
    for key, value in row.items():
        if isinstance(value, str) and value.lower().startswith("/subscriptions/"):
            return value
    parts = [str(row.get(k)) for k in ("subscriptionId", "resourceGroup", "name") if row.get(k)]
    return "/".join(parts) if parts else json.dumps(row, sort_keys=True, default=str)[:200]


def _row_name(row: Dict[str, Any], rid: str) -> str:
    for key in ("name", "Name", "resourceName", "acrName", "vaultName", "principalName", "roleName"):
        if row.get(key):
            return str(row[key])
    return rid.rstrip("/").split("/")[-1] if rid.startswith("/") else rid[:80]


def _compact_row(row: Dict[str, Any]) -> Dict[str, Any]:
    out = {}
    for k, v in row.items():
        if k in ("tags",) or v is None or v == "":
            continue
        if isinstance(v, (dict, list)):
            v = json.dumps(v, default=str)
        v = str(v)
        out[k] = v if len(v) <= 300 else v[:297] + "..."
    return out


def target_types(item: Dict[str, Any]) -> List[str]:
    types: List[str] = []
    for key in ("recommendationResourceType", "arm-service"):
        value = item.get(key)
        if isinstance(value, str) and "/" in value:
            types.append(value.lower())
    service = item.get("service")
    if isinstance(service, str):
        if "/" in service:
            types.append(service.lower())
        else:
            types += SERVICE_TYPES.get(service.strip().lower(), [])
    return [CONTAINER_TYPES.get(t, t) for t in dict.fromkeys(types)]


def evaluate_rows(item: Dict[str, Any], query: str, rows: List[Dict[str, Any]],
                  type_counts: Optional[Dict[str, int]], truncated: bool = False,
                  max_resources: int = 60) -> Dict[str, Any]:
    rows = [r for r in rows if not _phantom(r)]
    mode = query_mode(item, query, rows)
    types = target_types(item)
    known_types = type_counts is not None and bool(types)
    type_total = sum((type_counts or {}).get(t, 0) for t in types) if known_types else None

    resources: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        rid = _row_id(row)
        entry = resources.setdefault(rid, {"id": rid, "name": _row_name(row, rid), "compliant": None,
                                           "details": _compact_row(row)})
        if mode == "compliant":
            verdict = _row_verdict(row)
            # a resource is non-compliant if any of its rows is non-compliant
            if verdict is False or entry["compliant"] is None:
                entry["compliant"] = verdict
        elif mode == "aprl":
            entry["compliant"] = False

    compliant = sum(1 for r in resources.values() if r["compliant"] is True)
    non_compliant = sum(1 for r in resources.values() if r["compliant"] is False)
    unknown = sum(1 for r in resources.values() if r["compliant"] is None)

    if mode == "aprl":
        if type_total is not None and type_total == 0 and not resources:
            status = "not_applicable"
        elif not resources:
            status = "compliant" if type_total else "no_data"
            compliant = type_total or 0
        else:
            compliant = max((type_total or 0) - non_compliant, 0)
            status = "partial" if compliant > 0 else "non_compliant"
    elif mode == "compliant":
        if not resources:
            status = "not_applicable" if (type_total == 0) else "no_data"
        elif non_compliant and compliant:
            status = "partial"
        elif non_compliant:
            status = "non_compliant"
        elif compliant:
            status = "compliant"
        else:
            status = "info"
    else:
        status = "info" if resources else ("not_applicable" if type_total == 0 else "no_data")

    ordered = sorted(resources.values(), key=lambda r: (r["compliant"] is not False, r["compliant"] is not None,
                                                        r["name"].lower()))
    return {
        "mode": mode,
        "status": status,
        "counts": {"compliant": compliant, "nonCompliant": non_compliant, "unknown": unknown,
                   "rows": len(rows), "resources": len(resources), "typeTotal": type_total},
        "truncated": truncated,
        "resources": ordered[:max_resources],
        "resourcesOmitted": max(0, len(ordered) - max_resources),
        "targetTypes": types,
        # every per-resource verdict, for the workbook export; removed before results.json is written
        "_verdicts": [[r["id"], r["compliant"]] for r in ordered if r["compliant"] is not None],
    }


class ChecklistEvaluator:
    def __init__(self, client: ResourceGraphClient, source: ChecklistSource,
                 type_counts: Optional[Dict[str, int]] = None, workers: int = 4,
                 raw_dir: Optional[Path] = None):
        self.client = client
        self.source = source
        self.type_counts = type_counts
        self.workers = max(1, workers)
        self.raw_dir = raw_dir
        self._cache: Dict[str, Tuple[List[Dict[str, Any]], bool, Optional[str], float]] = {}

    def _run(self, query: str) -> Tuple[List[Dict[str, Any]], bool, Optional[str], float]:
        key = hashlib.sha1(" ".join(query.split()).encode("utf-8")).hexdigest()
        if key in self._cache:
            return self._cache[key]
        try:
            res = self.client.query(query)
            out = (res.rows, res.truncated, None, res.elapsed)
        except ArgError as exc:
            out = ([], False, str(exc), 0.0)
        except Exception as exc:  # network edge cases must not abort the whole checklist
            out = ([], False, f"{type(exc).__name__}: {exc}", 0.0)
        self._cache[key] = out
        if self.raw_dir is not None:
            util.write_json(self.raw_dir / f"{key}.json",
                            {"query": query, "error": out[2], "truncated": out[1], "rows": out[0][:500]})
        return out

    def evaluate(self, keys: Iterable[str], progress: bool = True) -> Dict[str, Any]:
        loaded: List[Tuple[str, Dict[str, Any]]] = []
        for key in keys:
            try:
                loaded.append((key, self.source.load(key)))
            except Exception as exc:
                util.warn(f"checklist '{key}' could not be loaded: {exc}")
        jobs: List[str] = []
        for _, data in loaded:
            for item in data.get("items", []):
                q, _ = corrected_query(item, runnable_query(item.get("graph")))
                if q:
                    jobs.append(q)
        unique = list(dict.fromkeys(jobs))
        util.log(f"review-checklists: {len(loaded)} checklist(s), {len(jobs)} automated items, "
                 f"{len(unique)} unique Resource Graph queries")
        started = time.time()
        done = 0
        with cf.ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures = {pool.submit(self._run, q): q for q in unique}
            for fut in cf.as_completed(futures):
                done += 1
                fut.result()
                if progress and (done % 25 == 0 or done == len(unique)):
                    util.log(f"  ARG queries {done}/{len(unique)} ({time.time() - started:.0f}s)")

        checklists = []
        for key, data in loaded:
            checklists.append(self._build(key, data))
        corrections: Dict[str, Dict[str, Any]] = {}
        for c in checklists:
            for i in c["items"]:
                if i.get("correction"):
                    entry = corrections.setdefault(i["guid"], {"guid": i["guid"], "id": i.get("id"), "text": i["text"],
                                                               **{k: i["correction"][k] for k in ("action", "reason")},
                                                               "checklists": []})
                    entry["checklists"].append(c["key"])
        if corrections:
            util.log(f"review-checklists: {len(corrections)} upstream quer{'y' if len(corrections) == 1 else 'ies'} "
                     "corrected or set aside (they do not test what their item says)")
        return {
            "schema": "azgov-assess/checklists@1",
            "generatedAt": util.iso(),
            "source": {"repo": f"https://github.com/{REPO}", "ref": self.source.ref,
                       "commit": self.source.commit, "commitDate": self.source.commit_date,
                       "local": str(self.source.local) if self.source.local else None},
            "scope": self.client.scope.describe(),
            "queries": {"unique": len(unique), "apiCalls": self.client.calls,
                        "durationSec": round(time.time() - started, 1)},
            "corrections": list(corrections.values()),
            "checklists": checklists,
        }

    def _build(self, key: str, data: Dict[str, Any]) -> Dict[str, Any]:
        meta = data.get("metadata") or {}
        items_out = []
        for item in data.get("items", []):
            upstream = runnable_query(item.get("graph"))
            q, fix = corrected_query(item, upstream)
            base = {
                "guid": item.get("guid"), "id": item.get("id"),
                "category": item.get("category") or item.get("recommendationControl") or item.get("waf") or "General",
                "subcategory": item.get("subcategory") or item.get("checklist") or item.get("service"),
                "text": (item.get("text") or "").strip(),
                "description": (item.get("description") or item.get("longDescription") or "").strip(),
                "severity": (item.get("severity") or item.get("recommendationImpact") or "Medium").title(),
                "waf": item.get("waf"), "service": item.get("service"),
                "link": item.get("link") or _first_link(item.get("learnMoreLink")),
                "training": item.get("training"),
                "benefits": item.get("potentialBenefits"),
            }
            if fix:
                base["correction"] = {"action": "corrected" if q else "set aside", "reason": fix["reason"],
                                      "upstreamQuery": upstream}
            if not q:
                base.update({"automated": False, "status": "manual", "mode": None})
            else:
                rows, truncated, error, elapsed = self._run(q)
                if error:
                    base.update({"automated": True, "status": "error", "error": error, "query": q, "mode": None})
                else:
                    base.update({"automated": True, "query": q, "durationSec": round(elapsed, 2),
                                 **evaluate_rows(item, q, rows, self.type_counts, truncated)})
            items_out.append(base)
        return {
            "key": key,
            "title": CATALOG.get(key, {}).get("title") or meta.get("name") or key,
            "name": meta.get("name") or key,
            "state": meta.get("state"),
            "timestamp": meta.get("timestamp"),
            "file": self.source.path_for(key),
            "summary": summarize(items_out),
            "items": items_out,
        }


def _first_link(links: Any) -> Optional[str]:
    if isinstance(links, list) and links:
        first = links[0]
        return first.get("url") if isinstance(first, dict) else str(first)
    return None


def summarize(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    counts = Counter(i["status"] for i in items)
    sev_fail = Counter(i["severity"] for i in items if i["status"] in ("non_compliant", "partial"))
    evaluated = counts["compliant"] + counts["partial"] + counts["non_compliant"]
    weight_total = weight_pass = 0.0
    res_ok = res_bad = 0
    for i in items:
        if i["status"] not in ("compliant", "partial", "non_compliant"):
            continue
        w = SEVERITY_WEIGHT.get(i["severity"].lower(), 2)
        weight_total += w
        c = i.get("counts") or {}
        res_ok += c.get("compliant", 0)
        res_bad += c.get("nonCompliant", 0)
        if i["status"] == "compliant":
            weight_pass += w
        elif i["status"] == "partial":
            tot = c.get("compliant", 0) + c.get("nonCompliant", 0)
            weight_pass += w * (c.get("compliant", 0) / tot if tot else 0.5)
    by_category: Dict[str, Counter] = defaultdict(Counter)
    for i in items:
        by_category[i["category"]][i["status"]] += 1
    return {
        "items": len(items),
        "automated": sum(1 for i in items if i.get("automated")),
        "evaluated": evaluated,
        "statusCounts": {s: counts.get(s, 0) for s in STATUSES},
        "failedBySeverity": {s: sev_fail.get(s, 0) for s in ("High", "Medium", "Low")},
        "score": round(100 * weight_pass / weight_total, 1) if weight_total else None,
        "resourceCompliance": {"compliant": res_ok, "nonCompliant": res_bad,
                               "percent": round(100 * res_ok / (res_ok + res_bad), 1) if (res_ok + res_bad) else None},
        "byCategory": {cat: {s: c.get(s, 0) for s in STATUSES} for cat, c in sorted(by_category.items())},
    }


def official_graph_results(results: Dict[str, Any], key: str) -> Dict[str, Any]:
    """Export in the format of review-checklists' checklist_graph.sh (importable into the Excel sheet)."""
    checks = []
    for cl in results.get("checklists", []):
        if cl["key"] != key:
            continue
        for item in cl["items"]:
            verdicts = item.get("_verdicts")
            if verdicts is None:  # results.json read back from disk: only the listed resources are available
                verdicts = [[r["id"], r.get("compliant")] for r in item.get("resources") or []]
            for rid, compliant in verdicts:
                if compliant is None:
                    continue
                checks.append({"guid": item["guid"], "compliant": "true" if compliant else "false", "id": rid})
    return {"metadata": {"format": "json", "timestamp": results.get("generatedAt")}, "checks": checks}


def strip_private(results: Dict[str, Any]) -> Dict[str, Any]:
    """Drop in-memory-only keys (full verdict lists) before results.json is written."""
    for cl in results.get("checklists", []):
        for item in cl.get("items", []):
            item.pop("_verdicts", None)
    return results
