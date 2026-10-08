"""Network findings: internet exposure, segmentation, topology and capacity (Resource Graph + AzGovViz)."""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List

from .. import util
from ..analysis import Finding, analyzer, evidence
from .common import ref, short_id

DOMAIN = "network"
REF_NSG = ref("Network security best practices", "/azure/security/fundamentals/network-best-practices")
REF_BASTION = ref("Azure Bastion", "/azure/bastion/bastion-overview")
REF_TOPOLOGY = ref("ALZ design area: network topology and connectivity",
                   "/azure/cloud-adoption-framework/ready/azure-best-practices/define-an-azure-network-topology")
REF_PE = ref("Azure Private Link and private endpoints", "/azure/private-link/private-endpoint-overview")
REF_DDOS = ref("Azure DDoS Protection overview", "/azure/ddos-protection/ddos-protection-overview")
SPECIAL_SUBNETS = {"gatewaysubnet", "azurefirewallsubnet", "azurefirewallmanagementsubnet", "azurebastionsubnet",
                   "routeserversubnet", "azureapplicationgatewaysubnet"}


MGMT_PORTS = (22, 3389)
_INTERNET_SOURCES = {"*", "0.0.0.0/0", "internet", "any"}


def _port_specs(value: str) -> List[str]:
    """'22', '*', '1000-2000' or a JSON-ish list of those (destinationPortRanges / sourceAddressPrefixes)."""
    return [p.strip().strip('"').strip() for p in str(value or "").strip("[]").split(",") if p.strip().strip('"').strip()]


def covers_mgmt_port(port: str) -> bool:
    for spec in _port_specs(port):
        if spec == "*":
            return True
        lo, _, hi = spec.partition("-")
        try:
            low, high = int(lo), int(hi or lo)
        except ValueError:
            continue
        if any(low <= p <= high for p in MGMT_PORTS):
            return True
    return False


def from_internet(src: str) -> bool:
    return any(s.lower() in _INTERNET_SOURCES for s in _port_specs(src))


@analyzer
def network_findings(ctx) -> List[Finding]:
    out: List[Finding] = []

    # NET-001 management ports open to the internet
    open_rules = ctx.inv("nsgOpenInbound")
    if open_rules is not None:
        open_rules = [r for r in open_rules if covers_mgmt_port(r.get("port")) and from_internet(r.get("src"))]
        out.append(Finding(
            "NET-001", DOMAIN, "Management ports (SSH/RDP) open to the internet", "high",
            "fail" if open_rules else "pass",
            f"{len(open_rules)} NSG rules allow inbound SSH/RDP (or any port) from the internet "
            f"across {len({r.get('nsg') for r in open_rules})} NSGs." if open_rules else
            "No NSG rule allows SSH/RDP from the internet.",
            details="Internet-exposed management ports are brute-forced within minutes of exposure and are a top "
                    "initial-access vector for ransomware.",
            recommendation="Remove the rules; use Azure Bastion or Defender for Servers just-in-time VM access, and "
                           "deny inbound management ports from the internet with policy.",
            evidence=evidence(["NSG", "Rule", "Port(s)", "Source", "Subscription"],
                              [[r.get("nsg"), r.get("rule"), r.get("port"), r.get("src"), ctx.sub_name(r.get("subscriptionId"))]
                               for r in open_rules]),
            references=[REF_NSG, REF_BASTION], source="Resource Graph", effort="low"))

    vnets = ctx.t("VirtualNetworks")
    subnets = ctx.t("VirtualNetworkSubnets")
    peerings = ctx.t("VirtualNetworkPeerings")

    # NET-002 topology
    if vnets:
        peer_counts = [(v.get("VNet"), util.to_int(v.get("PeeringsCount"))) for v in vnets]
        hubs = [v for v, n in peer_counts if n >= 2]
        isolated = [v for v, n in peer_counts if n == 0]
        if len(vnets) == 1:
            status, summary = "info", "A single virtual network - no hub-and-spoke topology needed yet."
        elif hubs:
            status, summary = "pass", (f"Hub-and-spoke pattern detected: {len(hubs)} hub VNet(s) "
                                       f"({', '.join(hubs[:3])}); {len(isolated)} of {len(vnets)} VNets are not peered.")
        else:
            status, summary = "warn", f"{len(vnets)} VNets but no hub with multiple peerings; {len(isolated)} are isolated."
        out.append(Finding(
            "NET-002", DOMAIN, "Network topology (hub-and-spoke / Virtual WAN)", "medium", status, summary,
            details="A hub (or Virtual WAN) centralises egress filtering, DNS, hybrid connectivity and inspection; "
                    "isolated VNets each reinvent these controls.",
            recommendation="Adopt hub-and-spoke or Virtual WAN; peer workload VNets to the hub and route egress through "
                           "Azure Firewall/NVA.",
            evidence=evidence(["VNet", "Subscription", "Peerings", "Address space", "DDoS"],
                              [[v.get("VNet"), v.get("SubscriptionName"), util.to_int(v.get("PeeringsCount")),
                                v.get("AddressSpaceAddressPrefixes"), v.get("DdosProtection")] for v in vnets]),
            references=[REF_TOPOLOGY], source="AzGovViz VirtualNetworks", effort="high"))

    # NET-003 subnets without NSG
    if subnets:
        no_nsg = [s for s in subnets if not (s.get("NetworkSecurityGroup") or "").strip()
                  and (s.get("SubnetName") or "").lower() not in SPECIAL_SUBNETS]
        out.append(Finding(
            "NET-003", DOMAIN, "Subnets without a network security group", "medium",
            "pass" if not no_nsg else ("warn" if len(no_nsg) <= 2 else "fail"),
            f"{len(no_nsg)} of {len(subnets)} subnets (excluding gateway/firewall/bastion subnets) have no NSG.",
            details="Subnets without NSGs allow unrestricted east-west traffic, so one compromised workload can reach "
                    "every other.",
            recommendation="Associate an NSG with every workload subnet (policy: 'Subnets should be associated with a "
                           "Network Security Group').",
            evidence=evidence(["Subnet", "VNet", "Subscription", "Prefix"],
                              [[s.get("SubnetName"), s.get("VNet"), s.get("SubscriptionName"), s.get("SubnetPrefix")] for s in no_nsg]),
            references=[REF_NSG], source="AzGovViz VirtualNetworkSubnets", effort="low"))

        # NET-004 IP exhaustion
        critical = [s for s in subnets if (s.get("SubnetIPAddressUsageCritical") or "").lower() == "true"]
        out.append(Finding(
            "NET-004", DOMAIN, "Subnet IP address capacity", "low",
            "warn" if critical else "pass",
            f"{len(critical)} subnets are above the IP usage threshold." if critical else
            "No subnet is close to IP exhaustion.",
            details="Exhausted subnets block scale-out, upgrades and new private endpoints.",
            recommendation="Plan larger address spaces or add subnets before scale events; keep 20%+ headroom.",
            evidence=evidence(["Subnet", "VNet", "Used %", "Available IPs"],
                              [[s.get("SubnetName"), s.get("VNet"), s.get("UsedIPAddressesPercent"), s.get("AvailableIPAddresses")]
                               for s in critical]),
            references=[REF_TOPOLOGY], source="AzGovViz VirtualNetworkSubnets", effort="medium"))

    # NET-005 private endpoints for PaaS data stores
    sa = ctx.inv("storageAccounts") or []
    kv = ctx.inv("keyVaults") or []
    pes = ctx.t("PrivateEndpoints")
    if (sa or kv) and ctx.azgv:
        # one row per endpoint connection (blob + file + queue on one account = 3 rows): count distinct targets
        targets: Dict[str, set] = defaultdict(set)
        for p in pes:
            targets[(p.get("ResourceType") or "").lower()].add(
                (p.get("ResourceId") or p.get("Resource") or p.get("PEName") or "").lower())
        paas = len(sa) + len(kv)
        with_pe = len(targets.get("microsoft.storage/storageaccounts", set())) + \
            len(targets.get("microsoft.keyvault/vaults", set()))
        out.append(Finding(
            "NET-005", DOMAIN, "Private connectivity for PaaS services", "low",
            "pass" if paas and with_pe >= paas else ("warn" if pes else "info"),
            f"{len(pes)} private endpoints in the estate; {with_pe} connect storage accounts/key vaults "
            f"(out of {paas}).",
            details="Private endpoints keep data-plane traffic on the Microsoft backbone and allow disabling public "
                    "network access entirely.",
            recommendation="Use private endpoints with centralised private DNS zones (policy-driven) for data services.",
            evidence=evidence(["Private endpoint", "Target type", "Target", "Subscription"],
                              [[p.get("PEName"), p.get("ResourceType"), p.get("Resource"), p.get("PESubscriptionName")] for p in pes]),
            references=[REF_PE], source="AzGovViz PrivateEndpoints", effort="medium"))

    # NET-006 DDoS on internet-facing VNets (informational)
    pips = ctx.inv("publicIps") or []
    if vnets and pips:
        protected = [v for v in vnets if (v.get("DdosProtection") or "").lower() == "true"]
        out.append(Finding(
            "NET-006", DOMAIN, "DDoS protection for internet-facing workloads", "low",
            "pass" if protected else "info",
            f"{len(pips)} public IP addresses; {len(protected)} of {len(vnets)} VNets have DDoS Network Protection.",
            details="Basic infrastructure protection is always on; DDoS Network/IP Protection adds adaptive tuning, "
                    "telemetry, rapid response and cost protection for public-facing production workloads.",
            recommendation="Enable DDoS IP or Network Protection for production public endpoints (not needed for labs).",
            evidence=evidence(["Public IP", "SKU", "Attached", "Subscription"],
                              [[p.get("name"), p.get("sku"), p.get("attached"), ctx.sub_name(p.get("subscriptionId"))] for p in pips]),
            references=[REF_DDOS], source="AzGovViz VirtualNetworks / Resource Graph", effort="medium"))
    return out
