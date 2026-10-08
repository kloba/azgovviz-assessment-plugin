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
                q = runnable_query(item.get("graph"))
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
        return {
            "schema": "azgov-assess/checklists@1",
            "generatedAt": util.iso(),
            "source": {"repo": f"https://github.com/{REPO}", "ref": self.source.ref,
                       "commit": self.source.commit, "commitDate": self.source.commit_date,
                       "local": str(self.source.local) if self.source.local else None},
            "scope": self.client.scope.describe(),
            "queries": {"unique": len(unique), "apiCalls": self.client.calls,
                        "durationSec": round(time.time() - started, 1)},
            "checklists": checklists,
        }

    def _build(self, key: str, data: Dict[str, Any]) -> Dict[str, Any]:
        meta = data.get("metadata") or {}
        items_out = []
        for item in data.get("items", []):
            q = runnable_query(item.get("graph"))
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
    return {"metadata": {"format": "list", "timestamp": results.get("generatedAt")}, "checks": checks}


def strip_private(results: Dict[str, Any]) -> Dict[str, Any]:
    """Drop in-memory-only keys (full verdict lists) before results.json is written."""
    for cl in results.get("checklists", []):
        for item in cl.get("items", []):
            item.pop("_verdicts", None)
    return results
