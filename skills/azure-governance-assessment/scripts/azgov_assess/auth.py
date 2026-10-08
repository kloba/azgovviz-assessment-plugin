"""Access-token acquisition for Azure Resource Manager.

The engine never stores credentials. It borrows a short-lived ARM token from whichever
signed-in tool is available, in this order (``--auth auto``):

1. ``AZURE_ACCESS_TOKEN`` environment variable (CI / advanced use)
2. Azure CLI       ``az account get-access-token --tenant <tenant>``
3. Az PowerShell   ``Get-AzAccessToken -TenantId <tenant>`` (same context AzGovViz uses)
"""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from . import util

ARM_RESOURCE = "https://management.azure.com/"


class AuthError(RuntimeError):
    """Raised when no provider can produce a token. Message is user-actionable."""


@dataclass
class Token:
    value: str
    expires_at: float  # epoch seconds
    provider: str

    def valid(self, skew: float = 300) -> bool:
        return time.time() < self.expires_at - skew


def _az_cli_token(tenant_id: Optional[str]) -> Token:
    az = util.which("az")
    if not az:
        raise AuthError("Azure CLI (az) is not installed")
    cmd = [az, "account", "get-access-token", "--resource", ARM_RESOURCE, "-o", "json"]
    if tenant_id:
        cmd += ["--tenant", tenant_id]
    proc = util.run(cmd, timeout=90)
    if proc.returncode != 0:
        raise AuthError(f"az CLI could not get a token: {_first_line(proc.stderr)}")
    data = json.loads(proc.stdout)
    exp = data.get("expires_on")
    expires_at = float(exp) if exp else (
        (util.parse_iso(data.get("expiresOn")) or util.utcnow()).timestamp())
    return Token(data["accessToken"], expires_at, "azcli")


# Values reach PowerShell through environment variables, never by string substitution into the script.
_PWSH_TOKEN_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$WarningPreference = 'SilentlyContinue'
Import-Module Az.Accounts -ErrorAction Stop
$p = @{ ResourceUrl = $env:AZGOV_PS_RESOURCE }
if ($env:AZGOV_PS_TENANT) { $p.TenantId = $env:AZGOV_PS_TENANT }
$cmd = Get-Command Get-AzAccessToken
if ($cmd.Parameters.ContainsKey('AsSecureString')) { $p.AsSecureString = $true }
$t = Get-AzAccessToken @p
$tok = if ($t.Token -is [securestring]) { [System.Net.NetworkCredential]::new('', $t.Token).Password } else { $t.Token }
[pscustomobject]@{ token = $tok; expiresOn = $t.ExpiresOn.UtcDateTime.ToString('o') } | ConvertTo-Json -Compress
"""


def pwsh_env(**values: Optional[str]) -> Dict[str, str]:
    """Process environment plus AZGOV_PS_<NAME> variables for a PowerShell child process."""
    env = dict(os.environ)
    for key, value in values.items():
        env[f"AZGOV_PS_{key.upper()}"] = value or ""
    return env


def _az_pwsh_token(tenant_id: Optional[str]) -> Token:
    pwsh = util.which("pwsh")
    if not pwsh:
        raise AuthError("PowerShell 7 (pwsh) is not installed")
    proc = util.run([pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", _PWSH_TOKEN_SCRIPT],
                    timeout=120, env=pwsh_env(resource=ARM_RESOURCE, tenant=tenant_id))
    out = (proc.stdout or "").strip().splitlines()
    payload = next((line for line in reversed(out) if line.startswith("{")), None)
    if proc.returncode != 0 or not payload:
        raise AuthError(f"Az PowerShell could not get a token: {_first_line(proc.stderr or proc.stdout)}")
    data = json.loads(payload)
    expires = util.parse_iso(data.get("expiresOn"))
    return Token(data["token"], expires.timestamp() if expires else time.time() + 1800, "azpwsh")


def _env_token(_tenant_id: Optional[str]) -> Token:
    value = os.environ.get("AZURE_ACCESS_TOKEN")
    if not value:
        raise AuthError("AZURE_ACCESS_TOKEN is not set")
    return Token(value.strip(), time.time() + 1800, "env")


PROVIDERS: Dict[str, Callable[[Optional[str]], Token]] = {
    "env": _env_token,
    "azcli": _az_cli_token,
    "azpwsh": _az_pwsh_token,
}


def _first_line(text: str) -> str:
    for line in (text or "").splitlines():
        line = line.strip()
        if line and not line.startswith("WARNING"):
            return line[:400]
    return "unknown error"


class TokenProvider:
    """Thread-safe cached ARM token for one tenant."""

    def __init__(self, tenant_id: Optional[str], mode: str = "auto"):
        if tenant_id and not util.is_tenant(tenant_id):
            raise AuthError(f"Not a tenant ID or domain: {tenant_id!r}")
        self.tenant_id = tenant_id
        self.mode = mode
        self._token: Optional[Token] = None
        self._lock = threading.Lock()
        self.errors: List[str] = []

    @property
    def provider_name(self) -> str:
        return self._token.provider if self._token else "none"

    def order(self) -> List[str]:
        if self.mode != "auto":
            return [self.mode]
        order = []
        if os.environ.get("AZURE_ACCESS_TOKEN"):
            order.append("env")
        order += ["azcli", "azpwsh"]
        return order

    def get(self, force_refresh: bool = False) -> str:
        with self._lock:
            if self._token and self._token.valid() and not force_refresh:
                return self._token.value
            preferred = [self._token.provider] if self._token else []
            self.errors = []
            for name in preferred + [n for n in self.order() if n not in preferred]:
                try:
                    self._token = PROVIDERS[name](self.tenant_id)
                    util.debug(f"ARM token acquired via {name}")
                    return self._token.value
                except AuthError as exc:
                    self.errors.append(f"{name}: {exc}")
                except Exception as exc:  # unexpected tool output
                    self.errors.append(f"{name}: {type(exc).__name__}: {exc}")
            raise AuthError(self.login_hint())

    def login_hint(self) -> str:
        tenant = self.tenant_id or "<tenant-id>"
        details = "\n  - ".join(self.errors) if self.errors else "no provider attempted"
        return ("Could not obtain an Azure Resource Manager token for tenant "
                f"{tenant}.\n  - {details}\n"
                "Sign in with ONE of:\n"
                f"  pwsh -c \"Connect-AzAccount -Tenant {tenant}\"   (also required by AzGovViz)\n"
                f"  az login --tenant {tenant}")


def list_tenants() -> Dict[str, dict]:
    """Tenants and subscriptions visible to the signed-in tools (az CLI and/or Az PowerShell)."""
    tenants: Dict[str, dict] = {}

    def add(tid: str, name: Optional[str], domain: Optional[str], sub: Optional[dict], source: str) -> None:
        t = tenants.setdefault(tid, {"tenantId": tid, "displayName": name, "defaultDomain": domain,
                                     "subscriptions": {}, "sources": set()})
        t["displayName"] = t["displayName"] or name
        t["defaultDomain"] = t["defaultDomain"] or domain
        t["sources"].add(source)
        if sub and sub.get("id"):
            t["subscriptions"][sub["id"]] = sub

    if util.which("az"):
        proc = util.run(["az", "account", "list", "--all", "-o", "json"], timeout=60)
        if proc.returncode == 0:
            for s in json.loads(proc.stdout or "[]"):
                add(s.get("tenantId"), s.get("tenantDisplayName"), s.get("tenantDefaultDomain"),
                    {"id": s.get("id"), "name": s.get("name"), "state": s.get("state"),
                     "user": (s.get("user") or {}).get("name")}, "azcli")
    if util.which("pwsh"):
        script = ("$ErrorActionPreference='SilentlyContinue'; $WarningPreference='SilentlyContinue';"
                  "Import-Module Az.Accounts; Get-AzContext -ListAvailable | ForEach-Object { "
                  "[pscustomobject]@{ tenantId=$_.Tenant.Id; subId=$_.Subscription.Id; subName=$_.Subscription.Name;"
                  " state=$_.Subscription.State; account=$_.Account.Id } } | ConvertTo-Json -Compress -Depth 3")
        proc = util.run(["pwsh", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script], timeout=90)
        text = (proc.stdout or "").strip()
        if proc.returncode == 0 and text:
            rows = json.loads(text)
            for r in rows if isinstance(rows, list) else [rows]:
                if r.get("tenantId"):
                    add(r["tenantId"], None, None,
                        {"id": r.get("subId"), "name": r.get("subName"), "state": r.get("state"),
                         "user": r.get("account")} if r.get("subId") else None, "azpwsh")
    for t in tenants.values():
        t["sources"] = sorted(t["sources"])
        t["subscriptions"] = sorted(t["subscriptions"].values(), key=lambda s: (s.get("name") or ""))
    return tenants
