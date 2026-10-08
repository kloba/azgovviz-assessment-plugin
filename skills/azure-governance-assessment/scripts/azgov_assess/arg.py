"""Minimal Azure Resource Graph REST client (stdlib only).

Handles paging ($skipToken), per-user quota headers, 429/5xx retries and token refresh.
Scope is either a list of management groups or a list of subscriptions.
"""

from __future__ import annotations

import http.client
import json
import random
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from . import util
from .auth import TokenProvider

ARG_URL = "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01"
ARM_BASE = "https://management.azure.com"


class ArgError(RuntimeError):
    def __init__(self, message: str, status: Optional[int] = None, code: Optional[str] = None):
        super().__init__(message)
        self.status = status
        self.code = code


@dataclass
class Scope:
    management_groups: List[str] = field(default_factory=list)
    subscriptions: List[str] = field(default_factory=list)

    def body(self) -> Dict[str, Any]:
        if self.subscriptions:
            return {"subscriptions": list(self.subscriptions)}
        if self.management_groups:
            return {"managementGroups": list(self.management_groups)}
        return {}

    def describe(self, tenant_id: str = "") -> str:
        if self.subscriptions:
            return f"{len(self.subscriptions)} selected subscription(s)"
        if self.management_groups:
            if tenant_id and [m.lower() for m in self.management_groups] == [tenant_id.lower()]:
                return "Whole tenant (Tenant Root Group)"
            return "Management group " + ", ".join(self.management_groups)
        return "All subscriptions visible to the signed-in identity"


@dataclass
class QueryResult:
    rows: List[Dict[str, Any]]
    truncated: bool = False
    total_records: Optional[int] = None
    elapsed: float = 0.0


class _Quota:
    """Honours x-ms-user-quota-remaining / x-ms-user-quota-resets-after across threads."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._blocked_until = 0.0

    def wait(self) -> None:
        while True:
            with self._lock:
                delay = self._blocked_until - time.time()
            if delay <= 0:
                return
            time.sleep(min(delay, 5))

    def update(self, headers: Any) -> None:
        try:
            remaining = int(headers.get("x-ms-user-quota-remaining", "99"))
        except (TypeError, ValueError):
            remaining = 99
        if remaining <= 1:
            self.block(_parse_timespan(headers.get("x-ms-user-quota-resets-after")) or 5.0)

    def block(self, seconds: float) -> None:
        with self._lock:
            self._blocked_until = max(self._blocked_until, time.time() + seconds)


def _parse_timespan(value: Optional[str]) -> Optional[float]:
    if not value:
        return None
    try:
        h, m, s = value.split(":")
        return int(h) * 3600 + int(m) * 60 + float(s)
    except ValueError:
        return None


def _retry_after(headers: Any, attempt: int) -> float:
    """Seconds to wait: ARG quota reset, Retry-After (seconds or HTTP date), else exponential backoff."""
    headers = headers or {}
    wait = _parse_timespan(headers.get("x-ms-user-quota-resets-after"))
    if wait:
        return wait
    value = (headers.get("Retry-After") or "").strip()
    if value:
        try:
            return max(0.0, float(value))
        except ValueError:
            try:
                from email.utils import parsedate_to_datetime
                return max(0.0, (parsedate_to_datetime(value) - util.utcnow()).total_seconds())
            except (TypeError, ValueError):
                pass
    return 2 ** attempt + random.random()


def _error_body(exc: Any) -> str:
    try:
        return exc.read().decode("utf-8", "replace")
    except Exception:  # the error body itself can fail to arrive (IncompleteRead, reset)
        return ""


class ResourceGraphClient:
    def __init__(self, tokens: TokenProvider, scope: Scope, page_size: int = 1000,
                 max_rows: int = 5000, timeout: float = 120.0):
        self.tokens = tokens
        self.scope = scope
        self.page_size = page_size
        self.max_rows = max_rows
        self.timeout = timeout
        self._quota = _Quota()
        self.calls = 0

    # -- low level -------------------------------------------------------------------------
    def _post(self, body: Dict[str, Any], attempt_limit: int = 6) -> Dict[str, Any]:
        data = json.dumps(body).encode("utf-8")
        last_error: Optional[ArgError] = None
        for attempt in range(attempt_limit):
            self._quota.wait()
            token = self.tokens.get(force_refresh=attempt > 0 and last_error is not None and last_error.status == 401)
            req = urllib.request.Request(ARG_URL, data=data, method="POST", headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "User-Agent": "azgovviz-assessment-plugin",
            })
            try:
                self.calls += 1
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    self._quota.update(resp.headers)
                    return json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:  # before OSError: HTTPError is an OSError subclass
                payload = _error_body(exc)
                self._quota.update(exc.headers)
                code, message = _error_details(payload)
                last_error = ArgError(f"HTTP {exc.code} {code}: {message}", exc.code, code)
                if exc.code == 429 or exc.code >= 500:
                    if attempt + 1 < attempt_limit:
                        retry_after = min(_retry_after(exc.headers, attempt), 60)
                        util.debug(f"ARG throttled/server error ({exc.code}); retrying in {retry_after:.1f}s")
                        self._quota.block(retry_after)
                    continue
                if exc.code == 401 and attempt == 0:
                    continue
                raise last_error
            except (OSError, http.client.HTTPException, ValueError) as exc:
                # URLError, socket.timeout (not a TimeoutError on Python 3.9), resets, truncated/invalid JSON
                last_error = ArgError(f"network error: {type(exc).__name__}: {exc}")
                if attempt + 1 < attempt_limit:
                    time.sleep(min(2 ** attempt, 20))
        raise last_error or ArgError("ARG request failed")

    # -- public ----------------------------------------------------------------------------
    def query(self, kql: str, max_rows: Optional[int] = None) -> QueryResult:
        limit = max_rows or self.max_rows
        started = time.time()
        rows: List[Dict[str, Any]] = []
        skip_token: Optional[str] = None
        total = None
        while True:
            options: Dict[str, Any] = {"resultFormat": "objectArray",
                                       "$top": min(self.page_size, max(1, limit - len(rows)))}
            if skip_token:
                options["$skipToken"] = skip_token
            body = {"query": kql, "options": options, **self.scope.body()}
            payload = self._post(body)
            data = payload.get("data") or []
            if isinstance(data, dict):  # table format fallback
                cols = [c["name"] for c in data.get("columns", [])]
                data = [dict(zip(cols, r)) for r in data.get("rows", [])]
            rows.extend(data)
            total = payload.get("totalRecords", total)
            skip_token = payload.get("$skipToken")
            if not skip_token or len(rows) >= limit:
                break
        truncated = bool(skip_token) or (total is not None and total > len(rows))
        return QueryResult(rows=rows[:limit], truncated=truncated, total_records=total,
                           elapsed=time.time() - started)

    def arm_get(self, path: str, api_version: str, attempt_limit: int = 4) -> Dict[str, Any]:
        """Plain ARM GET (tenant metadata, hierarchy settings, budgets...) with retry on throttling/network errors."""
        sep = "&" if "?" in path else "?"
        url = f"{ARM_BASE}{path}{sep}api-version={api_version}"
        last_error: Optional[ArgError] = None
        for attempt in range(attempt_limit):
            refresh = attempt > 0 and last_error is not None and last_error.status == 401
            req = urllib.request.Request(url, headers={"Authorization": f"Bearer {self.tokens.get(force_refresh=refresh)}",
                                                       "User-Agent": "azgovviz-assessment-plugin"})
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                code, message = _error_details(_error_body(exc))
                last_error = ArgError(f"HTTP {exc.code} {code}: {message}", exc.code, code)
                if exc.code == 401 and attempt == 0:
                    continue  # token expired between calls: refresh once
                if exc.code != 429 and exc.code < 500:
                    raise last_error
                delay = _retry_after(exc.headers, attempt)
            except (OSError, http.client.HTTPException, ValueError) as exc:
                last_error = ArgError(f"network error: {type(exc).__name__}: {exc}")
                delay = 2 ** attempt + random.random()
            if attempt + 1 < attempt_limit:
                time.sleep(min(delay, 30))
        raise last_error or ArgError("ARM request failed")


def _error_details(payload: str) -> tuple:
    try:
        err = json.loads(payload).get("error") or {}
        details = err.get("details") or []
        detail_msg = "; ".join(d.get("message", "") for d in details if isinstance(d, dict) and d.get("message"))
        message = err.get("message", "") + (f" ({detail_msg})" if detail_msg else "")
        return err.get("code", "Error"), message.strip()[:1500]
    except (ValueError, AttributeError):
        return "Error", payload[:500]
