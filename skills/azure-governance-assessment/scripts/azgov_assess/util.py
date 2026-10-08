"""Shared helpers: logging, JSON I/O, subprocess, time and path utilities."""

from __future__ import annotations

import datetime as _dt
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterable, Optional, Sequence

_VERBOSE = os.environ.get("AZGOV_VERBOSE", "") not in ("", "0", "false", "False")
_COLOR = sys.stderr.isatty() and os.environ.get("NO_COLOR") is None


def set_verbose(value: bool) -> None:
    global _VERBOSE
    _VERBOSE = value


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _COLOR else text


def log(msg: str) -> None:
    print(f"{_c('36', '[azgov]')} {msg}", file=sys.stderr, flush=True)


def ok(msg: str) -> None:
    print(f"{_c('32', '[ ok ]')} {msg}", file=sys.stderr, flush=True)


def warn(msg: str) -> None:
    print(f"{_c('33', '[warn]')} {msg}", file=sys.stderr, flush=True)


def err(msg: str) -> None:
    print(f"{_c('31', '[fail]')} {msg}", file=sys.stderr, flush=True)


def debug(msg: str) -> None:
    if _VERBOSE:
        print(f"{_c('90', '[dbg ]')} {msg}", file=sys.stderr, flush=True)


def utcnow() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def iso(ts: Optional[_dt.datetime] = None) -> str:
    return (ts or utcnow()).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_iso(value: Any) -> Optional[_dt.datetime]:
    """Parse the many timestamp spellings Azure tooling emits; returns aware UTC datetime or None."""
    if value is None:
        return None
    if isinstance(value, _dt.datetime):
        return value if value.tzinfo else value.replace(tzinfo=_dt.timezone.utc)
    text = str(value).strip()
    if not text:
        return None
    if text.isdigit():  # epoch seconds
        try:
            return _dt.datetime.fromtimestamp(int(text), tz=_dt.timezone.utc)
        except (OverflowError, ValueError):
            return None
    text = text.replace("Z", "+00:00")
    text = re.sub(r"(\.\d{6})\d+", r"\1", text)  # .NET 7-digit fractions
    for candidate in (text, text.replace(" ", "T")):
        try:
            parsed = _dt.datetime.fromisoformat(candidate)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=_dt.timezone.utc)
        except ValueError:
            pass
    for fmt in ("%m/%d/%Y %H:%M:%S", "%d/%m/%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%m/%d/%Y %I:%M:%S %p", "%Y%m%d"):
        try:
            return _dt.datetime.strptime(str(value).strip(), fmt).replace(tzinfo=_dt.timezone.utc)
        except ValueError:
            pass
    return None


def read_json(path: Path, default: Any = None) -> Any:
    try:
        with open(path, "r", encoding="utf-8-sig") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return default


def write_json(path: Path, data: Any, indent: Optional[int] = 2) -> None:
    """Atomic JSON write (temp file + rename) so readers never see half-written files."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=indent, ensure_ascii=False, default=str)
            fh.write("\n")
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def which(name: str) -> Optional[str]:
    return shutil.which(name)


def run(cmd: Sequence[str], timeout: Optional[float] = None, check: bool = False,
        env: Optional[dict] = None, cwd: Optional[str] = None) -> subprocess.CompletedProcess:
    debug("exec: " + " ".join(_redact_arg(a) for a in cmd))
    return subprocess.run(list(cmd), capture_output=True, text=True, timeout=timeout,
                          check=check, env=env, cwd=cwd)


def _redact_arg(arg: str) -> str:
    return "***" if len(arg) > 200 else arg


def slug(text: str, max_len: int = 40) -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "-", text or "").strip("-._")
    return (s[:max_len] or "tenant").lower()


def chunks(seq: Sequence[Any], size: int) -> Iterable[Sequence[Any]]:
    for i in range(0, len(seq), size):
        yield seq[i:i + size]


def truthy(value: Any) -> Optional[bool]:
    """Normalise the many boolean spellings found in CSV/ARG output. None when unknown."""
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    text = str(value).strip().lower()
    if text in ("true", "1", "yes", "y", "compliant", "enabled", "on"):
        return True
    if text in ("false", "0", "no", "n", "noncompliant", "non-compliant", "disabled", "off"):
        return False
    return None


def to_int(value: Any, default: int = 0) -> int:
    try:
        if value is None or value == "":
            return default
        return int(float(str(value).replace(",", "")))
    except (TypeError, ValueError):
        return default


def to_float(value: Any, default: Optional[float] = None) -> Optional[float]:
    try:
        if value is None or value == "":
            return default
        return float(str(value).replace(",", "."))
    except (TypeError, ValueError):
        return default


def plural(n: int, word: str, plural_word: Optional[str] = None) -> str:
    return f"{n:,} {word if n == 1 else (plural_word or word + 's')}"


def human_duration(seconds: float) -> str:
    seconds = int(round(seconds))
    if seconds < 60:
        return f"{seconds}s"
    minutes, sec = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m {sec:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes:02d}m"


def is_guid(text: Any) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
                             str(text or "").strip()))


def is_tenant(text: Any) -> bool:
    """Tenant ID (GUID) or verified domain such as contoso.onmicrosoft.com."""
    value = str(text or "").strip()
    return is_guid(value) or bool(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,62})(?:\.[A-Za-z0-9-]{1,63})+", value))


def tenant_id_for_domain(domain: str, timeout: float = 15) -> Optional[str]:
    """Tenant GUID for a verified domain from the public OpenID configuration (no sign-in needed)."""
    import urllib.parse
    import urllib.request
    url = (f"https://login.microsoftonline.com/{urllib.parse.quote(domain.strip())}"
           "/v2.0/.well-known/openid-configuration")
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            issuer = json.loads(resp.read().decode("utf-8")).get("issuer", "")
    except Exception as exc:  # offline, unknown domain (400), proxy...
        debug(f"tenant lookup for {domain} failed: {exc}")
        return None
    m = re.search(r"/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})/", issuer)
    return m.group(1).lower() if m else None


def is_mg_id(text: Any) -> bool:
    """Management group IDs: letters, digits, '-', '_', '.', '(' and ')' - at most 90 characters."""
    return bool(re.fullmatch(r"[A-Za-z0-9._()-]{1,90}", str(text or "").strip()))


def cache_dir() -> Path:
    """Persistent cache for downloaded AzGovViz / checklist sources."""
    for var in ("AZGOV_CACHE_DIR", "COPILOT_PLUGIN_DATA", "PLUGIN_DATA"):
        if os.environ.get(var):
            p = Path(os.environ[var]).expanduser()
            break
    else:
        base = os.environ.get("XDG_CACHE_HOME") or (
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "azgov-assess") if os.name == "nt" else None)
        p = Path(base) / "azgov-assess" if base and os.name != "nt" else (
            Path(base) if base else Path.home() / ".cache" / "azgov-assess")
    p.mkdir(parents=True, exist_ok=True)
    return p
