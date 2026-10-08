"""AzGovViz execution (via Invoke-AzGovViz.ps1) and output loading."""

from __future__ import annotations

import csv
import io
import json
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from . import util

SCRIPTS_DIR = Path(__file__).resolve().parent.parent
RUNNER = SCRIPTS_DIR / "Invoke-AzGovViz.ps1"

# Console lines worth echoing while AzGovViz runs (the full log is always written to disk).
_ECHO = re.compile(
    r"^(\[azgovviz\]|\[  ok   \]|\[problem\]|Azure Governance Visualizer|AzGovViz|.*\bduration\b|"
    r".*\bprocessing\b.*(?:subscription|management group)|.*Throttle|.*ERROR|.*throw|Exporting|Building HTML|"
    r"Check|Get |Caching|Collecting|.*\bdone\b)", re.IGNORECASE)

EXIT_AUTH = 10


class AzGovVizError(RuntimeError):
    def __init__(self, message: str, exit_code: Optional[int] = None):
        super().__init__(message)
        self.exit_code = exit_code


def run(tenant_id: str, out_dir: Path, management_group: Optional[str] = None,
        subscriptions: Optional[List[str]] = None, login: bool = False, device_code: bool = False,
        quick: bool = False, consumption: bool = False, consumption_days: int = 30, no_pim: bool = False,
        alz_checker: bool = False, scrub_pii: bool = False, azgovviz_ref: str = "master",
        azgovviz_path: Optional[str] = None, extra_args: Optional[Dict[str, Any]] = None,
        throttle: int = 10, timeout_minutes: int = 240, echo: bool = True) -> Dict[str, Any]:
    pwsh = util.which("pwsh")
    if not pwsh:
        raise AzGovVizError("PowerShell 7 (pwsh) is required to run AzGovViz. Install: https://aka.ms/powershell", 3)
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [pwsh, "-NoLogo", "-NoProfile", "-File", str(RUNNER), "-TenantId", tenant_id,
           "-OutputPath", str(out_dir), "-AzGovVizRef", azgovviz_ref, "-ThrottleLimit", str(throttle)]
    if management_group:
        cmd += ["-ManagementGroupId", management_group]
    if subscriptions:
        cmd += ["-SubscriptionIds", ",".join(subscriptions)]
    if azgovviz_path:
        cmd += ["-AzGovVizPath", azgovviz_path]
    for flag, enabled in (("-Login", login), ("-DeviceCode", device_code), ("-Quick", quick),
                          ("-IncludeConsumption", consumption), ("-NoPIM", no_pim),
                          ("-ALZPolicyAssignmentsChecker", alz_checker),
                          ("-DoNotShowRoleAssignmentsUserData", scrub_pii)):
        if enabled:
            cmd.append(flag)
    if consumption:
        cmd += ["-ConsumptionDays", str(consumption_days)]
    if extra_args:
        cmd += ["-ExtraArgsJson", json.dumps(extra_args)]

    log_path = out_dir / "azgovviz-console.log"
    started = time.time()
    util.log(f"AzGovViz: starting (log: {log_path})")
    env = dict(os.environ, NO_COLOR="1")
    lines = 0
    with open(log_path, "w", encoding="utf-8", errors="replace") as log_fh:
        # own process group, so a timeout or Ctrl+C also stops children that hold stdout (e.g. git clone)
        group = {"start_new_session": True} if os.name == "posix" else \
            {"creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)}
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                encoding="utf-8", errors="replace", env=env, bufsize=1,
                                stdin=None if (login or device_code) else subprocess.DEVNULL, **group)
        last_echo = [time.time()]
        stop = threading.Event()
        timed_out = threading.Event()

        def heartbeat() -> None:
            # also enforces the timeout: a silent hang never reaches the line loop below
            while not stop.wait(15):
                if time.time() - started > timeout_minutes * 60:
                    timed_out.set()
                    _kill_tree(proc)
                    return
                if time.time() - last_echo[0] >= 55:
                    util.log(f"AzGovViz still running... {util.human_duration(time.time() - started)} elapsed, "
                             f"{lines:,} log lines")
                    last_echo[0] = time.time()

        hb = threading.Thread(target=heartbeat, daemon=True)
        hb.start()
        try:
            assert proc.stdout is not None
            for raw in proc.stdout:
                line = _strip_ansi(raw.rstrip("\n"))
                log_fh.write(line + "\n")
                lines += 1
                if echo and line.strip() and (_ECHO.match(line.strip()) or "devicelogin" in line.lower()
                                              or "code" in line.lower() and "sign in" in line.lower()):
                    print(f"    {line.strip()[:220]}", file=sys.stderr, flush=True)
                    last_echo[0] = time.time()
            proc.wait()
        finally:
            stop.set()
            if proc.poll() is None:  # interrupted (Ctrl+C) or failed while reading output
                _kill_tree(proc)
    if timed_out.is_set():
        raise AzGovVizError(f"AzGovViz exceeded the {timeout_minutes} minute timeout and was stopped. "
                            f"Last lines:\n{_tail(log_path, 15)}")
    duration = time.time() - started
    prep = util.read_json(out_dir / "azgovviz-prepare.json", {}) or {}
    files = locate_outputs(out_dir)
    result = {
        "exitCode": proc.returncode,
        "durationSec": round(duration, 1),
        "log": log_path.name,
        "prepare": prep,
        "mainCsv": files.get("") and files[""].name,
        "csvCount": len([k for k in files if k != "__html__"]),
        "html": files.get("__html__") and files["__html__"].name,
    }
    if proc.returncode == EXIT_AUTH:
        raise AzGovVizError(_tail_problem(log_path) or "Azure sign-in required", EXIT_AUTH)
    if not files.get(""):
        raise AzGovVizError(f"AzGovViz finished with exit code {proc.returncode} but produced no CSV output. "
                            f"Last lines:\n{_tail(log_path, 25)}", proc.returncode)
    if proc.returncode != 0:
        util.warn(f"AzGovViz exited with code {proc.returncode}, but outputs exist - continuing")
    util.ok(f"AzGovViz finished in {util.human_duration(duration)} ({result['csvCount']} CSV files)")
    return result


def _kill_tree(proc: "subprocess.Popen[str]") -> None:
    """Stop pwsh and everything it started."""
    try:
        if os.name == "posix":
            import signal
            os.killpg(proc.pid, signal.SIGKILL)
        else:
            subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)], capture_output=True, timeout=30)
    except (ProcessLookupError, PermissionError, OSError, subprocess.SubprocessError):
        pass
    try:
        proc.kill()
    except OSError:
        pass


def _strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", text)


def _tail(path: Path, n: int) -> str:
    try:
        return "\n".join(path.read_text(encoding="utf-8", errors="replace").splitlines()[-n:])
    except OSError:
        return ""


def _tail_problem(path: Path) -> str:
    lines = [l for l in _tail(path, 40).splitlines() if "[problem]" in l]
    return "\n".join(l.replace("[problem]", "").strip() for l in lines)


# ----------------------------------------------------------------------------------------------
# Output discovery / loading
# ----------------------------------------------------------------------------------------------
def locate_outputs(out_dir: Path) -> Dict[str, Path]:
    """Map CSV suffix ('' for the base hierarchy CSV) -> newest file. '__html__' -> main HTML."""
    found: Dict[str, Path] = {}
    if not out_dir.exists():
        return found
    unknown: List[Path] = []
    for path in sorted(out_dir.glob("AzGovViz_*.csv"), key=lambda p: p.stat().st_mtime):
        suffix = csv_suffix(path.name)
        if suffix is None:
            unknown.append(path)
        else:
            found[suffix] = path
    if unknown:
        # the base CSV is the one without a known suffix and the shortest name (newest wins on ties)
        unknown.sort(key=lambda p: (len(p.name), -p.stat().st_mtime))
        found.setdefault("", unknown[0])
        for extra in unknown[1:]:
            found.setdefault(extra.stem.rsplit("_", 1)[-1], extra)
    htmls = [p for p in out_dir.glob("AzGovViz_*.html") if "DefinitionInsights" not in p.name]
    if htmls:
        found["__html__"] = max(htmls, key=lambda p: p.stat().st_mtime)
    return found


def csv_suffix(filename: str) -> Optional[str]:
    """'AzGovViz_6.7.2_20250101_101010_<mg>_RoleAssignments.csv' -> 'RoleAssignments'.

    Returns None when no known suffix matches (the caller decides which of those is the base CSV).
    """
    if not (filename.startswith("AzGovViz_") and filename.endswith(".csv")):
        return None
    stem = filename[:-4]
    for suffix in sorted(KNOWN_SUFFIXES, key=len, reverse=True):
        if stem.endswith("_" + suffix):
            return suffix
    return None


KNOWN_SUFFIXES = [
    "RoleAssignments", "RoleDefinitions", "PolicyAssignments", "PolicyDefinitions", "PolicySetDefinitions",
    "PolicyExemptions", "PolicyRemediation", "PolicyCustomBuiltInParity", "ClassicAdministrators",
    "PIMEligibility", "ResourcesAll", "ResourceLocks", "ResourcesCostOptimizationAndCleanup",
    "ResourceFluctuation", "ResourceFluctuationDetailed", "ResourceProviders", "SubscriptionsFeatures",
    "MDfCCoverage", "MDfCEmailNotifications", "SubscriptionDetails", "ALZPolicyVersionChecker",
    "StorageAccountAccessAnalysis", "VirtualNetworks", "VirtualNetworkSubnets", "VirtualNetworkPeerings",
    "PrivateEndpoints", "AdvisorScores", "DailySummary", "Consumption", "UserAssignedIdentities4Resources",
    "PSRule",
]


def read_csv(path: Path) -> List[Dict[str, str]]:
    csv.field_size_limit(min(sys.maxsize, 2 ** 31 - 1))
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    if not text.strip():
        return []
    head = text.split("\n", 1)[0]
    delimiter = ";" if head.count(";") >= head.count(",") else ","
    reader = csv.DictReader(io.StringIO(text), delimiter=delimiter)
    return [{(k or "").strip(): (v if v is not None else "") for k, v in row.items()} for row in reader]


class AzGovVizData:
    """Lazy accessor over an AzGovViz output folder."""

    def __init__(self, out_dir: Path):
        self.dir = out_dir
        self.files = locate_outputs(out_dir)
        self._cache: Dict[str, List[Dict[str, str]]] = {}

    @property
    def available(self) -> bool:
        return "" in self.files

    def has(self, suffix: str) -> bool:
        return suffix in self.files

    def table(self, suffix: str) -> List[Dict[str, str]]:
        if suffix not in self._cache:
            path = self.files.get(suffix)
            self._cache[suffix] = read_csv(path) if path else []
        return self._cache[suffix]

    def rows(self, suffix: str) -> Iterator[Dict[str, str]]:
        yield from self.table(suffix)

    def json_dir(self) -> Optional[Path]:
        dirs = [p for p in self.dir.glob("JSON_*") if p.is_dir()]
        return max(dirs, key=lambda p: p.stat().st_mtime) if dirs else None

    def html_report(self) -> Optional[Path]:
        return self.files.get("__html__")

    def markdown(self) -> Optional[Path]:
        mds = list(self.dir.glob("AzGovViz_*.md"))
        return max(mds, key=lambda p: p.stat().st_mtime) if mds else None

    def version(self) -> Optional[str]:
        prep = util.read_json(self.dir / "azgovviz-prepare.json", {}) or {}
        if prep.get("azGovVizVersion"):
            return prep["azGovVizVersion"]
        main = self.files.get("")
        m = re.match(r"AzGovViz_([^_]+)_\d{8}_", main.name) if main else None
        return m.group(1) if m else None
