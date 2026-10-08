"""Command line interface: `azgov-assess <command>` (see `azgov-assess --help`)."""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
import time
import webbrowser
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import TOOL_NAME, __version__, util
from .arg import ArgError, ResourceGraphClient, Scope
from .auth import AuthError, TokenProvider, list_tenants, pwsh_env

STAGES = ["azgovviz", "inventory", "checklists", "analysis", "report"]


# ----------------------------------------------------------------------------------------------
# Run manifest
# ----------------------------------------------------------------------------------------------
class Run:
    def __init__(self, run_dir: Path):
        self.dir = run_dir
        self.path = run_dir / "run.json"
        self.data: Dict[str, Any] = util.read_json(self.path, {}) or {}

    @classmethod
    def create(cls, root: Path, tenant: Dict[str, Any], options: Dict[str, Any]) -> "Run":
        label = util.slug((tenant.get("defaultDomain") or "").split(".")[0] or tenant["tenantId"][:8], 24)
        run_dir = root / f"{label}_{time.strftime('%Y%m%d-%H%M%S')}"
        run_dir.mkdir(parents=True, exist_ok=False)
        run = cls(run_dir)
        run.data = {"schema": "azgov-assess/run@1", "tool": {"name": TOOL_NAME, "version": __version__},
                    "tenant": tenant, "options": options, "startedAt": util.iso(), "stages": {},
                    "host": {"python": platform.python_version(), "platform": platform.platform()}}
        run.save()
        return run

    def save(self) -> None:
        util.write_json(self.path, self.data)

    @property
    def tenant_id(self) -> Optional[str]:
        return (self.data.get("tenant") or {}).get("tenantId")

    def stage(self, name: str) -> Dict[str, Any]:
        return self.data.setdefault("stages", {}).setdefault(name, {})

    def set_stage(self, name: str, status: str, **extra: Any) -> None:
        if status == "running":  # a new attempt: drop the previous attempt's results (score, counts, errors)
            self.data.setdefault("stages", {})[name] = {}
        st = self.stage(name)
        st.update({"status": status, "updatedAt": util.iso(), **extra})
        self.save()


def _resolve_run_dir(value: Optional[str]) -> Path:
    if value:
        p = Path(value).expanduser().resolve()
        if (p / "run.json").exists():
            return p
        raise SystemExit(f"error: {p} is not an assessment run folder (run.json missing)")
    root = Path(os.environ.get("AZGOV_OUTPUT_DIR", "azgov-assessments")).expanduser().resolve()
    runs = sorted((d for d in root.glob("*/run.json")), key=lambda p: p.stat().st_mtime)
    if not runs:
        raise SystemExit(f"error: no run folder given and none found under {root} (use --run-dir)")
    return runs[-1].parent


# ----------------------------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------------------------
def _tenant_metadata(client: ResourceGraphClient, tenant_id: str) -> Dict[str, Any]:
    meta: Dict[str, Any] = {"tenantId": tenant_id}
    try:
        for t in client.arm_get("/tenants", "2022-12-01").get("value", []):
            if t.get("tenantId") == tenant_id:
                meta.update({"displayName": t.get("displayName"), "defaultDomain": t.get("defaultDomain"),
                             "countryCode": t.get("countryCode"), "tenantType": t.get("tenantType")})
    except ArgError as exc:
        util.debug(f"tenant metadata unavailable: {exc}")
    return meta


def _build_scope(args: argparse.Namespace, tenant_id: str, tokens: TokenProvider) -> ResourceGraphClient:
    if getattr(args, "subscriptions", None):
        scope = Scope(subscriptions=args.subscriptions)
        return ResourceGraphClient(tokens, scope)
    explicit_mg = getattr(args, "management_group", None)
    mg = explicit_mg or tenant_id
    client = ResourceGraphClient(tokens, Scope(management_groups=[mg]))
    try:
        client.query("resourcecontainers | where type =~ 'microsoft.resources/subscriptions' | project subscriptionId",
                     max_rows=1)
        return client
    except ArgError as exc:
        if explicit_mg:
            # A typo or missing permission must not silently widen the scope beyond what was asked for.
            if exc.status in (400, 404):
                why = f"management group '{mg}' was not found ({exc.code}) - check the ID"
            elif exc.status in (401, 403):
                why = f"no read access to management group '{mg}' ({exc.code}) - the identity needs Reader on it"
            else:
                why = f"Resource Graph query at management group '{mg}' failed: {exc}"
            raise ArgError(why + "; the scope is not widened beyond the requested management group.",
                           exc.status, exc.code)
        if exc.status in (400, 401, 403, 404):
            util.warn(f"Resource Graph at management group '{mg}' not permitted ({exc.code}); "
                      "falling back to all subscriptions visible to this identity in the tenant")
            return ResourceGraphClient(tokens, Scope())
        raise


def _split_csv(value: Optional[str]) -> List[str]:
    return list(dict.fromkeys(v.strip() for v in (value or "").split(",") if v.strip()))


def _json_obj_arg(value: str) -> Dict[str, Any]:
    try:
        data = json.loads(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"not valid JSON: {exc}")
    if not isinstance(data, dict):
        raise argparse.ArgumentTypeError("expected a JSON object, e.g. '{\"LargeTenant\": true}'")
    return data


def _resolve_tenant(value: str) -> str:
    """Tenant GUID for a GUID or a tenant domain (AzGovViz, scopes and analyzers need the GUID)."""
    value = value.strip()
    if util.is_guid(value):
        return value.lower()
    if not util.is_tenant(value):
        raise SystemExit(f"error: not a tenant ID (GUID) or tenant domain: {value!r}")
    guid = util.tenant_id_for_domain(value)
    if not guid:
        raise SystemExit(f"error: could not resolve the tenant domain {value!r} to a tenant ID - pass the tenant GUID")
    util.log(f"Tenant {value} = {guid}")
    return guid


def _tenant_arg(value: str) -> str:
    value = value.strip()
    if not util.is_tenant(value):
        raise argparse.ArgumentTypeError(f"not a tenant ID (GUID) or tenant domain: {value!r}")
    return value


def _guid_arg(value: str) -> str:
    value = value.strip()
    if not util.is_guid(value):
        raise argparse.ArgumentTypeError(f"not a subscription ID (GUID): {value!r}")
    return value


def _guid_list_arg(value: str) -> List[str]:
    return [_guid_arg(v) for v in _split_csv(value)]


def _mg_arg(value: str) -> str:
    value = value.strip()
    if not util.is_mg_id(value):
        raise argparse.ArgumentTypeError(f"not a management group ID: {value!r}")
    return value


def _pick_tenant(args: argparse.Namespace) -> str:
    if args.tenant:
        return _resolve_tenant(args.tenant)
    if os.environ.get("AZGOV_TENANT_ID"):
        return _resolve_tenant(os.environ["AZGOV_TENANT_ID"])
    tenants = list_tenants()
    if len(tenants) == 1:
        return next(iter(tenants))
    if not tenants:
        raise SystemExit("error: no tenant visible - sign in first (`azgov-assess login --tenant <id>`) or pass --tenant")
    lines = "\n".join(f"  {t['tenantId']}  {t.get('displayName') or ''} ({len(t['subscriptions'])} subscriptions)"
                      for t in tenants.values())
    raise SystemExit("error: --tenant is required when several tenants are visible:\n" + lines)


# ----------------------------------------------------------------------------------------------
# Stages
# ----------------------------------------------------------------------------------------------
def stage_azgovviz(run: Run, args: argparse.Namespace) -> bool:
    from . import azgovviz
    out = run.dir / "azgovviz"
    run.set_stage("azgovviz", "running", startedAt=util.iso())
    extra = getattr(args, "azgovviz_args", None)
    try:
        result = azgovviz.run(
            run.tenant_id, out, management_group=args.management_group, subscriptions=args.subscriptions,
            login=args.login, device_code=args.device_code, quick=args.quick, consumption=args.consumption,
            consumption_days=args.consumption_days, no_pim=args.no_pim, alz_checker=args.alz_policy_checker,
            scrub_pii=args.scrub_pii, azgovviz_ref=args.azgovviz_ref, azgovviz_path=args.azgovviz_path,
            extra_args=extra, throttle=args.throttle)
        run.set_stage("azgovviz", "ok", **result)
        return True
    except azgovviz.AzGovVizError as exc:
        run.set_stage("azgovviz", "failed", error=str(exc), exitCode=exc.exit_code)
        util.err(f"AzGovViz failed: {exc}")
        if exc.exit_code == azgovviz.EXIT_AUTH:
            raise SystemExit(10)
        return False


def stage_inventory_and_checklists(run: Run, args: argparse.Namespace, tokens: TokenProvider) -> bool:
    from . import checklists as cl
    from . import inventory
    try:
        client = _build_scope(args, run.tenant_id, tokens)
    except (AuthError, ArgError) as exc:
        for st in ("inventory", "checklists"):
            run.set_stage(st, "failed", error=str(exc))
        util.err(str(exc))
        return False
    tenant = run.data.get("tenant") or {}
    if not tenant.get("displayName"):
        run.data["tenant"] = {**tenant, **{k: v for k, v in _tenant_metadata(client, run.tenant_id).items() if v}}
        run.save()
    run.data["scope"] = {"description": client.scope.describe(run.tenant_id or ""),
                         "managementGroups": client.scope.management_groups,
                         "subscriptions": client.scope.subscriptions, "tokenProvider": tokens.provider_name}
    run.save()

    if not getattr(args, "skip_inventory", False):
        run.set_stage("inventory", "running", startedAt=util.iso())
        util.log(f"Inventory: Resource Graph over {client.scope.describe(run.tenant_id or '')}")
        inv = inventory.collect(client, run.tenant_id, args.subscriptions or [])
        util.write_json(run.dir / "inventory.json", inv)
        failed = len(inv.get("errors") or {})
        run.set_stage("inventory", "ok" if not failed else "partial", durationSec=inv.get("durationSec"),
                      probeErrors=failed, subscriptions=len(inv.get("subscriptions") or []))
        util.ok(f"Inventory collected in {inv.get('durationSec')}s "
                f"({len(inv.get('subscriptions') or [])} subscriptions, {failed} probe(s) unavailable)")
    inv = util.read_json(run.dir / "inventory.json", None)

    keys = args.checklists
    if not keys:
        run.set_stage("checklists", "skipped")
        return True
    run.set_stage("checklists", "running", startedAt=util.iso(), checklists=keys)
    source = cl.ChecklistSource(ref=args.checklists_ref, local_path=args.checklists_path)
    source.resolve_commit()
    evaluator = cl.ChecklistEvaluator(client, source, inventory.load_type_counts(inv), workers=args.workers,
                                      raw_dir=run.dir / "checklists" / "raw")
    results = evaluator.evaluate(keys)
    if not results["checklists"]:
        run.set_stage("checklists", "failed", error="none of the requested checklists could be loaded",
                      checklists=keys)
        util.err("review-checklists: none of the requested checklists could be loaded (offline? use --checklists-path)")
        return True  # inventory is still usable
    for c in results["checklists"]:
        util.write_json(run.dir / "checklists" / f"graph_results_{c['key']}.json",
                        cl.official_graph_results(results, c["key"]))
    util.write_json(run.dir / "checklists" / "results.json", cl.strip_private(results))
    summary = {c["key"]: c["summary"]["statusCounts"] for c in results["checklists"]}
    run.set_stage("checklists", "ok", durationSec=results["queries"]["durationSec"],
                  uniqueQueries=results["queries"]["unique"], summary=summary, commit=source.commit)
    for c in results["checklists"]:
        s = c["summary"]
        sc = s["statusCounts"]
        util.ok(f"{c['title']}: {sc['compliant']} compliant, {sc['partial']} partial, {sc['non_compliant']} "
                f"non-compliant, {sc['not_applicable'] + sc['no_data']} n/a, {sc['manual']} manual"
                + (f" - score {s['score']}%" if s.get("score") is not None else ""))
    return True


def stage_analysis(run: Run, baseline: Optional[str] = None) -> Dict[str, Any]:
    try:
        return _stage_analysis(run, baseline)
    except BaseException as exc:  # never leave run.json saying "running" (and showing the previous score)
        run.set_stage("analysis", "failed", error=f"{type(exc).__name__}: {exc}"[:500])
        raise


def _stage_analysis(run: Run, baseline: Optional[str] = None) -> Dict[str, Any]:
    from . import analysis
    run.set_stage("analysis", "running", startedAt=util.iso())
    result = analysis.analyze_run(run.dir, run.data)
    baseline = baseline or run.data.get("baseline")
    if baseline and Path(baseline).expanduser().resolve() == run.dir.resolve():
        util.warn("--baseline points at this run itself - ignored")
        run.data.pop("baseline", None)
        baseline = None
    if baseline:
        base_findings = util.read_json(Path(baseline).expanduser() / "analysis" / "findings.json", None)
        base_tenant = ((base_findings or {}).get("tenant") or {}).get("tenantId")
        if base_findings is None:
            util.warn(f"baseline {baseline} has no analysis/findings.json - run `azgov-assess analyze` on it first")
        elif base_tenant and run.tenant_id and base_tenant.lower() != run.tenant_id.lower():
            util.warn(f"baseline {baseline} is an assessment of another tenant ({base_tenant}) - trend not computed")
            run.data.pop("baseline", None)
            baseline = None
        else:
            result["trend"] = analysis.compare(result, base_findings, str(baseline))
            run.data["baseline"] = str(Path(baseline).expanduser().resolve())
            run.save()
            t = result["trend"]
            delta = t["overall"]["delta"]
            util.ok(f"Trend vs baseline: overall {'n/a' if delta is None else format(delta, '+')} points; "
                    f"{t['improved']} findings improved, {t['regressed']} regressed")
            if not t.get("comparable", True):
                util.warn("evidence differs from the baseline (" + "; ".join(t.get("sourceDiff") or []) +
                          ") - the report marks the trend as indicative")
    assessed_checklists = result.pop("_checklists", None)
    if assessed_checklists:
        util.write_json(run.dir / "analysis" / "checklists.assessed.json", assessed_checklists, indent=None)
    util.write_json(run.dir / "analysis" / "findings.json", result)
    util.write_text(run.dir / "analysis" / "brief.md", analysis.brief_markdown(result))
    ov = result["scores"]["overall"]
    counts = result["summary"]["failedBySeverity"]
    run.set_stage("analysis", "ok", overallScore=ov["score"], rating=ov["rating"]["name"],
                  findings=len(result["findings"]), failedBySeverity=counts)
    util.ok(f"Analysis: overall {ov['score']} ({ov['rating']['name']}); failing findings "
            f"high={counts.get('high', 0)} medium={counts.get('medium', 0)} low={counts.get('low', 0)}")
    return result


def stage_report(run: Run, open_browser: bool = False, output: Optional[str] = None,
                 pdf: bool = True) -> Tuple[Path, Optional[Path]]:
    """Render the HTML report and (by default) print it to PDF - the PDF is the deliverable."""
    try:
        return _stage_report(run, open_browser, output, pdf)
    except BaseException as exc:
        run.set_stage("report", "failed", error=f"{type(exc).__name__}: {exc}"[:500])
        raise


def _report_targets(output: Optional[str]) -> Tuple[Optional[Path], Optional[Path]]:
    """(html, pdf) paths for --output: a .pdf value names the PDF (HTML beside it); other names get .html."""
    if not output:
        return None, None
    out = Path(output).expanduser().resolve()
    suffix = out.suffix.lower()
    if suffix == ".pdf":
        return out.with_suffix(".html"), out
    if suffix not in (".html", ".htm"):
        out = out.with_name(out.name + ".html")
    return out, None


def _stage_report(run: Run, open_browser: bool, output: Optional[str], pdf: bool) -> Tuple[Path, Optional[Path]]:
    from . import report
    run.set_stage("report", "running", startedAt=util.iso())
    html_out, pdf_out = _report_targets(output)
    path = report.render_run(run.dir, output=html_out)
    util.ok(f"HTML report: {path}")
    pdf_path = report.build_pdf(run.dir, path, pdf_out) if pdf else None
    if pdf_path:
        util.ok(f"PDF report: {pdf_path}")
    elif pdf and not report.find_browser():
        util.warn("PDF not produced: it needs Microsoft Edge, Google Chrome or Chromium. The HTML report prints to "
                  "PDF from any browser (Print > Save as PDF).")
    elif pdf:
        util.warn("PDF export failed (the browser produced no file) - the HTML report is complete.")
    elif (pdf_out or path.with_suffix(".pdf")).exists():
        util.warn(f"{(pdf_out or path.with_suffix('.pdf')).name} is from an earlier render and was not updated (--no-pdf)")

    def rel(p: Path) -> str:
        return str(p.relative_to(run.dir)) if p.is_relative_to(run.dir) else str(p)

    insights = (run.dir / "analysis" / "ai-insights.json").exists()
    run.set_stage("report", "ok", path=rel(path), pdf=rel(pdf_path) if pdf_path else None,
                  aiInsights=insights, bytes=path.stat().st_size)
    run.data["finishedAt"] = util.iso()
    run.save()
    if open_browser:
        webbrowser.open((pdf_path or path).as_uri())
    return path, pdf_path


# ----------------------------------------------------------------------------------------------
# Commands
# ----------------------------------------------------------------------------------------------
def cmd_run(args: argparse.Namespace) -> int:
    tenant_id = _pick_tenant(args)
    tokens = TokenProvider(tenant_id, args.auth)
    root = Path(args.output_dir or os.environ.get("AZGOV_OUTPUT_DIR", "azgov-assessments")).expanduser().resolve()
    tenant: Dict[str, Any] = {"tenantId": tenant_id}
    for t in [list_tenants().get(tenant_id)] if args.tenant_lookup else []:
        if t:
            tenant.update({"displayName": t.get("displayName"), "defaultDomain": t.get("defaultDomain")})
    options = {k: v for k, v in vars(args).items() if k not in ("func",) and not callable(v)}
    run = Run.create(root, tenant, options)
    util.log(f"Assessment run folder: {run.dir}")
    started = time.time()

    azgv_ok = False
    if not args.skip_azgovviz:
        azgv_ok = stage_azgovviz(run, args)
    else:
        run.set_stage("azgovviz", "skipped")
    arg_ok = stage_inventory_and_checklists(run, args, tokens)
    if not azgv_ok and not arg_ok:
        util.err("Neither AzGovViz nor Resource Graph data could be collected - nothing to analyse.")
        util.err(tokens.login_hint())
        return 2
    result = stage_analysis(run, args.baseline)
    path, pdf_path = stage_report(run, open_browser=args.open, pdf=args.pdf)
    _print_summary(run, result, path, pdf_path, time.time() - started)
    return 0


def _print_summary(run: Run, result: Dict[str, Any], path: Path, pdf_path: Optional[Path], seconds: float) -> None:
    ov = result["scores"]["overall"]
    print(json.dumps({
        "runDir": str(run.dir),
        "report": str(path),
        "pdf": str(pdf_path) if pdf_path else None,
        "findings": str(run.dir / "analysis" / "findings.json"),
        "brief": str(run.dir / "analysis" / "brief.md"),
        "overallScore": ov["score"],
        "maturity": ov["rating"]["name"],
        "failedBySeverity": result["summary"]["failedBySeverity"],
        "durationSec": round(seconds, 1),
        "nextStep": "Write analysis/ai-insights.json (see `azgov-assess insights-template`) then `azgov-assess report`.",
    }, indent=2))


def cmd_azgovviz(args: argparse.Namespace) -> int:
    run = _open_or_create(args)
    return 0 if stage_azgovviz(run, args) else 1


def cmd_checklists(args: argparse.Namespace) -> int:
    run = _open_or_create(args)
    tokens = TokenProvider(run.tenant_id, args.auth)
    return 0 if stage_inventory_and_checklists(run, args, tokens) else 1


def cmd_analyze(args: argparse.Namespace) -> int:
    run = Run(_resolve_run_dir(args.run_dir))
    stage_analysis(run, args.baseline)
    return 0


def _analysis_stale(run: Run) -> bool:
    """findings.json is missing or older than the evidence (e.g. after `checklists --run-dir`)."""
    findings = run.dir / "analysis" / "findings.json"
    if not findings.exists():
        return True
    built = findings.stat().st_mtime
    inputs = [run.dir / "inventory.json", run.dir / "checklists" / "results.json", *(run.dir / "azgovviz").glob("*.csv")]
    return any(p.exists() and p.stat().st_mtime > built for p in inputs)


def cmd_report(args: argparse.Namespace) -> int:
    run = Run(_resolve_run_dir(args.run_dir))
    if args.reanalyze or args.baseline or _analysis_stale(run):
        stage_analysis(run, args.baseline)
    if (run.dir / "analysis" / "ai-insights.json").exists():
        from . import insights
        data, problems = insights.load(run.dir / "analysis" / "ai-insights.json")
        if data is not None:
            problems = insights.validate(data, util.read_json(run.dir / "analysis" / "findings.json", {}))
        for p in problems:
            util.warn(f"ai-insights.json: {p}")
    path, pdf_path = stage_report(run, open_browser=args.open, output=args.output, pdf=args.pdf)
    print(str(path))
    if pdf_path:
        print(str(pdf_path))
    return 0


def cmd_insights_template(args: argparse.Namespace) -> int:
    from . import insights
    run = Run(_resolve_run_dir(args.run_dir))
    findings = util.read_json(run.dir / "analysis" / "findings.json", None)
    if findings is None:
        findings = stage_analysis(run)
    target = run.dir / "analysis" / "ai-insights.template.json"
    util.write_json(target, insights.template(findings))
    print(json.dumps({"template": str(target), "writeTo": str(run.dir / "analysis" / "ai-insights.json"),
                      "brief": str(run.dir / "analysis" / "brief.md"),
                      "schema": insights.SCHEMA_DOC}, indent=2))
    return 0


def cmd_validate_insights(args: argparse.Namespace) -> int:
    from . import insights
    run = Run(_resolve_run_dir(args.run_dir))
    data, problems = insights.load(run.dir / "analysis" / "ai-insights.json")
    if data is None and not problems:
        util.err("analysis/ai-insights.json not found")
        return 1
    if data is not None:
        problems = insights.validate(data, util.read_json(run.dir / "analysis" / "findings.json", {}))
    if problems:
        for p in problems:
            util.err(p)
        return 1
    util.ok("ai-insights.json is valid")
    return 0


def _open_or_create(args: argparse.Namespace) -> Run:
    if args.run_dir:
        return Run(_resolve_run_dir(args.run_dir))
    tenant_id = _pick_tenant(args)
    root = Path(args.output_dir or os.environ.get("AZGOV_OUTPUT_DIR", "azgov-assessments")).expanduser().resolve()
    return Run.create(root, {"tenantId": tenant_id}, {k: v for k, v in vars(args).items() if not callable(v)})


def cmd_tenants(args: argparse.Namespace) -> int:
    tenants = list_tenants()
    if args.json:
        print(json.dumps(list(tenants.values()), indent=2))
        return 0
    if not tenants:
        print("No tenants visible. Sign in with `az login` or `Connect-AzAccount`.")
        return 1
    for t in sorted(tenants.values(), key=lambda x: (x.get("displayName") or "", x["tenantId"])):
        print(f"{t['tenantId']}  {t.get('displayName') or '(name unknown)'}  {t.get('defaultDomain') or ''}"
              f"  [{', '.join(t['sources'])}]  {len(t['subscriptions'])} subscription(s)")
        for s in t["subscriptions"][: args.max_subs]:
            print(f"    - {s['id']}  {s.get('name')}  {s.get('state') or ''}  {s.get('user') or ''}")
        if len(t["subscriptions"]) > args.max_subs:
            print(f"    ... {len(t['subscriptions']) - args.max_subs} more")
    return 0


def cmd_login(args: argparse.Namespace) -> int:
    pwsh = util.which("pwsh")
    if not pwsh:
        util.err("pwsh not found; install PowerShell 7 (https://aka.ms/powershell)")
        return 3
    script = ("$ErrorActionPreference='Stop'; $WarningPreference='SilentlyContinue'; "
              "Update-AzConfig -LoginExperienceV2 Off -Scope Process | Out-Null; "
              "$p = @{ Tenant = $env:AZGOV_PS_TENANT }; "
              "if ($env:AZGOV_PS_DEVICECODE) { $p.UseDeviceAuthentication = $true }; "
              "$c = Connect-AzAccount @p; if (-not $c.Context.Account) { throw 'Sign-in did not complete.' }; "
              # select the subscription afterwards: Connect-AzAccount -Subscription would discard a successful
              # sign-in when the chosen account cannot see that subscription
              "if ($env:AZGOV_PS_SUBSCRIPTION) { try { $null = Set-AzContext -Subscription $env:AZGOV_PS_SUBSCRIPTION } "
              "catch { Write-Warning \"Signed in, but this account cannot use subscription $env:AZGOV_PS_SUBSCRIPTION\" } }; "
              "\"Signed in: $($c.Context.Account.Id) tenant=$($c.Context.Tenant.Id)\"")
    env = pwsh_env(tenant=args.tenant, subscription=args.subscription, devicecode="1" if args.device_code else "")
    return subprocess.call([pwsh, "-NoLogo", "-NoProfile", "-Command", script], env=env)


def cmd_doctor(args: argparse.Namespace) -> int:
    checks: List[Dict[str, Any]] = []

    def add(name: str, ok: Optional[bool], detail: str, required: bool = True) -> None:
        checks.append({"check": name, "ok": ok, "detail": detail, "required": required})

    add("python", sys.version_info >= (3, 9), platform.python_version())
    pwsh = util.which("pwsh")
    if pwsh:
        script = ("$v=$PSVersionTable.PSVersion.ToString(); $a=(Get-Module -ListAvailable Az.Accounts | Sort-Object Version -Desc | Select-Object -First 1).Version;"
                  "$c=(Get-Module -ListAvailable AzAPICall | Sort-Object Version -Desc | Select-Object -First 1).Version;"
                  "\"$v|$a|$c\"")
        proc = util.run([pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script], timeout=60)
        parts = (proc.stdout.strip().splitlines() or ["||"])[-1].split("|") + ["", "", ""]
        add("pwsh", parts[0].startswith("7"), f"PowerShell {parts[0]}")
        add("Az.Accounts", bool(parts[1]), parts[1] or "missing (auto-installed on first run)", required=False)
        add("AzAPICall", bool(parts[2]), parts[2] or "missing (auto-installed on first run)", required=False)
    else:
        add("pwsh", False, "PowerShell 7 not found - required for AzGovViz (https://aka.ms/powershell)")
    add("git", bool(util.which("git")), util.which("git") or "missing (zip download fallback is used)", required=False)
    add("az", bool(util.which("az")), util.which("az") or "missing (Az PowerShell is used for tokens)", required=False)
    try:
        import urllib.request
        urllib.request.urlopen("https://raw.githubusercontent.com/Azure/review-checklists/main/README.md", timeout=15)
        add("github", True, "raw.githubusercontent.com reachable")
    except Exception as exc:
        add("github", False, f"cannot reach GitHub ({exc}); use --checklists-path / --azgovviz-path offline copies")
    if args.tenant:
        args.tenant = _resolve_tenant(args.tenant)
        tokens = TokenProvider(args.tenant, args.auth)
        try:
            tokens.get()
            add("arm-token", True, f"token via {tokens.provider_name}")
            try:
                client = ResourceGraphClient(tokens, Scope(management_groups=[args.tenant]))
                res = client.query("resourcecontainers | where type =~ 'microsoft.resources/subscriptions' "
                                   "| project subscriptionId, name", max_rows=1000)
                add("tenant-root-read", True, f"Resource Graph at tenant root OK ({len(res.rows)} subscriptions)")
            except ArgError as exc:
                add("tenant-root-read", False, f"no Reader at tenant root management group ({exc.code}); "
                    "AzGovViz needs Reader on the target management group", required=False)
        except AuthError as exc:
            add("arm-token", False, str(exc))
        if pwsh:
            script = ("$WarningPreference='SilentlyContinue'; try { $null = Get-AzAccessToken -TenantId $env:AZGOV_PS_TENANT "
                      "-ResourceUrl https://management.azure.com/ -ErrorAction Stop; 'OK' } catch { 'FAIL: ' + $_.Exception.Message }")
            proc = util.run([pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script], timeout=90,
                            env=pwsh_env(tenant=args.tenant))
            out = (proc.stdout or "").strip().splitlines()
            line = out[-1] if out else "FAIL: no output"
            add("azpwsh-context", line.startswith("OK"),
                "Az PowerShell context ready for AzGovViz" if line.startswith("OK")
                else f"{line[:300]} -> run: azgov-assess login --tenant {args.tenant}")
    ok = all(c["ok"] for c in checks if c["required"])
    if args.json:
        print(json.dumps({"ok": ok, "checks": checks}, indent=2))
    else:
        for c in checks:
            mark = "OK  " if c["ok"] else ("FAIL" if c["required"] else "WARN")
            print(f"[{mark}] {c['check']:<17} {c['detail']}")
        print("\nReady." if ok else "\nNot ready - fix the FAIL items above.")
    return 0 if ok else 1


def cmd_list_checklists(args: argparse.Namespace) -> int:
    from . import checklists as cl
    if args.remote:
        for key in cl.ChecklistSource(ref=args.checklists_ref).list_remote():
            print(key)
        return 0
    for key, meta in cl.CATALOG.items():
        default = " (default)" if key in cl.DEFAULT_SET else ""
        print(f"{key:<22} {meta['title']}{default}")
    return 0


# ----------------------------------------------------------------------------------------------
# Parser
# ----------------------------------------------------------------------------------------------
def _add_scope_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--tenant", "-t", type=_tenant_arg, help="Microsoft Entra tenant ID to assess")
    p.add_argument("--management-group", "-m", type=_mg_arg, help="Management group ID (default: tenant root group)")
    p.add_argument("--subscriptions", "-s", type=_guid_list_arg, default=[],
                   help="Comma separated subscription IDs to limit the scope")
    p.add_argument("--auth", choices=["auto", "azcli", "azpwsh", "env"], default="auto",
                   help="Token source for Resource Graph (default: auto)")
    p.add_argument("--output-dir", "-o", help="Root folder for assessment runs (default: ./azgov-assessments)")


def _add_azgovviz_args(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("AzGovViz")
    g.add_argument("--login", action="store_true", help="Start Connect-AzAccount if no valid Az PowerShell context")
    g.add_argument("--device-code", action="store_true", help="Use device-code sign-in (headless machines)")
    g.add_argument("--quick", action="store_true", help="Faster AzGovViz run (no PIM, fewer details)")
    g.add_argument("--consumption", action="store_true", help="Collect Azure consumption (cost) data")
    g.add_argument("--consumption-days", type=int, default=30)
    g.add_argument("--no-pim", action="store_true", help="Skip PIM eligibility (needs Entra ID P2 / Graph permission)")
    g.add_argument("--alz-policy-checker", action="store_true",
                   help="Run AzGovViz ALZ policy assignments checker (ALZ management group structure)")
    g.add_argument("--scrub-pii", action="store_true", help="Do not show user names/UPNs in role assignments")
    g.add_argument("--azgovviz-ref", default="master", help="Git branch/tag of Azure/Azure-Governance-Visualizer")
    g.add_argument("--azgovviz-path", help="Use an existing local AzGovViz clone")
    g.add_argument("--azgovviz-args", type=_json_obj_arg, help="JSON object with extra AzGovVizParallel.ps1 parameters")
    g.add_argument("--throttle", type=int, default=10, help="AzGovViz ThrottleLimit (parallelism)")


def _add_checklist_args(p: argparse.ArgumentParser) -> None:
    from .checklists import DEFAULT_SET
    g = p.add_argument_group("Azure review checklists")
    g.add_argument("--checklists", "-c", type=_split_csv, default=list(DEFAULT_SET),
                   help=f"Checklists to evaluate (default: {','.join(DEFAULT_SET)}; '' to skip). "
                        "See `azgov-assess list-checklists`.")
    g.add_argument("--checklists-ref", default="main", help="Git ref of Azure/review-checklists")
    g.add_argument("--checklists-path", help="Local clone of Azure/review-checklists (offline)")
    g.add_argument("--workers", type=int, default=4, help="Parallel Resource Graph queries")
    g.add_argument("--skip-inventory", action="store_true", help=argparse.SUPPRESS)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="azgov-assess",
                                     description="Azure governance assessment: AzGovViz + Azure review checklists "
                                                 "-> scored PDF + HTML report.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--verbose", "-v", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("run", help="Full assessment: AzGovViz -> inventory -> checklists -> analysis -> report")
    _add_scope_args(p)
    _add_azgovviz_args(p)
    _add_checklist_args(p)
    p.add_argument("--skip-azgovviz", action="store_true", help="Resource Graph only (no PowerShell needed)")
    p.add_argument("--no-tenant-lookup", dest="tenant_lookup", action="store_false", help=argparse.SUPPRESS)
    p.add_argument("--open", action="store_true", help="Open the PDF (or HTML) report when done")
    p.add_argument("--no-pdf", dest="pdf", action="store_false", help="Skip the PDF export (HTML report only)")
    p.add_argument("--baseline", help="Previous run folder to compare against (trend section)")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("azgovviz", help="Run only AzGovViz into a (new or existing) run folder")
    _add_scope_args(p)
    _add_azgovviz_args(p)
    p.add_argument("--run-dir")
    p.set_defaults(func=cmd_azgovviz)

    p = sub.add_parser("checklists", help="Run inventory + review-checklist queries into a run folder")
    _add_scope_args(p)
    _add_checklist_args(p)
    p.add_argument("--run-dir")
    p.set_defaults(func=cmd_checklists)

    p = sub.add_parser("analyze", help="(Re)build analysis/findings.json and brief.md for a run folder")
    p.add_argument("--run-dir")
    p.add_argument("--baseline", help="Previous run folder to compare against (trend)")
    p.set_defaults(func=cmd_analyze)

    p = sub.add_parser("report", help="(Re)render the PDF and HTML report (merges analysis/ai-insights.json if present)")
    p.add_argument("--run-dir")
    p.add_argument("--output", help="Output path: name.html (PDF written beside it) or name.pdf (HTML beside it)")
    p.add_argument("--reanalyze", action="store_true", help="Re-run the analysis stage first")
    p.add_argument("--baseline", help="Previous run folder to compare against (implies --reanalyze)")
    p.add_argument("--no-pdf", dest="pdf", action="store_false",
                   help="Skip the PDF (by default the report is also printed to PDF with headless Edge/Chrome)")
    p.add_argument("--pdf", dest="pdf", action="store_true", help=argparse.SUPPRESS)  # default; kept for old scripts
    p.add_argument("--open", action="store_true")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("insights-template", help="Write the ai-insights.json template for the AI analysis step")
    p.add_argument("--run-dir")
    p.set_defaults(func=cmd_insights_template)

    p = sub.add_parser("validate-insights", help="Validate analysis/ai-insights.json")
    p.add_argument("--run-dir")
    p.set_defaults(func=cmd_validate_insights)

    p = sub.add_parser("tenants", help="List tenants and subscriptions visible to az CLI / Az PowerShell")
    p.add_argument("--json", action="store_true")
    p.add_argument("--max-subs", type=int, default=10)
    p.set_defaults(func=cmd_tenants)

    p = sub.add_parser("login", help="Interactive Az PowerShell sign-in for a tenant (needed by AzGovViz)")
    p.add_argument("--tenant", "-t", required=True, type=_tenant_arg)
    p.add_argument("--subscription", type=_guid_arg)
    p.add_argument("--device-code", action="store_true")
    p.set_defaults(func=cmd_login)

    p = sub.add_parser("doctor", help="Check prerequisites, connectivity and permissions")
    p.add_argument("--tenant", "-t", type=_tenant_arg)
    p.add_argument("--auth", choices=["auto", "azcli", "azpwsh", "env"], default="auto")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("list-checklists", help="Show available Azure review checklists")
    p.add_argument("--remote", action="store_true", help="List every checklist in the GitHub repository")
    p.add_argument("--checklists-ref", default="main")
    p.set_defaults(func=cmd_list_checklists)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    util.set_verbose(args.verbose)
    try:
        return int(args.func(args) or 0)
    except AuthError as exc:
        util.err(str(exc))
        return 10
    except KeyboardInterrupt:
        util.err("interrupted")
        return 130
