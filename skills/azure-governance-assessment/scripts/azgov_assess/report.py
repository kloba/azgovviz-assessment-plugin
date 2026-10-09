"""Self-contained HTML assessment report renderer (no external assets; works offline and prints well)."""

from __future__ import annotations

import html
import json
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from . import TOOL_NAME, __version__, scoring, util

ASSETS = Path(__file__).resolve().parent.parent.parent / "assets"
PRINT_EVIDENCE_ROWS = 10  # keep in sync with report-print.css (tr:nth-child(n+11))
LOGO_SVG = ('<svg width="22" height="22" viewBox="0 0 24 24" aria-hidden="true"><path d="M3 20h18" stroke="currentColor" stroke-width="2"/>'
            '<path d="M5 20V15h3v5M10.5 20V11h3v9M16 20V7h3v13" fill="none" stroke="currentColor" stroke-width="1.8"/>'
            '<path d="M4 9.5 L19 3.5" stroke="currentColor" stroke-width="1.6" stroke-dasharray="2 2.2"/></svg>')

SEV_LABEL = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}
STATUS_LABEL = {"fail": "Fail", "warn": "Warning", "pass": "Pass", "info": "Info", "not_assessed": "Not assessed"}
CL_STATUS = [
    ("compliant", "Compliant", "var(--good)"),
    ("partial", "Partially compliant", "var(--serious)"),
    ("non_compliant", "Non-compliant", "var(--critical)"),
    ("info", "Evidence for review", "#7c8ba1"),
    ("not_applicable", "Not applicable", "var(--neutral)"),
    ("no_data", "No matching resources", "var(--rule-strong)"),
    ("error", "Query error", "var(--warning)"),
    ("manual", "Manual review", "var(--panel-2)"),
]
CL_LABEL = {k: v for k, v, _ in CL_STATUS}


def esc(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def css_str(value: Any) -> str:
    """A quoted CSS string literal (for generated `content:` values)."""
    text = re.sub(r"[\x00-\x1f]", " ", "" if value is None else str(value))
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"').replace("<", "\\3c ") + '"'


def safe_url(value: Any) -> Optional[str]:
    """Only http(s) links from checklist/finding data become hrefs (no javascript:, data: ...)."""
    url = str(value or "").strip()
    return url if re.match(r"https?://", url, re.I) else None


# ----------------------------------------------------------------------------------------------
# Markdown (small, safe subset: paragraphs, lists, headings, bold, italics, code, links)
# ----------------------------------------------------------------------------------------------
def md(text: Optional[str]) -> str:
    if not text:
        return ""
    out: List[str] = []
    in_list: Optional[str] = None
    para: List[str] = []

    def inline(s: str) -> str:
        s = esc(s)
        s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
        s = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", s)
        s = re.sub(r"(?<![*\w])\*([^*\n]+)\*(?!\w)", r"<em>\1</em>", s)
        s = re.sub(r"(?<![\w])_([^_\n]+)_(?![\w])", r"<em>\1</em>", s)
        s = re.sub(r"\[([^\]]+)\]\((https?://[^)\s]+)\)", r'<a href="\2" target="_blank" rel="noopener">\1</a>', s)
        return s

    def flush_para() -> None:
        if para:
            out.append("<p>" + inline(" ".join(para)) + "</p>")
            para.clear()

    def close_list() -> None:
        nonlocal in_list
        if in_list:
            out.append(f"</{in_list}>")
            in_list = None

    for raw in text.replace("\r\n", "\n").split("\n"):
        line = raw.rstrip()
        m_ul = re.match(r"^\s*[-*]\s+(.*)", line)
        m_ol = re.match(r"^\s*\d+[.)]\s+(.*)", line)
        m_h = re.match(r"^(#{1,4})\s+(.*)", line)
        if not line.strip():
            flush_para()
            close_list()
        elif m_h:
            flush_para()
            close_list()
            level = min(4, len(m_h.group(1)) + 2)
            out.append(f"<h{level}>{inline(m_h.group(2))}</h{level}>")
        elif m_ul or m_ol:
            flush_para()
            tag = "ul" if m_ul else "ol"
            if in_list != tag:
                close_list()
                out.append(f"<{tag}>")
                in_list = tag
            out.append("<li>" + inline((m_ul or m_ol).group(1)) + "</li>")
        else:
            if in_list:
                close_list()
            para.append(line.strip())
    flush_para()
    close_list()
    return "\n".join(out)


# ----------------------------------------------------------------------------------------------
# Small components
# ----------------------------------------------------------------------------------------------
def chip(cls: str, label: str) -> str:
    return f'<span class="chip {esc(cls)}"><span class="dot" aria-hidden="true"></span>{esc(label)}</span>'


def sev_chip(sev: str) -> str:
    sev = (sev or "info").lower()
    return chip(sev, SEV_LABEL.get(sev, sev.title()))


def status_chip(status: str) -> str:
    return chip(status, STATUS_LABEL.get(status, status.replace("_", " ").title()))


def cl_chip(status: str) -> str:
    return chip(status, CL_LABEL.get(status, status))


def fmt_int(n: Any) -> str:
    try:
        return f"{int(n):,}"
    except (TypeError, ValueError):
        return "–"


def fmt_score(s: Optional[float]) -> str:
    # one decimal everywhere, so a column of scores lines up (68.0 next to 68.7); a full score is just 100
    return "–" if s is None else ("100" if s >= 99.95 else f"{s:.1f}")


def band_color(score: Optional[float]) -> str:
    if score is None:
        return "var(--neutral)"
    if score >= 75:
        return "var(--series-1)"
    if score >= 50:
        return "var(--warning)"
    return "var(--critical)"


def meter(score: Optional[float], label: str = "") -> str:
    if score is None:
        return '<div class="meter-h"><span class="muted small">Not assessed</span></div>'
    pct = max(0.0, min(100.0, score))
    return (f'<div class="meter-h" data-tip="{esc(label)}|{fmt_score(score)} / 100" role="img" '
            f'aria-label="{esc(label)} score {fmt_score(score)} of 100">'
            f'<div class="track"><div class="fill" style="width:{pct:.1f}%;background:{band_color(score)}"></div>'
            f'<div class="tick" style="left:60%"></div><div class="tick" style="left:75%"></div></div>'
            f'<span class="val num">{fmt_score(score)}</span></div>')


def stacked(counts: Dict[str, int], statuses: List[Tuple[str, str, str]] = CL_STATUS, total_label: str = "items",
            show_labels: bool = True, cls: str = "stackbar") -> str:
    total = sum(counts.get(k, 0) for k, _, _ in statuses)
    if not total:
        return '<div class="muted small">No data</div>'
    segs = []
    for key, label, color in statuses:
        n = counts.get(key, 0)
        if not n:
            continue
        pct = 100 * n / total
        text = f'<span>{n}</span>' if show_labels and pct >= 7 else ""
        dark = key == "non_compliant"  # white text only where it reaches 4.5:1 (green/grey segments use ink)
        segs.append(f'<div class="seg-{esc(key)}{" on-dark" if dark else ""}" style="flex:{n} 1 0;background:{color}" '
                    f'data-tip="{esc(label)}|{n:,} {total_label} ({pct:.0f}%)">{text}</div>')
    return f'<div class="{cls}" role="img" aria-label="{esc(_stack_aria(counts, statuses))}">{"".join(segs)}</div>'


def _stack_aria(counts: Dict[str, int], statuses: List[Tuple[str, str, str]]) -> str:
    return ", ".join(f"{label}: {counts.get(k, 0)}" for k, label, _ in statuses if counts.get(k))


def legend(counts: Dict[str, int], statuses: List[Tuple[str, str, str]] = CL_STATUS) -> str:
    parts = [f'<span><i style="background:{c}"></i>{esc(l)} <b class="num">{counts.get(k, 0):,}</b></span>'
             for k, l, c in statuses if counts.get(k)]
    return f'<div class="legend">{"".join(parts)}</div>'


def hbars(rows: List[Tuple[str, int]], top: int = 12, unit: str = "resources") -> str:
    if not rows:
        return '<p class="muted small">No data collected.</p>'
    rows = sorted(rows, key=lambda r: -r[1])
    shown = rows[:top]
    rest = rows[top:]
    if rest:
        shown.append((f"Other ({len(rest)} more)", sum(r[1] for r in rest)))
    mx = max(r[1] for r in shown) or 1
    out = ['<div class="hbars">']
    for label, n in shown:
        pct = 100 * n / mx
        out.append(f'<div class="hb-row" data-tip="{esc(label)}|{n:,} {unit}"><span class="hb-label" title="{esc(label)}">'
                   f'{esc(label)}</span><span class="hb-track"><span class="hb-fill" style="width:{pct:.1f}%"></span>'
                   f'</span><span class="hb-val num">{n:,}</span></div>')
    out.append("</div>")
    return "".join(out)


def glide_path(score: Optional[float]) -> str:
    """Maturity staircase: five ordinal steps sized to their score band, marker at the tenant score."""
    W, x0, x1, base = 700, 8, 692, 92
    bands = [(0, 40, "L1", "Initial"), (40, 60, "L2", "Developing"), (60, 75, "L3", "Defined"),
             (75, 90, "L4", "Managed"), (90, 100, "L5", "Optimized")]
    heights = [16, 28, 40, 52, 64]

    def x(v: float) -> float:
        return x0 + (x1 - x0) * v / 100

    parts = [f'<svg class="glide" viewBox="0 0 {W} 150" role="img" aria-label="Maturity scale from level 1 '
             f'Initial to level 5 Optimized; this tenant scores {fmt_score(score)}">']
    for i, (lo, hi, lvl, name) in enumerate(bands):
        left, right = x(lo) + (1 if i else 0), x(hi) - (1 if i < 4 else 0)
        h = heights[i]
        top = base - h
        r = 4
        path = (f"M{left:.1f},{base} L{left:.1f},{top + r} Q{left:.1f},{top} {left + r:.1f},{top} "
                f"L{right - r:.1f},{top} Q{right:.1f},{top} {right:.1f},{top + r} L{right:.1f},{base} Z")
        parts.append(f'<path d="{path}" fill="var(--ord-{i + 1})" data-tip="{lvl} {name}|scores {lo}–{hi}"/>')
        cx = (left + right) / 2
        parts.append(f'<text x="{cx:.1f}" y="{base + 18}" text-anchor="middle">{lvl}</text>')
        parts.append(f'<text class="lvl-name" x="{cx:.1f}" y="{base + 34}" text-anchor="middle">{name}</text>')
    for v in (0, 40, 60, 75, 90, 100):
        parts.append(f'<text x="{x(v):.1f}" y="{base + 52}" text-anchor="{"start" if v == 0 else ("end" if v == 100 else "middle")}" '
                     f'style="font-size:10px">{v}</text>')
    if score is not None:
        sx = x(max(0.0, min(100.0, score)))
        parts.append(f'<line x1="{sx:.1f}" x2="{sx:.1f}" y1="14" y2="{base}" stroke="var(--ink)" stroke-width="2"/>')
        parts.append(f'<circle cx="{sx:.1f}" cy="14" r="6" fill="var(--ink)" stroke="var(--panel)" stroke-width="2"/>')
        anchor = "start" if sx < W * 0.75 else "end"
        dx = 12 if anchor == "start" else -12
        parts.append(f'<text class="marker-label" x="{sx + dx:.1f}" y="19" text-anchor="{anchor}">'
                     f'This tenant · {fmt_score(score)}</text>')
    parts.append("</svg>")
    return "".join(parts)


def data_table(columns: List[str], rows: List[List[Any]], numeric: Iterable[int] = (), cls: str = "data",
               label: Optional[str] = None) -> str:
    """A data table; wide tables (`label` or > 6 columns) scroll sideways, so their wrapper is a focusable region."""
    nums = set(numeric)
    head = "".join(f'<th{" class=num" if i in nums else ""}>{esc(c)}</th>' for i, c in enumerate(columns))
    body = []
    for r in rows:
        cells = []
        for i, v in enumerate(r):
            cell = esc(v)
            if isinstance(v, str) and v.startswith("/subscriptions/"):
                cell = f'<span class="mono">{cell}</span>'
            cells.append(f'<td{" class=num" if i in nums else ""}>{cell}</td>')
        body.append("<tr>" + "".join(cells) + "</tr>")
    region = (f' role="region" tabindex="0" aria-label="{esc(label or columns[0] + " table")}"'
              if label or len(columns) > 6 else "")
    return (f'<div class="tbl-wrap"{region}><table class="{cls}"><thead><tr>{head}</tr></thead>'
            f'<tbody>{"".join(body)}</tbody></table></div>')


# ----------------------------------------------------------------------------------------------
# Sections
# ----------------------------------------------------------------------------------------------
class Report:
    def __init__(self, run_dir: Path, out_dir: Optional[Path] = None, toc_pages: Optional[Dict[str, int]] = None):
        self.toc_pages = toc_pages or {}  # heading text -> PDF page (from a first print pass)
        # links to the run's JSON/CSV files are relative to where the HTML is written (default: <run>/report/)
        try:
            self.base = Path(os.path.relpath(run_dir, out_dir or run_dir / "report")).as_posix()
        except ValueError:  # Windows: output on another drive / share - fall back to absolute links
            self.base = run_dir.resolve().as_uri()
        self.dir = run_dir
        self.run = util.read_json(run_dir / "run.json", {}) or {}
        self.f = util.read_json(run_dir / "analysis" / "findings.json", None)
        if self.f is None:
            raise FileNotFoundError("analysis/findings.json missing - run `azgov-assess analyze` first")
        self.cl = util.read_json(run_dir / "analysis" / "checklists.assessed.json", None) or \
            util.read_json(run_dir / "checklists" / "results.json", None)
        self.inv = util.read_json(run_dir / "inventory.json", None) or {}
        from .insights import load, sanitize, validate
        self.ai, self.ai_problems = load(run_dir / "analysis" / "ai-insights.json")
        if self.ai is not None:
            self.ai_problems = validate(self.ai, self.f)
            self.ai = sanitize(self.ai)  # the report renders even when the file has problems
        self.tenant = self.f.get("tenant") or self.run.get("tenant") or {}
        self.facts = self.f.get("facts") or {}
        self.findings = self.f.get("findings") or []
        self.by_id = {x["id"]: x for x in self.findings}
        self.scores = self.f.get("scores") or {}

    # -- helpers --
    @property
    def tenant_name(self) -> str:
        return self.tenant.get("displayName") or self.tenant.get("defaultDomain") or self.tenant.get("tenantId") or "Tenant"

    @property
    def assessed_at(self):
        """When the evidence was collected (run start) - re-analysing or re-rendering later must not change it."""
        from .analysis import assessed_at
        return util.parse_iso(assessed_at(self.dir, self.f)) or util.utcnow()

    def date(self) -> str:
        return self.assessed_at.strftime("%d %b %Y")

    def finding_link(self, fid: str) -> str:
        if fid in self.by_id:
            return f'<a class="fid" href="#F-{esc(fid)}">{esc(fid)}</a>'
        return f'<span class="fid">{esc(fid)}</span>'

    # -- plate --
    def plate(self) -> str:
        ov = self.scores.get("overall") or {}
        rating = ov.get("rating") or {}
        src = self.f.get("sources") or {}
        azv = src.get("azgovviz") or {}
        clsrc = ((src.get("checklists") or {}).get("source") or {})
        commit = (clsrc.get("commit") or "")[:7]
        sources = []
        if azv.get("available"):
            sources.append(f"AzGovViz {esc(azv.get('version') or '')}")
        if (src.get("inventory") or {}).get("available"):
            sources.append("Resource Graph")
        if (src.get("checklists") or {}).get("available"):
            sources.append("review-checklists" + (f" @{esc(commit)}" if commit else ""))
        scope = (self.f.get("scope") or {}).get("description") or "Tenant root management group"
        facts = self.facts
        evaluated = sum((c.get("evaluated") or 0) for c in (self.f.get("summary") or {}).get("checklists", []))
        stats = [
            ("Management groups", facts.get("managementGroups"), f"depth {facts.get('mgDepth')}" if facts.get("mgDepth") else ""),
            ("Subscriptions", facts.get("subscriptions"), f"{facts.get('subscriptionsEnabled', '')} enabled" if facts.get("subscriptionsEnabled") is not None else ""),
            ("Resources", facts.get("resources"), f"{facts.get('resourceTypes', 0)} types · {facts.get('regions', 0)} regions"),
            ("Policy assignments", facts.get("policyAssignments"),
             f"{facts.get('policyAssignmentsMg', 0)} at MG scope" if facts.get("policyAssignments") is not None else "needs AzGovViz"),
            ("Role assignments", facts.get("roleAssignments"),
             f"{facts.get('roleAssignmentsOwner', 0)} Owner" if facts.get("roleAssignments") is not None else "needs AzGovViz"),
            ("Checklist items tested", evaluated if facts.get("checklistQueries") else None,
             f"{facts.get('checklistQueries')} Resource Graph queries" if facts.get("checklistQueries") else "checklists not run"),
        ]
        foot = "".join(f'<div class="stat"><div class="label">{esc(l)}</div><div class="value">{fmt_int(v)}</div>'
                       f'<div class="hint">{esc(h)}</div></div>' for l, v, h in stats)
        return f"""
<div class="plate">
  <div class="plate-head">
    <div><div class="label">Tenant</div><div class="v">{esc(self.tenant_name)}</div>
         <div class="v mono muted">{esc(self.tenant.get('defaultDomain') or '')} · {esc(self.tenant.get('tenantId') or '')}</div></div>
    <div><div class="label">Scope</div><div class="v">{esc(scope)}</div></div>
    <div><div class="label">Assessed</div><div class="v">{esc(self.date())}</div>
         <div class="v mono muted">{esc(self.dir.name)}</div></div>
    <div><div class="label">Evidence</div><div class="v small">{' · '.join(sources) or 'n/a'}</div></div>
  </div>
  <div class="plate-body">
    <div class="plate-score">
      <div class="label">Governance maturity score</div>
      <div class="hero-num">{fmt_score(ov.get('score'))}<small>/ 100</small></div>
      <div class="hero-level">{esc(rating.get('name', 'Not assessed'))}<span class="lvl">LEVEL {esc(rating.get('level') or '–')} OF 5</span></div>
      <div class="ink2 small">{esc(rating.get('description', ''))}</div>
      {self.trend_line()}
    </div>
    <div class="plate-path">
      <div class="label">Where this tenant sits on the maturity scale</div>
      {glide_path(ov.get('score'))}
    </div>
  </div>
  <div class="plate-foot">{foot}</div>
</div>"""

    # -- trend --
    @property
    def trend(self) -> Dict[str, Any]:
        return self.f.get("trend") or {}

    def trend_line(self) -> str:
        t = self.trend
        ov = t.get("overall") or {}
        if ov.get("delta") is None:
            return ""
        when = util.parse_iso(t.get("baselineGeneratedAt"))
        since = f' ({esc(when.strftime("%d %b %Y"))})' if when else ""
        if not t.get("comparable", True):
            return (f'<div class="trend small"><span class="delta">≈ not comparable</span> with the previous assessment'
                    f'{since}: the evidence differs ({esc("; ".join(t.get("sourceDiff") or []))}), so '
                    f'{fmt_score(ov.get("before"))} → {fmt_score(ov.get("after"))} is indicative only.</div>')
        d = ov["delta"]
        arrow = "▲" if d > 0 else ("▼" if d < 0 else "■")
        return (f'<div class="trend small"><span class="delta {"up" if d > 0 else ("down" if d < 0 else "")}">'
                f'{arrow} {d:+.1f}</span> vs previous assessment{since}: {fmt_score(ov.get("before"))} → '
                f'{fmt_score(ov.get("after"))} · {t.get("improved", 0)} improved, {t.get("regressed", 0)} regressed</div>')

    def domain_delta(self, key: str) -> str:
        if not self.trend.get("comparable", True):
            return ""
        for d in self.trend.get("domains", []):
            if d["key"] == key and d.get("delta"):
                cls = "up" if d["delta"] > 0 else "down"
                return f'<span class="delta {cls}" title="Change since the previous assessment">{d["delta"]:+.1f}</span>'
        return ""

    def changes_section(self) -> str:
        t = self.trend
        if not t.get("changes"):
            return ""
        rows = []
        for c in t["changes"]:
            arrow = "▲ improved" if c["change"] == "improved" else "▼ regressed"
            rows.append(f'<tr><td style="white-space:nowrap"><span class="delta {"up" if c["change"] == "improved" else "down"}">{arrow}</span></td>'
                        f'<td><a href="#F-{esc(c["id"])}">{esc(c["id"])}</a> {esc(c["title"])}</td>'
                        f'<td style="white-space:nowrap">{status_chip(c["before"])} → {status_chip(c["after"])}</td>'
                        f'<td class="small ink2">{esc(c.get("afterSummary"))}</td></tr>')
        when = util.parse_iso(t.get("baselineGeneratedAt"))
        return (f'<div class="card pad" style="margin-top:16px"><h3>Changes since the previous assessment'
                f'{" (" + esc(when.strftime("%d %b %Y")) + ")" if when else ""}</h3>'
                f'<p class="small ink2" style="margin:4px 0 10px">Findings whose status changed between the two runs. '
                f'Baseline: <code>{esc(Path(t.get("baselineRun") or "").name)}</code>.'
                + ('' if t.get("comparable", True) else
                   f' <b>The evidence differs from the baseline ({esc("; ".join(t.get("sourceDiff") or []))})</b>: a '
                   'change can come from the additional evidence rather than from a configuration change.')
                + '</p>'
                f'<div class="tbl-wrap"><table class="data"><thead><tr><th>Change</th><th>Finding</th><th>Status</th>'
                f'<th>Now</th></tr></thead><tbody>{"".join(rows)}</tbody></table></div></div>')

    # -- executive summary --
    def summary(self) -> str:
        gaps = Counter(x["severity"] for x in self.findings if x["status"] in ("fail", "warn"))
        passes = sum(1 for x in self.findings if x["status"] == "pass")
        tiles = [
            ("high", "High or critical gaps", gaps.get("critical", 0) + gaps.get("high", 0)),
            ("medium", "Medium gaps", gaps.get("medium", 0)),
            ("low", "Low gaps", gaps.get("low", 0)),
            ("pass", "Controls in place", passes),
        ]
        tiles_html = "".join(
            f'<div class="sev-tile {k}"><div class="row">{sev_chip(k) if k != "pass" else chip("pass", "Passed")}</div>'
            f'<div class="value">{n}</div><div class="small ink2">{esc(label)}</div><div class="bar"></div></div>'
            for k, label, n in tiles)
        if self.ai and self.ai.get("executiveSummary"):
            verdict = f'<p class="verdict">{esc(self.ai.get("overallAssessment"))}</p>' if self.ai.get("overallAssessment") else ""
            body = (f'<div class="card pad"><div class="ai-badge" title="Narrative written by the Copilot analysis step '
                    f'from the evidence in this report">AI analysis · {esc(self.ai.get("generatedBy") or "GitHub Copilot")}</div>'
                    f'<div style="height:12px"></div>{verdict}<div class="prose">{md(self.ai["executiveSummary"])}</div></div>')
        else:
            body = f'<div class="card pad"><div class="prose">{md(self.generated_summary())}</div></div>'
        return f"""
<section class="block" id="summary">
  <div class="section-head"><div><h2>Executive summary</h2></div></div>
  {self.plate()}
  <div class="sev-tiles">{tiles_html}</div>
  <div style="height:16px"></div>
  {body}
</section>"""

    def generated_summary(self) -> str:
        ov = self.scores.get("overall") or {}
        doms = [d for d in self.scores.get("domains", []) if d.get("score") is not None]
        doms.sort(key=lambda d: d["score"])
        weakest = ", ".join(f"{d['name']} ({fmt_score(d['score'])})" for d in doms[:3])
        strongest = ", ".join(f"{d['name']} ({fmt_score(d['score'])})" for d in doms[-2:][::-1])
        top = [self.by_id[i] for i in (self.f.get("summary") or {}).get("topRisks", [])[:5] if i in self.by_id]
        lines = [f"The tenant scores **{fmt_score(ov.get('score'))}/100**, which corresponds to maturity level "
                 f"**{ov.get('rating', {}).get('level')} – {ov.get('rating', {}).get('name')}**. "
                 f"{ov.get('rating', {}).get('description', '')}", ""]
        if weakest:
            lines.append(f"The weakest design areas are {weakest}; the strongest are {strongest}.")
            lines.append("")
        if top:
            lines.append("The most important gaps to close:")
            for x in top:
                lines.append(f"- **{x['title']}** ({SEV_LABEL.get(x['severity'], x['severity'])}) – {x.get('summary', '')}")
        lines.append("")
        lines.append("_This summary was generated from the findings. Run the plugin's AI analysis step to add an "
                     "executive narrative, prioritised risks and a roadmap._")
        return "\n".join(lines)

    # -- scorecard --
    def scorecard(self) -> str:
        rows = []
        with_findings = {x["domain"] for x in self.findings}  # only those areas have a findings group to link to
        for d in self.scores.get("domains", []):
            c = d["checks"]
            split = (f"{c['fail']} fail · {c['warn']} warn · {c['pass']} pass"
                     + (f"<br>{c['checklistFailing']}/{c['checklistItems']} checklist items failing" if c["checklistItems"] else ""))
            comment = ""
            if self.ai and (self.ai.get("domainCommentary") or {}).get(d["key"]):
                comment = f'<div class="small ink2" style="margin-top:4px">{esc(self.ai["domainCommentary"][d["key"]])}</div>'
            rating = d.get("rating") or {}
            rows.append(f"""
<tr>
  <td><div class="dname">{f'<a href="#dom-{esc(d["key"])}">{esc(d["name"])}</a>' if d["key"] in with_findings else esc(d["name"])}</div><div class="dblurb">{esc(d['blurb'])}</div>{comment}</td>
  <td style="width:34%">{meter(d.get('score'), d['name'])}{self.domain_delta(d['key'])}</td>
  <td class="nowrap">{chip(_rating_cls(d.get('score')), rating.get('name', 'Not assessed'))}</td>
  <td class="split">{split}</td>
</tr>""")
        return f"""
<section class="block" id="scores">
  <div class="section-head"><div><h2>Scores by design area</h2>
  <p>Each score blends tenant-level governance checks (60%) with Azure review-checklist results (40%), weighted by severity.
  Ticks mark the Defined (60) and Managed (75) thresholds.</p></div></div>
  <div class="card pad"><table class="scorecard">
    <thead><tr><th>Design area</th><th>Score</th><th>Maturity</th><th>Checks</th></tr></thead>
    <tbody>{''.join(rows)}</tbody></table></div>
  {self.changes_section()}
</section>"""

    # -- risks & strengths --
    def risks(self) -> str:
        cards = []
        if self.ai and self.ai.get("keyRisks"):
            for r in self.ai["keyRisks"]:
                sev = (r.get("severity") or "medium").lower()
                refs = "".join(self.finding_link(i) for i in r.get("relatedFindings") or [])
                dom = scoring.DOMAINS.get(r.get("domain") or "", {}).get("name", "")
                cards.append(f"""
<div class="card risk {esc(sev)}">{sev_chip(sev)} <span class="label" style="margin-left:6px">{esc(dom)}</span>
  <h3 class="risk-title">{esc(r.get('title'))}</h3>
  <dl><dt>Why it matters</dt><dd>{esc(r.get('why'))}</dd>
      <dt>Evidence</dt><dd>{esc(r.get('evidence'))}</dd>
      <dt>Do this</dt><dd>{esc(r.get('recommendation'))}</dd></dl>
  <div class="refs">{refs}</div></div>""")
            origin = "Prioritised by the AI analysis step from the evidence below."
        else:
            for fid in (self.f.get("summary") or {}).get("topRisks", [])[:6]:
                x = self.by_id.get(fid)
                if not x:
                    continue
                cards.append(f"""
<div class="card risk {esc(x['severity'])}">{sev_chip(x['severity'])} <span class="label" style="margin-left:6px">{esc(scoring.DOMAINS.get(x['domain'], {}).get('name', ''))}</span>
  <h3 class="risk-title">{esc(x['title'])}</h3>
  <dl><dt>Finding</dt><dd>{esc(x.get('summary'))}</dd>
      <dt>Why it matters</dt><dd>{esc(x.get('details'))}</dd>
      <dt>Do this</dt><dd>{esc(x.get('recommendation'))}</dd></dl>
  <div class="refs">{self.finding_link(x['id'])}</div></div>""")
            origin = "The highest-severity failing checks, ordered by severity."
        strengths = ""
        items = (self.ai or {}).get("strengths") or [
            f"{x['title']} – {x.get('summary', '')}" for x in self.findings
            if x["status"] == "pass" and x["severity"] in ("critical", "high", "medium")][:8]
        if items:
            lis = "".join(f'<li><span class="check" aria-hidden="true">✓</span>{esc(s)}</li>' for s in items)
            strengths = f'<div class="card pad" style="margin-top:16px"><h3>What is working</h3><ul class="strengths" style="list-style:none;padding:0;margin:10px 0 0">{lis}</ul></div>'
        return f"""
<section class="block" id="risks">
  <div class="section-head"><div><h2>Top risks</h2><p>{esc(origin)}</p></div></div>
  <div class="grid-2">{''.join(cards) or '<p class="muted">No failing checks.</p>'}</div>
  {strengths}
</section>"""

    # -- roadmap --
    def roadmap(self) -> str:
        phases: List[Dict[str, Any]] = []
        origin = ""
        if self.ai and self.ai.get("roadmap"):
            phases = self.ai["roadmap"]
            origin = "Sequenced by the AI analysis step."
        else:
            fails = [x for x in self.findings if x["status"] in ("fail", "warn")]
            now = [x for x in fails if x["severity"] in ("critical", "high")]
            nxt = [x for x in fails if x["severity"] == "medium"]
            later = [x for x in fails if x["severity"] == "low"]
            for name, group in (("Now (0–30 days)", now), ("Next (30–90 days)", nxt), ("Later (90–180 days)", later)):
                phases.append({"phase": name, "items": [
                    {"title": x["title"], "detail": x.get("recommendation", ""), "effort": x.get("effort"),
                     "relatedFindings": [x["id"]]} for x in group[:8]]})
            origin = "Derived from finding severity: high first, then medium, then low."
        cols = []
        for p in phases[:3]:
            lis = []
            for it in p.get("items") or []:
                refs = " ".join(self.finding_link(i) for i in it.get("relatedFindings") or [])
                meta = " · ".join(v for v in (f"effort {it['effort']}" if it.get("effort") else "",
                                               it.get("owner") or "") if v)
                lis.append(f'<li><div><b>{esc(it.get("title"))}</b></div><div class="small ink2">{esc(it.get("detail"))}</div>'
                           f'<div class="meta">{esc(meta)} {refs}</div></li>')
            cols.append(f'<div class="card phase"><h3>{esc(p.get("phase"))}</h3><ol>{"".join(lis) or "<li class=muted>Nothing scheduled.</li>"}</ol></div>')
        qw = [self.by_id[i] for i in (self.f.get("summary") or {}).get("quickWins", []) if i in self.by_id]
        quick = ""
        if qw:
            lis = "".join(f'<li><a href="#F-{esc(x["id"])}">{esc(x["title"])}</a> <span class="small muted">– '
                          f'{esc(x.get("recommendation", ""))}</span></li>' for x in qw[:8])
            quick = (f'<div class="card pad quick-card" style="margin-top:16px"><h3>Quick wins</h3><p class="small ink2" '
                     f'style="margin:4px 0 8px">Low-effort fixes for medium-or-higher gaps.</p>'
                     f'<ul class="quick">{lis}</ul></div>')
        return f"""
<section class="block" id="roadmap">
  <div class="section-head"><div><h2>Remediation roadmap</h2><p>{esc(origin)}</p></div></div>
  <div class="roadmap">{''.join(cols)}</div>
  {quick}
</section>"""

    # -- findings --
    def findings_section(self) -> str:
        groups = []
        domains = {d["key"]: d for d in self.scores.get("domains", [])}
        for key, meta in scoring.DOMAINS.items():
            items = [x for x in self.findings if x["domain"] == key]
            if not items:
                continue
            d = domains.get(key, {})
            cards = "".join(self.finding_card(x) for x in items)
            groups.append(f'<div class="domain-group" id="dom-{esc(key)}"><div class="dg-head"><h3>{esc(meta["name"])}</h3>'
                          f'<span class="small muted">{esc(meta["blurb"])}</span><span class="score">score {fmt_score(d.get("score"))}</span></div>{cards}</div>')
        counts = Counter(x["status"] for x in self.findings)
        seg_status = "".join(
            f'<button type="button" aria-pressed="{"true" if s in ("fail", "warn") else "false"}" data-value="{s}">'
            f'<span class="dot" style="background:{c}"></span>{esc(STATUS_LABEL[s])} <span class="muted num">{counts.get(s, 0)}</span></button>'
            for s, c in (("fail", "var(--critical)"), ("warn", "var(--warning)"), ("pass", "var(--good)"),
                         ("info", "var(--neutral)"), ("not_assessed", "var(--rule-strong)")) if counts.get(s))
        seg_sev = "".join(f'<button type="button" aria-pressed="false" data-value="{s}">{esc(SEV_LABEL[s])}</button>'
                          for s in ("critical", "high", "medium", "low", "info") if any(x["severity"] == s for x in self.findings))
        dom_opts = "".join(f'<option value="{k}">{esc(m["name"])}</option>' for k, m in scoring.DOMAINS.items()
                           if any(x["domain"] == k for x in self.findings))
        return f"""
<section class="block" id="findings">
  <div class="section-head"><div><h2>Findings</h2>
  <p>Tenant-level checks computed from AzGovViz output and Azure Resource Graph, grouped by design area.
  <span class="screen-only">Open a finding for the evidence and the fix. Failing and warning findings are shown first; use the
  filters to include passed controls.</span><span class="print-inline">Gaps are shown with evidence and the recommended fix;
  passed and informational checks are listed in one line each.</span></p></div>
  <button type="button" class="more-btn no-print" id="expandAll" aria-pressed="false">Expand all</button></div>
  <div class="filters" data-target="details.finding" data-groups=".domain-group" data-print-all>
    <input type="search" placeholder="Search findings, resources, IDs…" aria-label="Search findings">
    <div class="seg" data-key="status" role="group" aria-label="Status">{seg_status}</div>
    <div class="seg" data-key="severity" role="group" aria-label="Severity">{seg_sev}</div>
    <select data-key="domain" aria-label="Design area"><option value="">All design areas</option>{dom_opts}</select>
    <span class="result-count"></span>
  </div>
  {''.join(groups)}
</section>"""

    def finding_card(self, x: Dict[str, Any]) -> str:
        ev = x.get("evidence") or {}
        ev_html = ""
        if ev.get("rows"):
            numeric = [i for i, c in enumerate(ev.get("columns", [])) if ev["rows"] and all(isinstance(r[i], (int, float)) for r in ev["rows"] if i < len(r))]
            ev_html = data_table(ev.get("columns", []), ev["rows"], numeric)
            if ev.get("total", 0) > len(ev["rows"]):
                ev_html += (f'<div class="trunc-note screen-only">Showing {len(ev["rows"])} of {ev["total"]:,} rows – full data '
                            'in the AzGovViz CSV / inventory files.</div>')
            if ev.get("note"):
                ev_html += f'<div class="trunc-note">{esc(ev["note"])}</div>'
            shown, total = len(ev["rows"]), max(len(ev["rows"]), ev.get("total", 0))
            if shown > PRINT_EVIDENCE_ROWS or total > shown:
                ev_html += (f'<div class="trunc-note print-only">Printed: {min(shown, PRINT_EVIDENCE_ROWS)} of {total:,} rows'
                            + (f"; the HTML report lists {shown:,}" if shown > PRINT_EVIDENCE_ROWS else "")
                            + ("; all rows are in the AzGovViz CSV / inventory files" if total > shown else "")
                            + ".</div>")
            ev_html = f'<div><div class="f-label">Evidence</div>{ev_html}</div>'
        refs = "".join(f'<a href="{esc(safe_url(r.get("url")))}" target="_blank" rel="noopener">{esc(r.get("title"))}</a>'
                       for r in x.get("references") or [] if safe_url(r.get("url")))
        alz = ""
        if x.get("alz"):
            alz = f'<div class="small muted">Evidence for ALZ checklist item(s): {", ".join(f"<code>{esc(g[:8])}</code>" for g in x["alz"])}</div>'
        text = " ".join(str(v) for v in (x["id"], x["title"], x.get("summary"), x.get("details"), x.get("recommendation"),
                                         json.dumps(ev.get("rows", [])[:50], default=str)))
        return f"""
<details class="finding" id="F-{esc(x['id'])}" data-status="{esc(x['status'])}" data-severity="{esc(x['severity'])}" data-domain="{esc(x['domain'])}" data-text="{esc(text.lower()[:6000])}">
  <summary>
    <span>{status_chip(x['status'])}</span>
    <span>{sev_chip(x['severity'])}</span>
    <span class="f-main"><h4 class="f-title"><span class="vh">{esc(x['id'])} · </span>{esc(x['title'])}</h4><div class="f-sum">{esc(x.get('summary'))}</div></span>
    <span class="f-id">{esc(x['id'])}</span>
  </summary>
  <div class="f-body">
    <div class="two">
      <div><div class="f-label">Why it matters</div><p>{esc(x.get('details') or '—')}</p></div>
      <div class="fix"><div class="f-label">Recommendation</div><p>{esc(x.get('recommendation') or '—')}</p>
        <div class="small muted" style="margin-top:6px">Effort: {esc(x.get('effort', 'medium'))} · Source: {esc(x.get('source', ''))}</div></div>
    </div>
    {ev_html}
    {alz}
    {f'<div class="refs">{refs}</div>' if refs else ''}
  </div>
</details>"""

    # -- checklists --
    def checklists_section(self) -> str:
        if not self.cl or not self.cl.get("checklists"):
            return """<section class="block compact" id="checklists"><div class="section-head"><div><h2>Azure review checklists</h2>
<p>Checklist evaluation was not run for this assessment.</p></div></div></section>"""
        src = self.cl.get("source") or {}
        cards = []
        all_rows = []
        for c in self.cl["checklists"]:
            s = c.get("summaryAssisted") or c["summary"]
            sc = s["statusCounts"]
            cats = []
            for cat, cc in sorted(s.get("byCategory", {}).items(), key=lambda kv: -sum(kv[1].values())):
                ev = cc.get("compliant", 0) + cc.get("partial", 0) + cc.get("non_compliant", 0)
                cats.append(f'<tr><td>{esc(cat)}</td><td class="num">{sum(cc.values())}</td><td class="num">{ev}</td>'
                            f'<td>{stacked(cc, show_labels=False, cls="stackbar mini")}</td></tr>')
            assisted_note = ""
            if c.get("summaryAssisted"):
                n = sum(1 for i in c["items"] if i.get("assistedBy"))
                assisted_note = (f'<p class="small ink2" style="margin:8px 0 0">{n} otherwise-manual items were assessed with '
                                 f'tenant evidence (marked <span class="assist">via finding</span>).</p>')
            score = s.get("score")
            rc = s.get("resourceCompliance") or {}
            cards.append(f"""
<div class="card cl-card" id="cl-{esc(c['key'])}">
  <div class="cl-head"><h3>{esc(c['title'])}</h3><span class="label">{esc(c.get('state') or '')} {esc(c.get('timestamp') or '')}</span>
    <span class="score" data-tip="Severity-weighted share of evaluated items that pass">{fmt_score(score)}<small>% items passing</small></span></div>
  <p class="small ink2" style="margin:6px 0 0">{s['items']:,} items · {s['automated']:,} with Resource Graph queries · {s['evaluated']:,} evaluated against resources
  {f"· resource-level compliance {fmt_score(rc.get('percent'))}% ({rc.get('compliant', 0):,} of {rc.get('compliant', 0) + rc.get('nonCompliant', 0):,} resource checks)" if rc.get('percent') is not None else ''}</p>
  {stacked(sc)}
  {legend(sc)}
  {assisted_note}
  <details style="margin-top:12px"><summary class="small" style="cursor:pointer">Results by category</summary>
  <div class="tbl-wrap" style="margin-top:8px"><table class="data cat-table"><thead><tr><th>Category</th><th class="num">Items</th><th class="num">Evaluated</th><th>Status mix</th></tr></thead>
  <tbody>{''.join(cats)}</tbody></table></div></details>
</div>""")
            for item in c["items"]:
                all_rows.append((c, item))
        return f"""
<section class="block" id="checklists">
  <div class="section-head"><div><h2>Azure review checklists</h2>
  <p>Recommendations from <a href="https://github.com/Azure/review-checklists" target="_blank" rel="noopener">Azure/review-checklists</a>
  {f"(commit <code>{esc((src.get('commit') or '')[:7])}</code>)" if src.get('commit') else ''}, evaluated with their Azure Resource Graph queries
  against this tenant. Items without a query need a reviewer; several are answered by tenant evidence from the findings above.
  Results per checklist are also saved in the official <code>checklist_graph.sh</code> format for the review-checklists Excel
  workbook: {' · '.join(f'<a href="{esc(self.base)}/checklists/graph_results_{esc(c["key"])}.json">{esc(c["key"])}</a>' for c in self.cl["checklists"])}.</p></div></div>
  {''.join(cards)}
  {self.items_table(all_rows)}
</section>"""

    def items_table(self, rows: List[Tuple[Dict[str, Any], Dict[str, Any]]]) -> str:
        order = {"non_compliant": 0, "partial": 1, "error": 2, "info": 3, "compliant": 4, "no_data": 5,
                 "not_applicable": 6, "manual": 7}
        include_manual = {"alz"}
        visible_rows = []
        hidden_manual = Counter()
        for c, i in rows:
            st = i.get("assistedStatus") or i["status"]
            if st == "manual" and c["key"] not in include_manual:
                hidden_manual[c["title"]] += 1
                continue
            visible_rows.append((c, i, st))
        visible_rows.sort(key=lambda r: (order.get(r[2], 9), scoring.SEVERITY_ORDER.get((r[1].get("severity") or "").lower(), 9),
                                         r[0]["key"], r[1].get("id") or ""))
        trs = []
        for c, i, st in visible_rows:
            counts = i.get("counts") or {}
            res = ""
            if i.get("resources"):
                rr = [[r.get("name"), "compliant" if r.get("compliant") else ("non-compliant" if r.get("compliant") is False else "–"),
                       r.get("id")] for r in i["resources"]]
                res = data_table(["Resource", "Result", "Resource ID"], rr)
                if i.get("resourcesOmitted"):
                    res += f'<div class="trunc-note">{i["resourcesOmitted"]:,} more resources in checklists/results.json</div>'
            assist = ""
            if i.get("assistedBy"):
                assist = (f'<p><b>Assessed via finding</b> {self.finding_link(i["assistedBy"])} – {esc(i.get("assistedSummary") or "")}</p>')
            fix = i.get("correction") or {}
            q_label = "Resource Graph query (corrected)" if fix.get("action") == "corrected" else "Resource Graph query"
            q = f'<div class="f-label" style="margin-top:10px">{q_label}</div><pre>{esc(i["query"])}</pre>' if i.get("query") else ""
            if fix:
                assist += f'<p><b>Upstream query {esc(fix.get("action"))}.</b> {esc(fix.get("reason"))}</p>'
                if fix.get("upstreamQuery"):
                    q += f'<div class="f-label" style="margin-top:10px">Upstream query (not used)</div><pre>{esc(fix["upstreamQuery"])}</pre>'
            err = f'<p><b>Query error:</b> {esc(i["error"])}</p>' if i.get("error") else ""
            links = " · ".join(f'<a href="{esc(u)}" target="_blank" rel="noopener">{lbl}</a>'
                               for lbl, u in (("Learn more", safe_url(i.get("link"))),
                                              ("Training", safe_url(i.get("training")))) if u)
            counts_txt = ""
            if st in ("compliant", "partial", "non_compliant") and (counts.get("compliant") or counts.get("nonCompliant")):
                counts_txt = f'{counts.get("nonCompliant", 0):,} ✕ / {counts.get("compliant", 0):,} ✓'
            elif st == "info":
                counts_txt = f'{counts.get("resources", 0):,} listed'
            text = f"{i.get('id') or ''} {i.get('guid')} {i.get('text')} {i.get('category')} {i.get('subcategory') or ''} {i.get('service') or ''}".lower()
            dom = i.get("domain") or ""
            trs.append(f"""
<tr class="item-row" data-status="{esc(st)}" data-severity="{esc((i.get('severity') or '').lower())}" data-checklist="{esc(c['key'])}" data-domain="{esc(dom)}" data-text="{esc(text)}">
  <td>{cl_chip(st)}{'<span class="assist">via finding</span>' if i.get('assistedBy') else ''}{f'<span class="assist">query {esc(fix.get("action"))}</span>' if fix else ''}</td>
  <td>{sev_chip((i.get('severity') or 'info').lower())}</td>
  <td><button type="button" class="row-toggle" aria-expanded="false">{esc(i.get('text'))}</button><div class="small muted">{esc(c['key'].upper())} · {esc(i.get('id') or i.get('guid', '')[:8])} · {esc(i.get('category'))}{(' · ' + esc(i.get('subcategory'))) if i.get('subcategory') else ''}</div></td>
  <td class="num nowrap small">{counts_txt}</td>
</tr>
<tr class="detail-row" hidden><td colspan="4">
  {f'<p>{esc(i.get("description"))}</p>' if i.get('description') else ''}
  {assist}{err}
  {res}
  {q}
  <div class="small" style="margin-top:8px">{links} <span class="muted">· GUID <code>{esc(i.get('guid'))}</code></span></div>
</td></tr>""")
        st_counts = Counter(st for _, _, st in visible_rows)
        seg = "".join(
            f'<button type="button" aria-pressed="{"true" if k in ("non_compliant", "partial") else "false"}" data-value="{k}">'
            f'<span class="dot" style="background:{col}"></span>{esc(lbl)} <span class="muted num">{st_counts.get(k, 0)}</span></button>'
            for k, lbl, col in CL_STATUS if st_counts.get(k))
        cl_opts = "".join(f'<option value="{esc(c["key"])}">{esc(c["title"])}</option>' for c in self.cl["checklists"])
        dom_opts = "".join(f'<option value="{k}">{esc(m["name"])}</option>' for k, m in scoring.DOMAINS.items())
        hidden_note = ""
        if hidden_manual:
            hidden_note = ('<p class="small muted">Manual-review items are listed for the ALZ checklist only; '
                           + "; ".join(f"{n:,} manual items of {esc(t)} are in checklists/results.json" for t, n in hidden_manual.items())
                           + ".</p>")
        return f"""
<h3 id="items" style="margin:26px 0 10px">All checklist items</h3>
{hidden_note}
<p class="print-note" id="itemsPrintNote"></p>
<div class="filters" data-target="tr.item-row" data-page="150" data-more="itemsMore" data-print-note="itemsPrintNote">
  <input type="search" placeholder="Search recommendations, IDs, services…" aria-label="Search checklist items">
  <div class="seg" data-key="status" role="group" aria-label="Result">{seg}</div>
  <select data-key="checklist" aria-label="Checklist"><option value="">All checklists</option>{cl_opts}</select>
  <select data-key="severity" aria-label="Severity"><option value="">Any severity</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select>
  <select data-key="domain" aria-label="Design area"><option value="">All design areas</option>{dom_opts}</select>
  <span class="result-count"></span>
</div>
<div class="tbl-wrap" style="max-height:none"><table class="data items-table"><thead><tr><th>Result</th><th>Severity</th><th>Recommendation</th><th class="num">Resources</th></tr></thead>
<tbody>{''.join(trs)}</tbody></table></div>
<button type="button" class="more-btn" id="itemsMore" hidden>Show more</button>"""

    # -- environment --
    def environment(self) -> str:
        hier = self.f.get("hierarchy")
        tree = self.tree_html(hier) if hier else '<p class="muted small">Hierarchy not available (AzGovViz not run).</p>'
        subs = self.f.get("subscriptions") or []
        sub_rows = [[s.get("name"), s.get("id"), s.get("state"), s.get("mgPath") or "", s.get("offer") or "",
                     s.get("resources"), s.get("resourceGroups"),
                     fmt_score(s.get("secureScore")) + ("%" if s.get("secureScore") is not None else ""),
                     s.get("defenderPlansOn"), "yes" if s.get("budget") else ("no" if s.get("budget") is False else "–"),
                     "yes" if s.get("activityLogExport") else ("no" if s.get("activityLogExport") is False else "–")]
                    for s in subs]
        sub_table = data_table(["Subscription", "ID", "State", "Management group path", "Offer", "Resources", "RGs",
                                "Secure score", "Defender plans on", "Budget", "Activity log export"], sub_rows, numeric=[5, 6, 8],
                               cls="data subs-table", label="Subscriptions")
        inv = self.f.get("inventorySummary") or {}
        types = [(re.sub(r"^microsoft\.", "", t["type"]), t["n"]) for t in inv.get("types", [])]
        regions = [(r["location"], r["n"]) for r in inv.get("locations", [])]
        advisor = inv.get("advisor") or []
        adv_rows = [[a.get("category"), a.get("impact"), a.get("problem"), a.get("resources")] for a in advisor[:25]]
        adv_html = data_table(["Category", "Impact", "Recommendation", "Resources"], adv_rows, numeric=[3]) if adv_rows else \
            '<p class="muted small">No Azure Advisor recommendations returned.</p>'
        secrec = inv.get("securityRecommendations") or []
        sec_html = data_table(["Defender for Cloud recommendation", "Severity", "Unhealthy resources"],
                              [[r.get("title"), r.get("severity"), r.get("resources")] for r in secrec[:25]], numeric=[2]) \
            if secrec else '<p class="muted small">No unhealthy Defender for Cloud assessments returned.</p>'
        return f"""
<section class="block" id="environment">
  <div class="section-head"><div><h2>Environment</h2><p>What was assessed: hierarchy, subscriptions and resources.</p></div></div>
  <div class="grid-2">
    <div class="card pad"><h3>Management group hierarchy</h3><div class="tree" style="margin-top:12px">{tree}</div></div>
    <div class="card pad"><h3>Resources by type</h3><div style="margin-top:12px">{hbars(types, 12)}</div>
      <h3 style="margin-top:22px">Resources by region</h3><div style="margin-top:12px">{hbars(regions, 8)}</div></div>
  </div>
  <div class="card pad" style="margin-top:16px"><h3>Subscriptions</h3><div style="margin-top:12px">{sub_table}</div></div>
  <div class="grid-2" style="margin-top:16px">
    <div class="card pad"><h3>Azure Advisor recommendations</h3><div style="margin-top:12px">{adv_html}</div></div>
    <div class="card pad"><h3>Defender for Cloud – unhealthy assessments</h3><div style="margin-top:12px">{sec_html}</div></div>
  </div>
</section>"""

    def tree_html(self, node: Dict[str, Any]) -> str:
        def render(n: Dict[str, Any]) -> str:
            kind = "MG" if n.get("type") == "mg" else "SUB"
            meta = []
            if n.get("policyAssignments") is not None:
                meta.append(f"{n['policyAssignments']} policy")
            if n.get("roleAssignments") is not None:
                meta.append(f"{n['roleAssignments']} RBAC")
            if n.get("resources") is not None:
                meta.append(f"{n['resources']} res")
            label = (f'<span class="node {"mg" if kind == "MG" else "sub"}"><span class="kind">{kind}</span>{esc(n.get("name"))}'
                     f'<span class="meta">{esc(" · ".join(meta))}</span></span>')
            kids = n.get("children") or []
            inner = "".join(render(k) for k in kids)
            return f"<li>{label}{f'<ul>{inner}</ul>' if inner else ''}</li>"
        return f"<ul>{render(node)}</ul>"

    # -- method --
    def method(self) -> str:
        src = self.f.get("sources") or {}
        azv = src.get("azgovviz") or {}
        stage = azv.get("stage") or {}
        cls = (src.get("checklists") or {})
        clsrc = cls.get("source") or {}
        q = cls.get("queries") or {}
        links = []
        if azv.get("html"):
            links.append(f'<a href="{esc(self.base)}/azgovviz/{esc(azv["html"])}">AzGovViz HTML report</a>')
        links.append(f'<a href="{esc(self.base)}/analysis/findings.json">findings.json</a>')
        links.append(f'<a href="{esc(self.base)}/analysis/brief.md">brief.md</a>')
        if cls.get("available"):
            links.append(f'<a href="{esc(self.base)}/checklists/results.json">checklists/results.json</a>')
        links.append(f'<a href="{esc(self.base)}/inventory.json">inventory.json</a>')
        inv_err = (src.get("inventory") or {}).get("errors") or {}
        limitations = []
        if not azv.get("available"):
            limitations.append("AzGovViz did not run or produced no output; platform findings rely on Resource Graph only.")
        if inv_err:
            limitations.append("Some Resource Graph / ARM probes were unavailable: " + ", ".join(sorted(inv_err)) + ".")
        for e in self.f.get("analyzerErrors") or []:
            limitations.append(f"Analyzer {e['analyzer']} failed: {e['error']}")
        if self.ai_problems:
            limitations.append("AI insights file has validation warnings: " + "; ".join(self.ai_problems[:5]))
        if self.ai and (self.ai.get("notes") or "").strip():
            limitations.append("AI analysis notes: " + self.ai["notes"].strip())
        if not cls.get("available"):
            limitations.append("The Azure review checklists were not evaluated (skipped or could not be downloaded).")
        limitations.append("Checklist queries return what the signed-in identity can read; items without a query need human review.")
        lim = "".join(f"<li>{esc(l)}</li>" for l in limitations)
        steps = []
        if azv.get("available"):
            took = f" in {util.human_duration(stage.get('durationSec') or 0)}" if stage.get("durationSec") else ""
            steps.append(f"<li><b>AzGovViz</b> {esc(azv.get('version') or '')} collected the management group hierarchy, "
                         f"Azure Policy, RBAC, Defender for Cloud, network and resource data read-only{took}.</li>")
        if (src.get("inventory") or {}).get("available"):
            steps.append("<li><b>Azure Resource Graph</b> provided inventory, Defender for Cloud, Advisor, policy-state and "
                         "configuration evidence.</li>")
        corrections = cls.get("corrections") or []
        if cls.get("available"):
            keys = ", ".join(c.get("key", "").upper() for c in (self.cl or {}).get("checklists", []))
            commit = f" from commit <code>{esc((clsrc.get('commit') or '')[:7])}</code>" if clsrc.get("commit") else ""
            fixed = (f" {len(corrections)} upstream {'query that does' if len(corrections) == 1 else 'queries that do'} "
                     f"not test what the item says {'was' if len(corrections) == 1 else 'were'} corrected or set aside "
                     "(listed below).") if corrections else ""
            steps.append(f"<li><b>Azure review checklists</b> ({esc(keys)}) were evaluated with "
                         f"{fmt_int(q.get('unique'))} Resource Graph queries{commit}.{fixed}</li>")
        steps = "".join(steps)
        corr_card = ""
        if corrections:
            rows = [[f"{'/'.join(k.upper() for k in c.get('checklists') or [])} {c.get('id') or (c.get('guid') or '')[:8]}",
                     c.get("text"), c.get("action"), c.get("reason")] for c in corrections]
            corr_card = f"""
  <div class="card pad corr-card" style="margin-top:16px"><h3>Checklist query corrections</h3>
    <p class="small ink2" style="margin:6px 0 10px">These Azure/review-checklists queries do not test what their item says, so a
    corrected query ran instead, or the item was set aside for manual review. A correction stops applying once the upstream
    query no longer has the defect.</p>
    {data_table(["Item", "Recommendation", "Action", "Why"], rows, cls="data corr-table", label="Checklist query corrections")}</div>"""
        return f"""
<section class="block" id="method">
  <div class="section-head"><div><h2>Method and sources</h2></div></div>
  <div class="grid-2">
    <div class="card pad"><h3>How this assessment was produced</h3>
      <ol class="prose small" style="margin-top:10px">
        {steps}
        <li>Findings are scored by severity (high 3, medium 2, low 1; warnings earn half credit). Design-area scores blend tenant checks (60%)
        and checklist results (40%); the overall score is the mean of assessed design areas.</li>
        <li>Maturity levels: Initial &lt;40, Developing 40–59, Defined 60–74, Managed 75–89, Optimized ≥90.</li>
      </ol></div>
    <div class="card pad"><h3>Run details</h3>
      <dl class="kv" style="margin-top:12px">
        <dt>Run folder</dt><dd class="mono">{esc(self.dir)}</dd>
        <dt>Generated</dt><dd>{esc(self.f.get('generatedAt'))}</dd>
        <dt>Tool</dt><dd>{esc(TOOL_NAME)} {esc(__version__)} (GitHub Copilot CLI plugin)</dd>
        <dt>Signed-in identity</dt><dd>{esc(((stage.get('prepare') or {}).get('account')) or '–')}</dd>
        <dt>Token source</dt><dd>{esc((self.f.get('scope') or {}).get('tokenProvider') or '–')}</dd>
        <dt>Raw data</dt><dd>{' · '.join(links)}</dd>
      </dl>
      <h3 style="margin-top:18px">Limitations</h3><ul class="small" style="margin:8px 0 0">{lim}</ul></div>
  </div>{corr_card}
</section>"""

    # -- page --
    # -- print / PDF --
    def print_cover(self) -> str:
        """First PDF page: who, when, the score and where it sits on the maturity scale (hidden on screen)."""
        ov = self.scores.get("overall") or {}
        rating = ov.get("rating") or {}
        facts = self.facts
        src = self.f.get("sources") or {}
        azv = src.get("azgovviz") or {}
        clsrc = (src.get("checklists") or {}).get("source") or {}
        evidence = []
        if azv.get("available"):
            evidence.append(f"AzGovViz {azv.get('version') or ''}".strip())
        if (src.get("inventory") or {}).get("available"):
            evidence.append("Azure Resource Graph")
        if (src.get("checklists") or {}).get("available"):
            evidence.append("Azure review checklists" + (f" @{clsrc.get('commit', '')[:7]}" if clsrc.get("commit") else ""))
        gaps = sum(1 for x in self.findings if x["status"] in ("fail", "warn") and x["severity"] in ("critical", "high"))
        evaluated = sum((c.get("evaluated") or 0) for c in (self.f.get("summary") or {}).get("checklists", []))
        stats = [("Subscriptions", facts.get("subscriptions")), ("Resources", facts.get("resources")),
                 ("Policy assignments", facts.get("policyAssignments")), ("Role assignments", facts.get("roleAssignments")),
                 ("High-severity gaps", gaps), ("Checklist items tested", evaluated if facts.get("checklistQueries") else None)]
        stats_html = "".join(f'<div><div class="n">{fmt_int(v)}</div><div class="k">{esc(k)}</div></div>' for k, v in stats)
        verdict = ""
        if self.ai and self.ai.get("overallAssessment"):
            verdict = (f'<div class="pc-verdict"><div class="q">{esc(self.ai["overallAssessment"])}</div>'
                       f'<span class="src">AI analysis · {esc(self.ai.get("generatedBy") or "GitHub Copilot")}</span></div>')
        scope = (self.f.get("scope") or {}).get("description") or "Tenant root management group"
        ids = " · ".join(v for v in (self.tenant.get("defaultDomain"), self.tenant.get("tenantId")) if v)
        return f"""
<section class="print-cover">
  <div class="pc-band">
    <div class="pc-mark">{LOGO_SVG}<span>Azure governance assessment</span></div>
    <div class="pc-tenant{" xlong" if len(self.tenant_name) > 70 else (" long" if len(self.tenant_name) > 36 else "")}">{esc(self.tenant_name)}</div>
    <div class="pc-ids">{esc(ids)}</div>
    <div class="pc-meta">
      <div><span class="k">Scope</span><span class="v">{esc(scope)}</span></div>
      <div><span class="k">Assessed</span><span class="v">{esc(self.date())}</span></div>
      <div><span class="k">Evidence</span><span class="v">{esc(" · ".join(evidence) or "n/a")}</span></div>
    </div>
  </div>
  <div class="pc-body">
    <div class="pc-score">
      <div class="label">Governance maturity score</div>
      <div class="pc-num">{fmt_score(ov.get('score'))}<small>/ 100</small></div>
      <div class="pc-level"><span class="lvl">Level {esc(rating.get('level') or '–')} of 5</span>{esc(rating.get('name', 'Not assessed'))}
        <p>{esc(rating.get('description', ''))}</p></div>
      {self.trend_line()}
    </div>
    <div class="pc-path">{glide_path(ov.get('score'))}</div>
    {verdict}
    <div class="pc-stats">{stats_html}</div>
  </div>
  <div class="pc-foot">
    <div><b>Read-only assessment.</b> Evidence was collected with read permissions only; verify findings before acting.
      Not an official Microsoft attestation.</div>
    <div><b>Confidential.</b> Contains tenant configuration data (identities, scopes, resource names).</div>
    <div>Prepared with the {esc(TOOL_NAME)} {esc(__version__)} plugin for GitHub Copilot CLI.</div>
  </div>
</section>"""

    def print_toc(self) -> str:
        """Contents page of the PDF. Page numbers come from the first print pass and are only shown in the exported
        PDF (html.pdf-export), because a reader's own browser may paginate differently."""
        sections = [("summary", "Executive summary", []), ("scores", "Scores by design area", []),
                    ("risks", "Top risks", []), ("roadmap", "Remediation roadmap", []),
                    ("findings", "Findings", [(f"dom-{k}", m["name"]) for k, m in scoring.DOMAINS.items()
                                              if any(x["domain"] == k for x in self.findings)]),
                    ("checklists", "Azure review checklists",
                     [(f"cl-{c['key']}", c.get("title") or c["key"]) for c in (self.cl or {}).get("checklists", [])]
                     + ([("items", "All checklist items")] if (self.cl or {}).get("checklists") else [])),
                    ("environment", "Environment", []), ("method", "Method and sources", [])]

        def entry(level: int, anchor: str, title: str, num: str = "", section: str = "") -> str:
            page = self.toc_pages.get(section + TOC_SEP + title if section else title)
            return (f'<li class="l{level}"><a href="#{esc(anchor)}"><span class="n">{esc(num)}</span>'
                    f'<span class="t">{esc(title)}</span><span class="dots"></span>'
                    f'<span class="p">{page if page else ""}</span></a></li>')

        items = []
        for i, (anchor, title, subs) in enumerate(sections, 1):
            items.append(entry(1, anchor, title, str(i)))
            items.extend(entry(2, a, t, section=title) for a, t in subs)
        return (f'<section class="print-toc"><div class="label">Azure governance assessment · '
                f'{esc(self.tenant_name)}</div><h2 class="toc-title">Contents</h2><ol>{"".join(items)}</ol></section>')

    def page_css(self) -> str:
        """Running footer for the PDF: CSS page-margin boxes need literal strings, so they are generated here."""
        name = self.tenant_name if len(self.tenant_name) <= 42 else self.tenant_name[:40].rstrip() + "…"
        left = css_str(f"Azure Governance Assessment · {name} · {self.date()}")
        box = ('font: 500 8pt/1.3 "Segoe UI", -apple-system, "Helvetica Neue", Arial, sans-serif; color: #5f6877; '
               'white-space: nowrap;')
        return (f"@page {{ @bottom-left {{ content: {left}; {box} }} "
                f"@bottom-right {{ content: \"Page \" counter(page) \" of \" counter(pages); {box} }} }} "
                "@page :first { @bottom-left { content: none; } @bottom-right { content: none; } }")

    def render(self) -> str:
        css = (ASSETS / "report.css").read_text(encoding="utf-8") + EXTRA_CSS
        print_css = (ASSETS / "report-print.css").read_text(encoding="utf-8") + self.page_css()
        js = (ASSETS / "report.js").read_text(encoding="utf-8")
        fails = sum(1 for x in self.findings if x["status"] in ("fail", "warn"))
        cl_fail = sum((c.get("statusCounts") or {}).get("non_compliant", 0) + (c.get("statusCounts") or {}).get("partial", 0)
                      for c in (self.f.get("summary") or {}).get("checklists", []))
        nav = [("summary", "Executive summary", ""), ("scores", "Scores by design area", ""), ("risks", "Top risks", ""),
               ("roadmap", "Roadmap", ""), ("findings", "Findings", str(fails)), ("checklists", "Review checklists", str(cl_fail)),
               ("environment", "Environment", ""), ("method", "Method and sources", "")]
        nav_html = "".join(f'<a href="#{k}">{esc(t)}<span class="count">{esc(c)}</span></a>' for k, t, c in nav)
        title = f"Azure Governance Assessment – {self.tenant_name} – {self.date()}"
        return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="{esc(TOOL_NAME)} {esc(__version__)}">
<title>{esc(title)}</title>
<style>{css}</style>
<style media="print">{print_css}</style>
</head>
<body>
{self.print_cover()}
{self.print_toc()}
<header class="topbar"><div class="topbar-inner">
  <div class="mark">{LOGO_SVG}<span>Governance assessment</span></div>
  <h1 class="title">{esc(self.tenant_name)} · {esc(self.date())}</h1>
  <div class="spacer"></div>
  <button type="button" id="themeToggle" aria-label="Toggle dark mode">Theme</button>
  <button type="button" id="printBtn">Print / PDF</button>
</div></header>
<div class="layout">
  <nav class="toc" aria-label="Sections"><div class="label">Contents</div>{nav_html}</nav>
  <main>
    {self.summary()}
    {self.scorecard()}
    {self.risks()}
    {self.roadmap()}
    {self.findings_section()}
    {self.checklists_section()}
    {self.environment()}
    {self.method()}
  </main>
</div>
<footer class="foot">Generated by the {esc(TOOL_NAME)} plugin for GitHub Copilot CLI from AzGovViz (Azure Governance Visualizer)
and Azure/review-checklists evidence. Read-only assessment; verify findings before acting. Not an official Microsoft attestation.</footer>
<div id="tip" aria-hidden="true"></div>
<script>{js}</script>
</body>
</html>"""


EXTRA_CSS = """
.meter-h { display: flex; align-items: center; gap: 10px; }
.meter-h .track { position: relative; flex: 1; height: 10px; border-radius: 5px; background: var(--track); overflow: hidden; min-width: 120px; }
.meter-h .fill { position: absolute; left: 0; top: 0; bottom: 0; border-radius: 5px; }
.meter-h .tick { position: absolute; top: -2px; bottom: -2px; width: 2px; background: var(--panel); }
.meter-h .val { font: 650 15px/1 var(--display); min-width: 34px; text-align: right; }
.stackbar { display: flex; gap: 2px; height: 26px; margin: 14px 0 10px; }
.stackbar > div { min-width: 3px; display: flex; align-items: center; justify-content: center; font: 650 12px/1 var(--sans); color: #0f1b2d; }
.stackbar > div:first-child { border-radius: 5px 0 0 5px; }
.stackbar > div:last-child { border-radius: 0 5px 5px 0; }
.stackbar > div:only-child { border-radius: 5px; }
.stackbar > div.on-dark { color: #fff; }
.stackbar > div.seg-manual { box-shadow: inset 0 0 0 1px var(--rule-strong); }
.stackbar > div.seg-manual, .stackbar > div.seg-no_data { color: var(--ink); }  /* theme-dependent backgrounds */
.stackbar.mini { height: 10px; margin: 2px 0; min-width: 140px; }
.hbars { display: grid; gap: 7px; }
.hb-row { display: grid; grid-template-columns: minmax(120px, 46%) minmax(0, 1fr) 54px; gap: 10px; align-items: center; font-size: 13px; }
.hb-label { color: var(--ink-2); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-family: var(--mono); font-size: 12px; }
.hb-track { height: 14px; display: block; }
.hb-fill { display: block; height: 14px; background: var(--series-1); border-radius: 0 4px 4px 0; min-width: 2px; }
.hb-val { text-align: right; font-weight: 600; }
.trend { margin-top: 6px; color: var(--ink-2); }
.delta { font: 700 12.5px/1 var(--mono); padding: 2px 6px; border-radius: 5px; background: var(--neutral-wash); color: var(--ink); white-space: nowrap; }
.delta.up { background: var(--good-wash); }
.delta.down { background: var(--critical-wash); }
td .delta { margin-left: 8px; }
ul.quick { margin: 0; padding-left: 18px; }
ul.quick li { margin: 6px 0; }
"""


def _rating_cls(score: Optional[float]) -> str:
    if score is None:
        return "not_assessed"
    if score >= 75:
        return "pass"
    if score >= 50:
        return "warn"
    return "fail"


def render_run(run_dir: Path, output: Optional[Path] = None, toc_pages: Optional[Dict[str, int]] = None) -> Path:
    rep = Report(run_dir, output.parent if output else None, toc_pages)
    page = rep.render()
    if output is None:
        label = util.slug((rep.tenant.get("defaultDomain") or rep.tenant_name).split(".")[0], 30)
        stamp = rep.assessed_at.strftime("%Y%m%d")
        output = run_dir / "report" / f"Azure-Governance-Assessment_{label}_{stamp}.html"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(page, encoding="utf-8")
    return output


BROWSERS = [
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    "microsoft-edge", "google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "msedge", "chrome",
]


def find_browser() -> Optional[str]:
    import shutil
    for b in BROWSERS:
        if ("/" in b or "\\" in b) and Path(b).exists():
            return b
        if "/" not in b and "\\" not in b and shutil.which(b):
            return shutil.which(b)
    return None


def export_pdf(html_path: Path, pdf_path: Optional[Path] = None, timeout: int = 180) -> Optional[Path]:
    """Print the report to PDF with a headless Edge/Chrome (print stylesheet, all findings expanded).

    Some headless browser builds keep running after writing the PDF, so the file is polled and the browser is
    stopped once the PDF is complete.
    """
    import time as _time
    browser = find_browser()
    if not browser:
        util.warn("PDF export skipped: no Edge/Chrome/Chromium found")
        return None
    pdf_path = pdf_path or html_path.with_suffix(".pdf")
    if pdf_path.exists():
        try:
            pdf_path.unlink()
        except PermissionError:  # Windows: the previous PDF is open in a viewer
            pdf_path = pdf_path.with_name(f"{pdf_path.stem}-{_time.strftime('%H%M%S')}{pdf_path.suffix}")
            util.warn(f"the previous PDF is in use; writing {pdf_path.name} instead")
    for attempt in range(1, 4):  # a headless browser now and then exits without writing (busy machine, profile lock)
        if _print_to_pdf(browser, html_path, pdf_path, timeout):
            return pdf_path
        if pdf_path.exists():
            pdf_path.unlink()
        if attempt < 3:
            util.debug(f"PDF export attempt {attempt} produced no file; retrying")
            _time.sleep(2 * attempt)
    util.warn("PDF export failed (browser produced no file)")
    return None


def _print_to_pdf(browser: str, html_path: Path, pdf_path: Path, timeout: int) -> bool:
    import shutil
    import subprocess
    import tempfile
    import time as _time
    profile = tempfile.mkdtemp(prefix="azgov-pdf-")
    try:
        proc = subprocess.Popen([browser, "--headless=new", "--disable-gpu", "--no-pdf-header-footer",
                                 "--generate-pdf-document-outline",  # PDF bookmarks from the headings
                                 "--no-first-run", "--no-default-browser-check", f"--user-data-dir={profile}",
                                 f"--print-to-pdf={pdf_path}", "--virtual-time-budget=5000",
                                 html_path.resolve().as_uri() + "#print"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = _time.time() + timeout
        last_size, stable = -1, 0
        try:
            while _time.time() < deadline:
                if proc.poll() is not None and not pdf_path.exists():
                    break
                if pdf_path.exists():
                    size = pdf_path.stat().st_size
                    stable = stable + 1 if size == last_size and size > 0 else 0
                    last_size = size
                    if stable >= 3 or (proc.poll() is not None and size > 0):
                        break
                _time.sleep(0.5)
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
    finally:
        shutil.rmtree(profile, ignore_errors=True)  # Edge may still touch its profile for a moment
    return pdf_path.exists() and pdf_path.stat().st_size > 0


# ----------------------------------------------------------------------------------------------
# PDF contents page: two print passes; page numbers are read back from the PDF outline (bookmarks)
# ----------------------------------------------------------------------------------------------
def _pdf_string(raw: bytes) -> str:
    if raw.startswith(b"<"):
        data = bytes.fromhex(raw[1:-1].decode("ascii"))
        return data[2:].decode("utf-16-be", "replace") if data[:2] == b"\xfe\xff" else data.decode("latin-1")
    body, out, i = raw[1:-1], bytearray(), 0
    escapes = {b"n": b"\n", b"r": b"\r", b"t": b"\t", b"b": b"\b", b"f": b"\f", b"(": b"(", b")": b")", b"\\": b"\\"}
    while i < len(body):
        c = body[i:i + 1]
        if c == b"\\" and i + 1 < len(body):
            nxt = body[i + 1:i + 2]
            if nxt in escapes:
                out += escapes[nxt]
                i += 2
                continue
            m = re.match(rb"[0-7]{1,3}", body[i + 1:i + 4])
            if m:
                out.append(int(m.group(0), 8) & 0xFF)
                i += 1 + len(m.group(0))
                continue
            i += 1
            continue
        out += c
        i += 1
    data = bytes(out)
    return data[2:].decode("utf-16-be", "replace") if data[:2] == b"\xfe\xff" else data.decode("latin-1")


TOC_SEP = " › "  # key separator for second-level contents entries ("Findings › Security")


def pdf_outline_pages(pdf_path: Path) -> Dict[str, int]:
    """Page numbers of the PDF bookmarks, keyed "Section" and "Section › Sub-heading" (walking the outline tree,
    so equal titles in different sections - e.g. a "### Security" heading in the summary - cannot collide).
    Works for the uncompressed PDFs that Chromium writes; {} if the outline cannot be read."""
    try:
        data = pdf_path.read_bytes()
        objs = {int(m.group(1)): m.group(2) for m in re.finditer(rb"(\d+) 0 obj(.*?)endobj", data, re.S)}
        root = next(o for o in objs.values() if re.search(rb"/Type\s*/Catalog", o))

        def ref(obj: bytes, key: bytes) -> Optional[int]:
            m = re.search(rb"/" + key + rb"\s+(\d+) 0 R", obj)
            return int(m.group(1)) if m else None

        order: List[int] = []

        def walk_pages(num: int) -> None:
            obj = objs.get(num, b"")
            kids = re.search(rb"/Kids\s*\[([^\]]*)\]", obj)
            if re.search(rb"/Type\s*/Pages", obj) and kids:
                for k in re.findall(rb"(\d+) 0 R", kids.group(1)):
                    walk_pages(int(k))
            else:
                order.append(num)
        walk_pages(ref(root, b"Pages"))
        index = {num: i + 1 for i, num in enumerate(order)}
        out: Dict[str, int] = {}

        def walk_items(first: Optional[int], prefix: str, depth: int) -> None:
            num, seen = first, set()
            while num is not None and num not in seen and depth < 8:
                seen.add(num)
                obj = objs.get(num, b"")
                t = re.search(rb"/Title\s*(\((?:\\.|[^\\)])*\)|<[0-9A-Fa-f]*>)", obj, re.S)
                d = re.search(rb"/Dest\s*\[\s*(\d+) 0 R", obj) or re.search(rb"/D\s*\[\s*(\d+) 0 R", obj)
                title = _pdf_string(t.group(1)).strip() if t else ""
                key = prefix + title
                if title and d and int(d.group(1)) in index:
                    out.setdefault(key, index[int(d.group(1))])
                walk_items(ref(obj, b"First"), key + TOC_SEP, depth + 1)
                num = ref(obj, b"Next")
        walk_items(ref(objs.get(ref(root, b"Outlines"), b""), b"First"), "", 0)
        return out
    except Exception as exc:  # the contents page then simply has no page numbers
        util.debug(f"PDF outline not readable: {exc}")
        return {}


def build_pdf(run_dir: Path, html_path: Path, pdf_path: Optional[Path] = None) -> Optional[Path]:
    """Print the report to PDF; a first pass finds the page of every section for the contents page."""
    probe = export_pdf(html_path, html_path.with_name(html_path.stem + ".pass1.pdf"))
    if not probe:
        return None
    pages = pdf_outline_pages(probe)
    try:
        probe.unlink()
    except OSError:
        pass
    if pages:
        render_run(run_dir, html_path, toc_pages=pages)
    return export_pdf(html_path, pdf_path)
