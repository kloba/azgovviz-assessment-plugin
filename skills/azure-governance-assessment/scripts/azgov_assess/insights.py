"""AI insights contract: the JSON file GitHub Copilot writes after reading analysis/brief.md.

The deterministic engine produces facts, scores and findings. The Copilot agent adds judgement:
an executive narrative, prioritised risks, a phased roadmap and per-domain commentary. The renderer
merges `analysis/ai-insights.json` into the HTML report (and the report stays complete without it).
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Tuple

SCHEMA = "azgov-assess/ai-insights@1"

SCHEMA_DOC = {
    "schema": SCHEMA,
    "generatedBy": "string - e.g. 'GitHub Copilot CLI (<model>)'",
    "executiveSummary": "markdown, 2-4 short paragraphs for executives: posture, biggest risks, what to do first",
    "overallAssessment": "one sentence verdict",
    "strengths": ["string - evidence-backed things that are done well (3-6)"],
    "keyRisks": [{
        "title": "string", "severity": "critical|high|medium|low",
        "domain": "identity|resource_org|governance|security|network|management|resiliency|cost|performance",
        "why": "business impact in plain language", "evidence": "concrete facts from findings/checklists",
        "recommendation": "specific, actionable fix", "relatedFindings": ["finding ids e.g. IAM-003"],
    }],
    "roadmap": [{
        "phase": "Now (0-30 days)|Next (30-90 days)|Later (90-180 days)",
        "items": [{"title": "string", "detail": "string", "effort": "low|medium|high",
                   "owner": "suggested team/role", "relatedFindings": ["ids"]}],
    }],
    "domainCommentary": {"<domain key>": "1-3 sentences interpreting the domain score"},
    "notes": "caveats / data limitations (optional)",
}

_SEVERITIES = {"critical", "high", "medium", "low"}
_DOMAINS = {"identity", "resource_org", "governance", "security", "network", "management", "resiliency", "cost",
            "performance"}


def template(findings: Dict[str, Any]) -> Dict[str, Any]:
    failing = [f for f in findings.get("findings", []) if f.get("status") in ("fail", "warn")]
    failing.sort(key=lambda f: ({"critical": 0, "high": 1, "medium": 2, "low": 3}.get(f.get("severity"), 4), f["id"]))
    return {
        "schema": SCHEMA,
        "generatedBy": "GitHub Copilot CLI",
        "executiveSummary": "TODO: 2-4 paragraphs (markdown).",
        "overallAssessment": "TODO",
        "strengths": [],
        "keyRisks": [{"title": f["title"], "severity": f["severity"], "domain": f["domain"], "why": "TODO",
                      "evidence": f.get("summary", ""), "recommendation": f.get("recommendation", ""),
                      "relatedFindings": [f["id"]]} for f in failing[:6]],
        "roadmap": [{"phase": "Now (0-30 days)", "items": []}, {"phase": "Next (30-90 days)", "items": []},
                    {"phase": "Later (90-180 days)", "items": []}],
        "domainCommentary": {d["key"]: "TODO" for d in findings.get("scores", {}).get("domains", [])
                             if d.get("score") is not None},
        "notes": "",
        "_instructions": "Replace every TODO, delete this key, save as analysis/ai-insights.json, then run "
                         "`azgov-assess report --run-dir <run>`. Every claim must be supported by findings.json, "
                         "checklists/results.json or inventory.json.",
    }


def load(path: Any) -> Tuple[Any, List[str]]:
    """(data, problems) for analysis/ai-insights.json; invalid JSON is a problem, never a crash."""
    try:
        with open(path, "r", encoding="utf-8-sig") as fh:
            return json.load(fh), []
    except FileNotFoundError:
        return None, []
    except ValueError as exc:
        return None, [f"ai-insights.json is not valid JSON: {exc}"]


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _ids(value: Any, where: str, known_ids: set, problems: List[str]) -> None:
    if value is None:
        return
    if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
        problems.append(f"{where}.relatedFindings must be a list of finding id strings")
        return
    for fid in value:
        if known_ids and fid not in known_ids:
            problems.append(f"{where} references unknown finding id '{fid}'")


def validate(data: Dict[str, Any], findings: Dict[str, Any]) -> List[str]:
    """Problems that would make the report wrong or unrenderable. Every element is type-checked, so a file that
    validates also renders."""
    problems: List[str] = []
    if not isinstance(data, dict):
        return ["root must be a JSON object"]
    known_ids = {f.get("id") for f in (findings or {}).get("findings", [])}
    if data.get("schema") != SCHEMA:
        problems.append(f"schema must be '{SCHEMA}'")
    summary = data.get("executiveSummary")
    if not isinstance(summary, str) or len(summary.strip()) < 80 or "TODO" in summary:
        problems.append("executiveSummary must be a substantive markdown string (no TODO)")
    for key in ("overallAssessment", "generatedBy", "notes"):
        if data.get(key) is not None and not isinstance(data.get(key), str):
            problems.append(f"{key} must be a string")
    if "TODO" in str(data.get("overallAssessment") or ""):
        problems.append("overallAssessment still contains TODO")
    strengths = data.get("strengths")
    if strengths is not None and (not isinstance(strengths, list) or not all(_text(x) for x in strengths)):
        problems.append("strengths must be a list of non-empty strings")

    risks = data.get("keyRisks")
    if risks is not None and not isinstance(risks, list):
        problems.append("keyRisks must be a list")
        risks = []
    for i, risk in enumerate(risks or []):
        if not isinstance(risk, dict):
            problems.append(f"keyRisks[{i}] must be an object")
            continue
        if not isinstance(risk.get("severity"), str) or risk["severity"].lower() not in _SEVERITIES:
            problems.append(f"keyRisks[{i}].severity must be one of {sorted(_SEVERITIES)}")
        if risk.get("domain") is not None and not (isinstance(risk.get("domain"), str) and risk["domain"] in _DOMAINS):
            problems.append(f"keyRisks[{i}].domain '{risk.get('domain')}' is not a known domain key")
        _ids(risk.get("relatedFindings"), f"keyRisks[{i}]", known_ids, problems)
        for key in ("title", "why", "recommendation"):
            if not _text(risk.get(key)) or "TODO" in risk[key]:
                problems.append(f"keyRisks[{i}].{key} is missing (non-empty string, no TODO)")
        if risk.get("evidence") is not None and not isinstance(risk.get("evidence"), str):
            problems.append(f"keyRisks[{i}].evidence must be a string")

    roadmap = data.get("roadmap")
    if roadmap is not None and not isinstance(roadmap, list):
        problems.append("roadmap must be a list of phases")
        roadmap = []
    for i, phase in enumerate(roadmap or []):
        if not isinstance(phase, dict) or not isinstance(phase.get("items", []), list):
            problems.append(f"roadmap[{i}] must be an object with an items list")
            continue
        if phase.get("phase") is not None and not isinstance(phase.get("phase"), str):
            problems.append(f"roadmap[{i}].phase must be a string")
        for j, item in enumerate(phase.get("items") or []):
            where = f"roadmap[{i}].items[{j}]"
            if not isinstance(item, dict):
                problems.append(f"{where} must be an object with title/detail/effort/owner")
                continue
            if not _text(item.get("title")) or "TODO" in item["title"]:
                problems.append(f"{where}.title is missing")
            for key in ("detail", "effort", "owner"):
                if item.get(key) is not None and not isinstance(item.get(key), str):
                    problems.append(f"{where}.{key} must be a string")
            _ids(item.get("relatedFindings"), where, known_ids, problems)

    commentary = data.get("domainCommentary")
    if commentary is not None and not isinstance(commentary, dict):
        problems.append("domainCommentary must be an object keyed by domain")
        commentary = {}
    for key, text in (commentary or {}).items():
        if not isinstance(key, str) or key not in _DOMAINS:
            problems.append(f"domainCommentary key '{key}' is not a known domain")
        elif not isinstance(text, str):
            problems.append(f"domainCommentary.{key} must be a string")
        elif "TODO" in text:
            problems.append(f"domainCommentary.{key} still contains TODO")
    if "_instructions" in data:
        problems.append("remove the _instructions key")
    return problems


def sanitize(data: Any) -> Any:
    """Coerce a (possibly invalid) insights file into the shape the renderer expects; drops what cannot be used.
    `validate()` still reports the problems - this only guarantees the report renders."""
    if not isinstance(data, dict):
        return None

    def text(value: Any) -> str:
        return value if isinstance(value, str) else ("" if value is None else str(value))

    def ids(value: Any) -> List[str]:
        return [x for x in value if isinstance(x, str)] if isinstance(value, list) else []

    out: Dict[str, Any] = {k: text(data.get(k)) for k in ("schema", "generatedBy", "executiveSummary",
                                                          "overallAssessment", "notes") if data.get(k) is not None}
    out["strengths"] = [text(x) for x in data.get("strengths") or [] if isinstance(x, (str, int, float))] \
        if isinstance(data.get("strengths"), list) else []
    risks = []
    for r in data.get("keyRisks") or [] if isinstance(data.get("keyRisks"), list) else []:
        if not isinstance(r, dict):
            continue
        sev = text(r.get("severity")).lower()
        risks.append({"title": text(r.get("title")), "severity": sev if sev in _SEVERITIES else "medium",
                      "domain": r["domain"] if isinstance(r.get("domain"), str) and r["domain"] in _DOMAINS else None,
                      "why": text(r.get("why")), "evidence": text(r.get("evidence")),
                      "recommendation": text(r.get("recommendation")), "relatedFindings": ids(r.get("relatedFindings"))})
    out["keyRisks"] = risks
    phases = []
    for p in data.get("roadmap") or [] if isinstance(data.get("roadmap"), list) else []:
        if not isinstance(p, dict):
            continue
        items = []
        for it in p.get("items") or [] if isinstance(p.get("items"), list) else []:
            if isinstance(it, str):
                it = {"title": it}
            if isinstance(it, dict):
                items.append({"title": text(it.get("title")), "detail": text(it.get("detail")),
                              "effort": text(it.get("effort")), "owner": text(it.get("owner")),
                              "relatedFindings": ids(it.get("relatedFindings"))})
        phases.append({"phase": text(p.get("phase")), "items": items})
    out["roadmap"] = phases
    commentary = data.get("domainCommentary")
    out["domainCommentary"] = {k: v for k, v in commentary.items() if k in _DOMAINS and isinstance(v, str)} \
        if isinstance(commentary, dict) else {}
    return out
