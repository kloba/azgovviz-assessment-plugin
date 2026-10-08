---
name: azure-governance-assessment
description: Run a complete Azure governance assessment of a Microsoft Entra tenant - executes AzGovViz (Azure Governance Visualizer), evaluates the Azure/review-checklists (Azure Landing Zone, Well-Architected, APRL) with Azure Resource Graph, scores nine design areas, writes an AI analysis and produces a self-contained HTML assessment report. Use when the user asks to assess, audit or review Azure governance, landing zones, Azure Policy, RBAC/privileged access, Defender for Cloud coverage, or to "run AzGovViz" on a tenant.
---

# Azure governance assessment (AzGovViz + Azure review checklists)

This skill turns a tenant into an evidence-based governance assessment:

1. **AzGovViz** collects the management-group hierarchy, Azure Policy, RBAC, PIM, Defender for Cloud,
   network, resource and cost data (read-only).
2. **Azure Resource Graph** adds inventory, Defender/Advisor/policy-state and configuration evidence.
3. **Azure/review-checklists** items (ALZ, WAF, APRL by default) are evaluated with their own Resource Graph queries.
4. A deterministic engine produces ~50 scored findings across nine design areas and a maturity level.
5. **You (Copilot)** read the brief and write the AI analysis (executive summary, key risks, roadmap).
6. The engine renders one self-contained HTML report (works offline, prints to PDF).

Everything is driven by one launcher in this skill's folder: `scripts/azgov-assess` (on Windows:
`pwsh scripts/azgov-assess.ps1`). Paths below are relative to this skill's directory - resolve them to
absolute paths before running commands, and run the commands from the user's working directory so the
`azgov-assessments/` output folder is created there.

## Ground rules

- **Read-only.** Never run commands that change Azure resources, policies or role assignments, even if a
  finding recommends it. Recommend; do not remediate.
- Never print, log or store access tokens. Do not `cat` credential files.
- Outputs contain sensitive tenant data (identities, resource IDs). Keep them local; do not upload them
  anywhere. Offer `--scrub-pii` when the user is sensitive about user names in role assignments.
- Do not invent facts. Every statement in the AI analysis must trace back to `analysis/findings.json`,
  `analysis/checklists.assessed.json`, `inventory.json` or the AzGovViz CSVs.

## Workflow

### Step 1 - Pick the tenant and scope

If the user did not give a tenant ID, list what is available and ask which one to assess:

```bash
scripts/azgov-assess tenants
```

Confirm the scope before a long run (defaults in bold):
- **Whole tenant (tenant root management group)**, a specific management group (`--management-group`),
  or specific subscriptions (`--subscriptions id1,id2`).
- Checklists: **`alz,waf,aprl`**; see `scripts/azgov-assess list-checklists` (e.g. add `aks`, `avd`, `ai_lz`).
- Optional: `--consumption` (cost data, slower), `--scrub-pii`, `--quick` (no PIM, fewer details),
  `--alz-policy-checker` (only for ALZ-shaped hierarchies).

### Step 2 - Preflight and sign-in

```bash
scripts/azgov-assess doctor --tenant <TENANT_ID>
```

- `azpwsh-context` must be OK: AzGovViz runs in PowerShell 7 with the Az PowerShell context.
  If it fails, the user has to sign in interactively (MFA). Ask them to run this themselves - in Copilot CLI
  they can prefix it with `!`:

  ```bash
  ! <absolute path>/scripts/azgov-assess login --tenant <TENANT_ID>        # browser sign-in
  ! <absolute path>/scripts/azgov-assess login --tenant <TENANT_ID> --device-code   # headless
  ```
- `tenant-root-read` WARN means the identity lacks Reader on the root management group. AzGovViz needs
  Reader on the target management group; offer `--management-group <id>` or `--subscriptions ...`, or the
  Resource-Graph-only mode (`--skip-azgovviz`).
- If PowerShell 7 is missing and cannot be installed, use `--skip-azgovviz` (Resource Graph + checklists only)
  and say clearly that platform findings will be limited.

### Step 3 - Run the assessment

```bash
scripts/azgov-assess run --tenant <TENANT_ID> [--subscriptions ...] [--checklists alz,waf,aprl] [--consumption]
```

- Duration: a few minutes for small tenants, 30+ minutes for large ones (AzGovViz dominates). Run it as a
  long-running command (async/detached shell, generous timeout) and poll its output; relay progress lines.
  The full AzGovViz console log is in `<run>/azgovviz/azgovviz-console.log`.
- Exit code 10 = sign-in required (go back to Step 2). Exit code 2 = no data could be collected.
- The command prints a JSON summary with `runDir`, `report`, `brief`, `overallScore`.

### Step 4 - Write the AI analysis (this is your job)

1. Read `<run>/analysis/brief.md` completely. Open `<run>/analysis/findings.json` for evidence rows and
   `<run>/analysis/checklists.assessed.json` for checklist details when you need more depth. For drill-downs
   use the AzGovViz CSVs in `<run>/azgovviz/` (semicolon-delimited; see `references/azgovviz-outputs.md`).
2. Run `scripts/azgov-assess insights-template --run-dir <run>` - it writes
   `analysis/ai-insights.template.json` and prints the schema.
3. Write `<run>/analysis/ai-insights.json` following `references/analysis-playbook.md`:
   - `executiveSummary`: 2-4 short markdown paragraphs for a CIO/CISO audience: posture and score, the
     2-3 risks that matter most and why, what to do first. Quantify (counts, percentages).
   - `overallAssessment`: one-sentence verdict.
   - `strengths`: 3-6 evidence-backed positives.
   - `keyRisks`: 4-8 items, ordered by business risk (not by count), each with `relatedFindings` IDs that
     exist in findings.json, plus concrete evidence and an actionable recommendation.
   - `roadmap`: three phases (Now 0-30 days / Next 30-90 days / Later 90-180 days) with sequenced,
     dependency-aware items (e.g. management-group hierarchy before policy assignment at MG scope).
   - `domainCommentary`: one to three sentences per assessed design area, interpreting the score.
4. Validate, then render the final report:

```bash
scripts/azgov-assess validate-insights --run-dir <run>
scripts/azgov-assess report --run-dir <run>
```

Fix every validation error before rendering (unknown finding IDs, TODO text, wrong severities).

### Step 5 - Present the result

Reply with: overall score and maturity level, the three to five most important risks (one line each, with
finding IDs), quick wins, and the absolute path of the HTML report. Offer to open it
(`open <file>` on macOS, `start <file>` on Windows, `xdg-open <file>` on Linux) and to drill into any area.

## Re-running pieces

| Need | Command |
|---|---|
| Only Resource Graph inventory + checklists (no PowerShell) | `scripts/azgov-assess run --tenant <id> --skip-azgovviz` |
| Re-evaluate checklists into an existing run | `scripts/azgov-assess checklists --run-dir <run> --tenant <id> -c alz,waf,aprl,aks` |
| Re-analyse after changing data | `scripts/azgov-assess analyze --run-dir <run>` |
| Re-render report (e.g. after editing ai-insights.json) | `scripts/azgov-assess report --run-dir <run>` |
| Also produce a PDF (headless Edge/Chrome) | `scripts/azgov-assess report --run-dir <run> --pdf` |
| Compare with an earlier assessment of the same tenant | `scripts/azgov-assess report --run-dir <run> --baseline <older run>` (or `run ... --baseline <older run>`) |
| Use an offline AzGovViz / checklist clone | `--azgovviz-path <dir>` / `--checklists-path <dir>` |

## Troubleshooting

| Symptom | Fix |
|---|---|
| `No usable Az PowerShell sign-in` / exit 10 | User runs `scripts/azgov-assess login --tenant <id>` (MFA in browser). |
| `AADSTS700082` / refresh token expired (az CLI) | Harmless if Az PowerShell works (`--auth azpwsh`); else `az login --tenant <id>`. |
| `AuthorizationFailed` at management group | Need Reader on the MG; use `--subscriptions` or ask an admin. |
| PIM errors in AzGovViz log | Re-run with `--no-pim` (needs Entra ID P2 / Graph permission). |
| Checklist download fails (proxy) | Clone github.com/Azure/review-checklists and pass `--checklists-path`. |
| Very large tenant (>500 subscriptions) | Add `--quick` and `--azgovviz-args '{"LargeTenant": true}'`. |

## Files in a run folder

```
azgov-assessments/<tenant>_<timestamp>/
  run.json                       stage status, timings, options
  azgovviz/                      AzGovViz HTML/CSV/JSON/MD output + console log
  inventory.json                 Resource Graph + ARM evidence
  checklists/results.json        raw checklist evaluation (+ graph_results_<key>.json for the Excel importer)
  analysis/findings.json         scored findings, facts, domain scores
  analysis/checklists.assessed.json  checklist items with design area and tenant-evidence assists
  analysis/brief.md              compact brief for the AI step
  analysis/ai-insights.json      written by you in Step 4
  report/Azure-Governance-Assessment_<tenant>_<date>.html
```
