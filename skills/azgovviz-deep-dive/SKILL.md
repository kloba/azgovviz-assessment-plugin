---
name: azgovviz-deep-dive
description: Answer detailed questions about an existing Azure governance assessment run or AzGovViz output folder - who holds Owner where, which policy assignments are not enforced, orphaned role assignments, Defender plan gaps, non-compliant checklist items, resources by subscription - by querying the run's JSON and AzGovViz CSV files. Use after an assessment exists, or when the user points at an AzGovViz output folder.
---

# AzGovViz / assessment deep dive

Use this skill to answer follow-up questions with evidence from files - no new Azure calls are needed.

## Locate the data

- Assessment runs live in `./azgov-assessments/<tenant>_<timestamp>/` (newest = latest). The user may also
  point at a plain AzGovViz output folder (files named `AzGovViz_<version>_<timestamp>_<mgId>_*.csv`).
- Key files in a run:
  - `analysis/findings.json` - scored findings (`id`, `domain`, `severity`, `status`, `summary`, `evidence`).
  - `analysis/checklists.assessed.json` - every checklist item with `status`, `counts`, `resources`, `query`.
  - `inventory.json` - Resource Graph inventory (subscriptions, type counts, Defender plans, Advisor, Key Vault,
    storage, NSG exposure, budgets, activity-log export...).
  - `azgovviz/*.csv` - AzGovViz exports, **semicolon-delimited**. See
    `../azure-governance-assessment/references/azgovviz-outputs.md` for what each file contains.

## How to answer

1. Prefer the structured JSON first; go to the CSVs for row-level detail.
2. Use Python for CSV queries (handles quoting and the `;` delimiter), for example:

   ```bash
   python3 - <<'EOF'
   import csv, glob
   path = glob.glob('azgov-assessments/*/azgovviz/*_RoleAssignments.csv')[-1]
   rows = list(csv.DictReader(open(path, encoding='utf-8-sig'), delimiter=';'))
   owners = [r for r in rows if r.get('Role') == 'Owner']
   for r in owners[:50]:
       print(r.get('Scope'), r.get('ObjectType'), r.get('ObjectDisplayName'), r.get('ObjectSignInName'))
   EOF
   ```

   Inspect the header line first (`head -1 file.csv`) - column names differ between AzGovViz versions.
3. Quote counts and name scopes precisely; cite finding IDs and checklist IDs where relevant.
4. Respect privacy: summarise identities unless the user asks for names; never paste whole CSVs.
5. If the question needs data that was not collected (e.g. consumption without `--consumption`), say so and
   offer the exact command to re-run that part.
