---
name: azure-review-checklists
description: Evaluate the Azure/review-checklists (Azure Landing Zone, Well-Architected, APRL, AKS, AVD, AI landing zone and more) against a tenant or subscriptions using their Azure Resource Graph queries, without running AzGovViz or PowerShell, and produce the HTML report. Use when the user wants checklist/landing-zone/WAF compliance results quickly, or cannot run PowerShell.
---

# Azure review checklists (Resource Graph only)

This skill reuses the engine of the `azure-governance-assessment` skill (sibling folder) in
Resource-Graph-only mode. The launcher is `../azure-governance-assessment/scripts/azgov-assess`
(resolve to an absolute path; on Windows use `pwsh ../azure-governance-assessment/scripts/azgov-assess.ps1`).

## What it does

- Downloads the selected checklists from https://github.com/Azure/review-checklists (cached for 24 h) and
  runs every item's Resource Graph query against the scope.
- Interprets the three query conventions used in the repository:
  - `compliant` column -> per-resource compliant / non-compliant,
  - APRL convention (rows are the non-compliant resources) -> combined with the resource inventory so
    unaffected resources count as compliant and absent resource types become "Not applicable",
  - plain listings -> "Evidence for review".
- Items without a query are kept as "Manual review" (ALZ items are listed in the report as a worksheet).
- Writes `checklists/graph_results_<key>.json` in the format of the repository's `checklist_graph.sh`, which
  the review-checklists Excel workbook can import ("Import Graph Results").

## Steps

1. Tenant: if missing, run `<launcher> tenants` and ask. Sign-in only needs an ARM token: Azure CLI
   (`az login --tenant <id>`) **or** Az PowerShell (`<launcher> login --tenant <id>`). The user must run
   interactive sign-ins themselves (prefix with `!` in Copilot CLI).
2. Choose checklists: default `alz,waf,aprl`. `<launcher> list-checklists` shows the catalogue;
   `<launcher> list-checklists --remote` lists every checklist in the repository.
3. Run:

   ```bash
   <launcher> run --tenant <TENANT_ID> --skip-azgovviz --checklists alz,waf,aprl [--subscriptions id1,id2]
   ```

   Typical duration 1-5 minutes (about 300 unique queries for the default set; Resource Graph throttling
   is handled automatically).
4. Optionally write the AI analysis exactly as in Step 4 of the `azure-governance-assessment` skill, then
   `<launcher> report --run-dir <run>`.
5. Summarise per checklist: score (% of evaluated items passing, severity-weighted), counts by status, the
   High-severity non-compliant items with the number of affected resources, and the report path.

## Interpreting results honestly

- "No matching resources" means the query returned nothing; for resource-specific checks this usually means
  the service is not deployed. It is excluded from scores.
- A checklist score only covers automated items. Say how many items still need manual review.
- Queries see only what the signed-in identity can read.
