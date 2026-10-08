---
description: Evaluate Azure review checklists (ALZ, WAF, APRL...) with Azure Resource Graph - no PowerShell needed
argument-hint: "[tenant-id] [--checklists alz,waf,aprl,aks] [--subscriptions id1,id2]"
---

Use the `azure-review-checklists` skill to evaluate Azure/review-checklists items against the tenant with
Azure Resource Graph and produce the HTML report (Resource-Graph-only mode, AzGovViz is skipped).

Arguments from the user (may be empty): $ARGUMENTS

Ask for the tenant if it is missing, run the evaluation, then summarise the checklist scores, the High-severity
non-compliant items and the report path.
