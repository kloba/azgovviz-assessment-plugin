---
description: Run a full Azure governance assessment (AzGovViz + Azure review checklists) and produce the HTML report
argument-hint: "[tenant-id] [--subscriptions id1,id2] [--checklists alz,waf,aprl] [--consumption]"
---

Use the `azure-governance-assessment` skill to run a complete Azure governance assessment.

Arguments from the user (may be empty): $ARGUMENTS

1. If no tenant ID is given, list tenants with the skill's `tenants` command and ask which one to assess.
2. Confirm scope and options, run `doctor`, handle sign-in, then run the assessment.
3. Write the AI analysis (`analysis/ai-insights.json`), validate it, render the report.
4. Summarise the score, maturity level, top risks (with finding IDs), quick wins and the report path.
