---
description: Re-render (and optionally re-analyse) the PDF and HTML report of an existing assessment run
argument-hint: "[run folder] [--reanalyze]"
---

Use the `azure-governance-assessment` skill to re-render the PDF and HTML report for an existing run folder.

Arguments from the user (may be empty): $ARGUMENTS

- If no run folder is given, use the newest folder under `./azgov-assessments/`.
- If `analysis/ai-insights.json` is missing or the user asks for a fresh analysis, write it first (Step 4 of
  the skill), validate it, then run the `report` command.
- Reply with the PDF path (and the HTML path) and offer to open it.
