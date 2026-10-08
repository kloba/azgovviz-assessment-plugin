---
description: Check prerequisites, sign-in and permissions for an Azure governance assessment
argument-hint: "[tenant-id]"
---

Use the `azure-governance-assessment` skill's `doctor` command to check readiness for an assessment.

Arguments from the user (may be empty): $ARGUMENTS

Report each check (PowerShell 7, Az.Accounts, AzAPICall, Python, GitHub reachability, ARM token, Az PowerShell
context, Reader at the tenant root) and explain how to fix anything that fails. If sign-in is required, give the
user the exact `login` command to run themselves with the `!` prefix.
