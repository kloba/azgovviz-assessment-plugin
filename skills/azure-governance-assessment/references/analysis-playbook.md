# AI analysis playbook

How to turn `analysis/brief.md` (+ findings, checklists, inventory) into `analysis/ai-insights.json`.
The deterministic engine already scored everything; your job is **judgement**: what matters most for this
tenant, why, and in which order to fix it.

## 1. Read in this order

1. `analysis/brief.md` - facts, domain scores, failing findings with recommendations, checklist summaries and
   the top failing checklist items.
2. `analysis/findings.json` - `findings[].evidence` holds the rows behind each finding (scopes, principals,
   resources). Use them to quantify and to name scopes precisely.
3. `analysis/checklists.assessed.json` - per checklist item: `status`, `counts`, `resources`, `domain`,
   `assistedBy` (item answered with a platform finding).
4. `inventory.json` - Resource Graph evidence (Defender plans, secure score, Advisor, storage/Key Vault posture,
   NSG exposure, budgets, activity-log export, Service Health alerts).
5. AzGovViz CSVs (`azgovviz/*.csv`, `;`-delimited) only for drill-downs.

If the brief has a **"Trend vs previous assessment"** section (the run was compared with `--baseline`), say in
the executive summary which way the tenant is moving: the score change, the findings that improved and,
first, any that regressed. A regression of a high-severity control belongs in `keyRisks`.

## 2. Prioritise by business risk, not by count

Rank risks with this order of precedence (ties broken by blast radius = scope x number of resources):

1. **Privileged access exposure** - Owner/User Access Administrator held by guests, service principals,
   standing (non-PIM) human owners, assignments at tenant root, orphaned assignments, classic administrators,
   custom roles with `*` actions.
2. **Missing guardrails at scale** - no policy assignments at management-group scope, no security baseline
   initiative (Microsoft cloud security benchmark), no allowed-locations policy, policies in DoNotEnforce.
3. **Data exposure / internet attack surface** - public blob access, storage/Key Vault open to all networks,
   management ports (22/3389) open to the internet, Key Vaults without purge protection.
4. **Threat protection and detection gaps** - Defender for Cloud plans off, no security contacts, no
   activity-log export / central Log Analytics, no Service Health alerts.
5. **Structural debt** - flat or root-attached hierarchy, no platform/landing-zone separation, no sandbox.
6. **Resilience** - APRL/WAF reliability gaps on production resources (zones, replication, backup).
7. **Cost and hygiene** - no budgets, orphaned resources, tagging and naming gaps.

A *single* guest Owner on a production subscription outranks fifty missing tags.

## 3. What good looks like (CAF Azure landing zone reference)

| Design area | Good |
|---|---|
| Resource organization | Intermediate root MG under Tenant Root; Platform (Management, Connectivity, Identity) and Landing Zones (Corp, Online) MGs; Sandbox and Decommissioned MGs; no subscriptions under Tenant Root; default MG for new subscriptions is not the root; MG creation requires authorization; hierarchy <= 4 levels; tags for owner/cost-center/environment. |
| Identity & access | Roles assigned to groups; PIM for privileged roles; 2-3 owners per subscription; no guest/service-principal owners; no custom roles with wildcard actions; no orphaned assignments; no classic administrators; least privilege at the lowest practical scope. |
| Governance & policy | Initiatives assigned at intermediate-root/landing-zone MGs (MCSB, ALZ defaults); Deny/DeployIfNotExists guardrails enforced; allowed locations; tagging policies; exemptions time-bound; ALZ policies current. |
| Security | Defender CSPM + workload plans (Servers, Storage, Key Vault, ARM, SQL, Containers, App Service) on all subscriptions; security contacts and alert notifications set; secure score tracked. |
| Management | One central Log Analytics workspace (per region/sovereignty need); subscription activity logs exported; Service Health and Resource Health alerts; resource locks on shared platform resources; backup for stateful workloads. |
| Network | Hub-and-spoke or Virtual WAN; private endpoints for PaaS; no management ports open to the internet; DDoS protection on internet-facing VNets; subnet capacity headroom. |
| Resiliency / performance | Zone-redundant SKUs and deployments, geo-redundant data, tested DR (APRL / WAF reliability). |
| Cost | Budgets with alerts per subscription; Advisor cost recommendations actioned; orphaned disks/IPs/NICs removed. |

Scale the advice to the estate: for a small or lab tenant, recommend the minimal viable version (e.g. a
three-level hierarchy and a handful of policies), not a full enterprise landing zone programme.

## 4. Writing the JSON

```json
{
  "schema": "azgov-assess/ai-insights@1",
  "generatedBy": "GitHub Copilot CLI (<model name>)",
  "overallAssessment": "One sentence: the posture and the single most important thing to fix.",
  "executiveSummary": "2-4 short markdown paragraphs ...",
  "strengths": ["Evidence-backed positive (with the number)", "..."],
  "keyRisks": [
    {
      "title": "Short, specific risk name",
      "severity": "critical|high|medium|low",
      "domain": "identity",
      "why": "Business impact in one or two sentences.",
      "evidence": "Exact counts/scopes from the findings.",
      "recommendation": "Concrete, scoped action.",
      "relatedFindings": ["IAM-002", "IAM-004"]
    }
  ],
  "roadmap": [
    {"phase": "Now (0-30 days)", "items": [{"title": "...", "detail": "...", "effort": "low", "owner": "Platform team", "relatedFindings": ["IAM-002"]}]},
    {"phase": "Next (30-90 days)", "items": []},
    {"phase": "Later (90-180 days)", "items": []}
  ],
  "domainCommentary": {"identity": "1-3 sentences interpreting the score and what drives it."},
  "notes": "Data limitations worth stating (optional)."
}
```

Rules:

- `relatedFindings` must use IDs that exist in `findings.json` (validation fails otherwise). Checklist
  references go in the text (e.g. "ALZ B03.07").
- Severity scale: `critical` only for exploitable, tenant-wide exposure (e.g. guest Owner at root);
  otherwise high/medium/low consistent with the findings.
- Executive summary structure: (1) posture + score + maturity in plain words; (2) the two or three risks that
  matter and their business impact; (3) what to do first and the expected effect. No bullet soup, no hype,
  no hedging when evidence is clear; state limitations once.
- Roadmap: sequence by dependency (hierarchy -> policy assignment scope; groups/PIM -> remove direct owners;
  logging -> alerting). Put low-effort high-impact items in "Now". 3-6 items per phase.
- Strengths must be real and specific ("Defender for Servers P2 on all 3 subscriptions"), never filler.
- Length guide: executive summary 200-350 words, 4-8 key risks, 3-6 roadmap items per phase, 1-3 sentences per
  domain commentary. File size does not matter - do not spend effort trimming it; write it once, validate, render.

## 5. Before rendering

- `azgov-assess validate-insights --run-dir <run>` returns no errors.
- Every number you quote appears in the evidence.
- Every risk has a recommendation a platform engineer can act on.
