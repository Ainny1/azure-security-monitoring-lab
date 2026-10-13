# Azure Security Monitoring — Reproducible Lab Guide

This is a **validation plan**, not a claim that alerts have been deployed or detections have succeeded. Use only an Azure subscription and Windows VM you own or are authorized to administer. Keep cloud costs in mind; remove lab resources when finished.

## Architecture and prerequisites

- Azure subscription and a dedicated resource group.
- Windows VM with security auditing enabled.
- Log Analytics workspace and a supported data collection configuration that routes Windows Security events to the workspace.
- Appropriate Azure RBAC permissions to configure collection and read logs.

> **Important:** The `SecurityEvent` table is populated only when Windows Security event collection has been correctly configured. Azure Activity Logs and Entra sign-in logs are separate data sources with different schemas.

## Step 1 — Verify data ingestion

In the workspace Logs view, run:

```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| summarize Events=count(), Latest=max(TimeGenerated) by Computer, EventID
| order by Events desc
```

If the table does not exist or returns no data, check the data collection rule, VM association, agent health, audit policy, workspace selection, and ingestion latency. Do not treat missing events as proof that no suspicious activity occurred.

## Step 2 — Investigate failed logons (4625)

```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4625
| summarize FailedAttempts=count(), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated)
    by Computer, Account, IpAddress, bin(TimeGenerated, 5m)
| where FailedAttempts >= 5
| order by FailedAttempts desc
```

This is a **triage heuristic**, not confirmed brute force. Check account context, source address availability, expected administrative activity, and possible false positives. Field population varies by event and collection method.

## Step 3 — Investigate successful logons (4624)

```kusto
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4624
| summarize Logons=count() by Computer, Account, LogonType
| order by Logons desc
```

Successful logons are routine. Investigate only with supporting context and appropriate baselines.

## Step 4 — Validate safely

1. Record the VM name, workspace, collection rule, and time range (redact identifiers before publishing).
2. Generate a small number of expected sign-in events using **your own test account** on the isolated VM. Avoid lockouts.
3. Wait for ingestion, rerun the queries, and note whether events appeared.
4. Save redacted screenshots of the query, timestamp, and result count.
5. Document negative results and troubleshooting rather than claiming success.

## Step 5 — Optional alert exercise

Once events are flowing, consider a scheduled query alert based on the failed-logon query. Define evaluation frequency, threshold, suppression, and notification action group; test with benign events and record whether the alert actually fired. Alert availability, naming, pricing, and configuration vary by Azure environment. **Do not claim a working alert without evidence.**

## Evidence template

| Item | Record |
| --- | --- |
| Lab date (UTC) | Not yet recorded |
| VM / workspace (redacted) | Not yet recorded |
| Data source and collection rule | Not yet recorded |
| Query and time range | Not yet recorded |
| Expected result | Not yet recorded |
| Observed result | Not yet recorded |
| Alert fired? | Not tested |
| False positives / gaps | Not yet evaluated |

## Security, privacy, and cost notes

Use synthetic accounts and non-sensitive test data. Never upload credentials, tokens, connection strings, patient data, or unredacted production logs. Restrict network exposure and permissions. Review Azure billing and delete the resource group or lab resources when finished.

## Scope and limitations

The queries depend on the `SecurityEvent` schema and valid Windows event ingestion. They do not validate Microsoft Defender for Cloud recommendations, Entra ID sign-ins, or production incident response. Screenshots alone do not establish reproducibility or detection accuracy.
