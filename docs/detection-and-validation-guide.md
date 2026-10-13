# Azure Security Monitoring: Detection and Validation Guide

These examples are for authorized cloud-security labs and must be validated against your own Azure Log Analytics workspace before operational use.

## Prerequisites

- An Azure subscription and authorized lab resources.
- Log Analytics workspace and configured diagnostic collection.
- Windows authentication hunting requires Windows Security events in the `SecurityEvent` table.
- Entra ID sign-in hunting requires `SigninLogs` ingestion, subject to your tenant's supported configuration and licensing.
- Microsoft Sentinel is optional for ad hoc Log Analytics queries; scheduled analytics rules require appropriate Sentinel configuration.

## Windows failed logons (4625)

```kql
SecurityEvent
| where TimeGenerated >= ago(24h)
| where EventID == 4625
| summarize FailedLogons=count() by Computer, Account, bin(TimeGenerated, 15m)
| where FailedLogons >= 5
| order by FailedLogons desc
```

## Windows successful logons (4624)

```kql
SecurityEvent
| where TimeGenerated >= ago(24h)
| where EventID == 4624
| summarize SuccessfulLogons=count() by Computer, Account, bin(TimeGenerated, 1h)
| order by SuccessfulLogons desc
```

## Entra ID sign-in hunting

See [failed sign-ins followed by success](../detections/failed-signins-followed-by-success.kql) for an example sequence hunt. This is an investigative lead, not proof of account compromise.

## Lab validation checklist

1. Confirm each expected table is populated and inspect its schema.
2. Run the query over a short interval in your authorized workspace.
3. Generate safe, benign test events and verify the expected results.
4. Investigate false positives and tune thresholds before enabling alerts.
5. Record the query, date, observations, and configuration without exposing credentials or personal data.

## SOC triage

Verify event context, correlate account and source IP activity, scope related events, document findings, and follow approved response procedures before any containment.

> These examples have not been executed against a live Azure tenant in this pull request.
