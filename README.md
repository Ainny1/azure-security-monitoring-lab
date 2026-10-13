# Azure Security Monitoring Lab

A portfolio lab for exploring cloud log collection, Microsoft Sentinel hunting queries, and security operations workflows. The repository includes examples; it does **not** claim that the included detections have been validated in a production tenant.

## Architecture and prerequisites

- Azure subscription and an appropriately permissioned lab tenant.
- Log Analytics workspace with relevant diagnostic data ingestion.
- For Entra ID sign-in hunting: the `SigninLogs` table must be populated via diagnostic settings and supported licensing/configuration.
- For Windows authentication examples: the `SecurityEvent` table requires a configured collection path for Windows Security events. Azure Monitor Agent and data collection rules may be required.
- Optional: Microsoft Sentinel enabled on the workspace.

## Detection examples

### Windows failed logons (Event ID 4625)

```kql
SecurityEvent
| where TimeGenerated >= ago(24h)
| where EventID == 4625
| summarize FailedLogons=count() by Computer, Account, bin(TimeGenerated, 15m)
| where FailedLogons >= 5
| order by FailedLogons desc
```

### Windows successful logons (Event ID 4624)

```kql
SecurityEvent
| where TimeGenerated >= ago(24h)
| where EventID == 4624
| summarize SuccessfulLogons=count() by Computer, Account, bin(TimeGenerated, 1h)
| order by SuccessfulLogons desc
```

### Microsoft Entra ID sign-in sequence

See [`detections/failed-signins-followed-by-success.kql`](detections/failed-signins-followed-by-success.kql) for a hunting query identifying repeated failed sign-ins followed by a success from the same user and IP. This is an investigation lead, not proof of compromise.

## Validation checklist

1. Confirm the expected table contains data and check the actual schema.
2. Run each query over a short time window in a lab workspace.
3. Verify that expected test events appear and review false positives.
4. Tune failure thresholds and exclude known benign automation only after investigation.
5. Record the results, query cost, and any alert configuration before enabling scheduled rules.

## Screenshots from the original lab

### Azure log analysis

<img width="1006" height="600" alt="Azure log analysis screenshot" src="https://github.com/user-attachments/assets/50f6ae4d-908e-4c8c-b908-f6a06c690fd8" />

### Alert rule triggered

<img width="1000" height="500" alt="Alert rule screenshot" src="https://github.com/user-attachments/assets/9ec06aab-76c7-488f-8a60-ff3644ad5159" />

### Outcome

<img width="479" height="283" alt="Original lab outcome screenshot" src="https://github.com/user-attachments/assets/bfe37127-e01e-4568-b5e3-f5b91f8a2b76" />

## Security and scope

Use only systems and Azure resources you own or are explicitly authorized to test. Do not commit secrets, access tokens, tenant credentials, or personal data. Lab screenshots should be reviewed for sensitive identifiers before publication.

## Skills demonstrated

Azure monitoring, KQL, authentication-event analysis, detection engineering fundamentals, and SOC-style investigation documentation.
