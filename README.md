# ☁️ Azure Security Monitoring Lab

## 📌 Overview
This project demonstrates hands-on experience with cloud security monitoring using Microsoft Azure. The lab focuses on detecting suspicious activity, analyzing logs, and creating alerts in a cloud environment.

## 🛠️ Tools Used
- Microsoft Azure  
- Log Analytics Workspace  
- Microsoft Defender for Cloud  
- Windows Virtual Machine  

## 🎯 Objectives
- Monitor cloud-based systems  
- Analyze authentication and security events  
- Detect suspicious activity  
- Create alert rules  
- Simulate SOC workflows  

## 🔍 Use Cases

### Failed Login Detection
SecurityEvent
| where EventID == 4625

### Successful Login Tracking
SecurityEvent
| where EventID == 4624

## 🚨 Detection Capabilities
- Brute-force login detection  
- Cloud activity monitoring  
- User authentication tracking  
- Alert-based threat detection  

## 🧠 Skills Demonstrated
- Azure Security  
- Cloud Monitoring  
- Log Analysis  
- Incident Detection  
- Security Operations  

## 📸 Screenshots
## 📸 Screenshots

### Azure Log Analysis
![Azure Logs](azure-logs.png)

### Alert Rule Triggered
![Azure Alert](azure-alert.png)

## 📸 Screenshots

### Azure Log Analysis (Log Analytics Workspace)
![Azure Logs](azure-logs-realistic.png)

### Alert Rule Configuration (Azure Monitor)
![Azure Alert](azure-alert-realistic.png)

## 📈 Outcome
This lab demonstrates practical experience with cloud-based security monitoring, detection engineering, and incident response workflows aligned with enterprise environment
