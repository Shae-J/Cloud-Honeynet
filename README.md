# Building a SOC + Honeynet in Azure (Live Traffic)
![CLOUD HONEYNET SOC](https://github.com/user-attachments/assets/164ff7e8-dc7e-4a01-852b-047315891709)

## Overview

In this project, I deployed a mini honeynet in Azure, aggregating log data from various resources into a Log Analytics workspace. The data was then leveraged by Microsoft Sentinel to construct attack vectors, generate real-time alerts, and create security incidents. Initially, I monitored security telemetry in the vulnerable environment for 24 hours, then implemented a series of hardening measures, including network segmentation and enhanced access controls. Afterward, I conducted a second 24-hour observation to quantify the impact of the applied controls. The metrics below provide a detailed analysis of the captured security data throughout this assessment:
- SecurityEvent: Windows Event Logs
- Syslog: Linux Event Logs
- SecurityAlert: Log Analytics Alerts Triggered
- SecurityIncident: Incidents created by Sentinel
- AzureNetworkAnalytics_CL: Malicious Flows allowed into the honeynet

## Architecture Before Hardening / Security Controls
![BEFORE HARDENING](https://github.com/user-attachments/assets/4fd383ea-0786-463c-a5f2-2782487e663a)


## Architecture After Hardening / Security Controls
![AFTER HARDENING](https://github.com/user-attachments/assets/46f5c428-0792-49e8-8839-cb3191e1355c)


The architecture of the mini honeynet in Azure consists of the following components:

- Virtual Network (VNet)
- Network Security Group (NSG)
- Virtual Machines (2 windows, 1 linux)
- Log Analytics Workspace
- Azure Key Vault
- Azure Storage Account
- Microsoft Sentinel

## Architecture Changes

### Before Hardening: 
The initial architecture was exposed and unsecured, with all resources publicly accessible over the internet. The Virtual Machines had their Network Security Groups (NSGs) and built-in firewalls configured with overly permissive rules, while other resources were deployed with public endpoints, completely bypassing the use of Private Endpoints. This configuration rendered the environment highly susceptible to external threats and attack vectors.
#### Vulnerabilities:
- Open ports facilitated unrestricted access to Virtual Machines, enabling potential exploitation.
- Publicly accessible resources (e.g., Azure Key Vault, Azure Blob Storage) left the environment vulnerable to external reconnaissance and exploitation.
#### Security Risks:
- The unprotected resources allowed attackers to conduct extensive scanning and exploit vulnerabilities, resulting in numerous failed authentication attempts and a surge in malicious traffic patterns.
### After Hardening:
A hardened architecture was implemented to mitigate the identified risks. Key changes included:
#### Architecture Security Enhancements:
- Deployment of Network Security Groups (NSGs) with granular, restrictive rules to limit inbound traffic to only authorized sources.
- Subnet segmentation to improve resource isolation and minimize lateral movement potential.
- Hardening of Virtual Machines by incorporating security controls such as Multi-Factor Authentication (MFA), encryption at rest, and comprehensive access control lists (ACLs).
- Protection of Key Vault and Blob Storage through the use of Azure Firewall and Private Endpoints to restrict access to internal networks.
#### Security Improvements:
- The implementation of these security controls drastically reduced the attack surface. Only whitelisted traffic was permitted to access the resources, and continuous monitoring with advanced threat detection mechanisms was established to identify anomalous behavior and potential intrusions.



## Attack Maps Before Hardening / Security Controls
![BEFORE nsg-malicious-allowed-in](https://github.com/user-attachments/assets/ef4733bc-ba87-4f5b-bef7-ba7931ef56b3)
<br>![BEFORE linux-ssh-auth-fail](https://github.com/user-attachments/assets/75930d7c-4614-4dc9-8489-753c143b17a6)
<br>
![BEFORE windows-rdp-auth-fail](https://github.com/user-attachments/assets/6d4823eb-2c6e-4211-abb9-447abc5d90a3)
<br>

## Metrics Before Hardening / Security Controls

The following table shows the metrics we measured in our insecure environment for 24 hours:

Start Time 2023-09-14T18:27:20

Stop Time 2023-09-15T18:27:20

| Metric                   | Count
| ------------------------ | -----
| SecurityEvent            | 111583
| Syslog                   | 9900
| SecurityAlert            | 204
| SecurityIncident         | 204
| AzureNetworkAnalytics_CL | 2612

## Attack Maps Before Hardening / Security Controls

```All map queries returned no results due to no instances of malicious activity for the 24 hour period after hardening.```

## Metrics After Hardening / Security Controls

The following table shows the metrics we measured in our environment for another 24 hours, but after we have applied security controls:

Start Time 2024-09-16T22:46:20

Stop Time	2024-09-17T22:46:20

| Metric                   | Count
| ------------------------ | -----
| SecurityEvent            | 20178
| Syslog                   | 32
| SecurityAlert            | 0
| SecurityIncident         | 0
| AzureNetworkAnalytics_CL | 0

## Key Observations:
- Windows Security Events: There was a significant reduction (81.92%) in security events recorded on Windows VMs after hardening. This indicates the success of applied controls like firewalls and NSG rules in mitigating unauthorized attempts.
- Linux Syslog Events: The reduction of Syslog entries by 99.68% demonstrates that SSH brute force attacks on Linux VMs were nearly eliminated after implementing security measures, especially limiting open ports and securing SSH access.
- Security Alerts and Incidents: Both SecurityAlerts from Microsoft Defender for Cloud and SecurityIncidents from Sentinel dropped to zero, confirming the effectiveness of the applied hardening techniques, which helped block all potential attacks and eliminated the need for triggered alerts.
- NSG Inbound Malicious Flows: The elimination of malicious flows allowed through the NSG (100% reduction) reflects the success of fine-tuning inbound traffic rules, preventing unwanted traffic from reaching the honeynet.
  
## Conclusion

This project demonstrates the practical application of Azure services in setting up a SOC and honeynet for cybersecurity monitoring and threat analysis. The hardening process significantly improved the security posture, making the environment more resilient to common attack vectors. The comparison between pre- and post-hardening metrics highlights the effectiveness of the implemented security controls. The maps and logs provide critical insights into global attack patterns, offering valuable data for incident response teams to proactively mitigate threats.

It is worth noting that if the resources within the network were heavily utilized by regular users, it is likely that more security events and alerts may have been generated within the 24-hour period following the implementation of the security controls.# Cloud-Honeynet
