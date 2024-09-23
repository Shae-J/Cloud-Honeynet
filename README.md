# Building a SOC + Honeynet in Azure (Live Traffic)
![CLOUD HONEYNET SOC](https://github.com/user-attachments/assets/164ff7e8-dc7e-4a01-852b-047315891709)

## Overview

In this project, I built a mini honeynet in Azure, ingesting log sources from various resources into a Log Analytics workspace. These logs were then utilized by Microsoft Sentinel to build attack maps, trigger alerts, and create incidents. I measured security metrics in the insecure environment for 24 hours, applied several security controls to harden the environment, and then measured metrics for another 24 hours to assess the effectiveness of the hardening. The metrics shown below highlight key security data captured during this project:
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
The architecture was initially unsecured, with all resources exposed to the internet. The Virtual Machines had both their Network Security Groups and built-in firewalls wide open, and all other resources were deployed with public endpoints visible to the internet, without any use of Private Endpoints. This configuration made the environment highly vulnerable to external attacks.
#### Vulnerabilities:
- Open ports allowed unrestricted access to VMs.
- Publicly accessible resources (e.g., Key Vault, Storage) left the environment exposed to external threats.
#### Security Risks:
- The unprotected resources allowed attackers to easily scan and exploit the environment, resulting in a high volume of failed authentication attempts and malicious traffic.
### After Hardening:
A hardened architecture was implemented to mitigate the identified risks. Key changes included:
#### Architecture Security Enhancements:
- Implementation of NSGs with restrictive rules to limit inbound traffic.
- Subnet segregation for better isolation of resources.
- Hardened VMs with security controls such as MFA and access control lists.
- Key Vault and Blob Storage protected by firewalls and private endpoints.
#### Security Improvements:
- The introduction of these security controls drastically reduced the attack surface.
- Only authorized traffic could access the resources, and strict monitoring was put in place to detect anomalous behavior.


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

## Conclusion

This project demonstrates the practical application of Azure services in setting up a SOC and honeynet for cybersecurity monitoring and threat analysis. The hardening process significantly improved the security posture, making the environment more resilient to common attack vectors. The comparison between pre- and post-hardening metrics highlights the effectiveness of the implemented security controls. The maps and logs provide critical insights into global attack patterns, offering valuable data for incident response teams to proactively mitigate threats.

It is worth noting that if the resources within the network were heavily utilized by regular users, it is likely that more security events and alerts may have been generated within the 24-hour period following the implementation of the security controls.# Cloud-Honeynet
