# Proof of Concept: RDP Monitoring with Microsoft Sentinel and Micrososft Defender

## 1. Objective

Build a cloud SOC lab that collects Windows security events and detects successful RDP sign-ins using Microsoft Sentinel.

What I wanted to validate:
Successfull detection of suspicious successful RDP logins on a Virtual Machine

## 2. Scope and Environment

This proof of concept uses an Azure Windows VM and controlled login activity to test log collection, detection, and incident generation.

Test date: 12/10/2026
Observation period and time zone: 12/10/2026 20:00 - 12/10/2026 22:00

## 3. Architecture

Windows security events are collected by the Azure Monitor Agent according to the Data Collection Rule and sent to Log Analytics. Microsoft Sentinel queries these logs to detect relevant RDP sign-ins.

<img width="2040" height="727" alt="image" src="https://github.com/user-attachments/assets/1ecc779d-05b6-4053-9079-02eaeffef3c4" />

## 4. Implementation

**I configured the following components:**

Virtual Machine  

<img width="2387" height="1121" alt="image" src="https://github.com/user-attachments/assets/355aa2bb-8d77-45cf-a3cb-e5cff2970628" />

Log Analytics Workspace

<img width="2432" height="328" alt="image" src="https://github.com/user-attachments/assets/70bfbfba-8c16-4318-ae58-e664abce0336" />

Sentinel Analytics and rule settings in Microsoft Defender 

<img width="2435" height="1133" alt="image" src="https://github.com/user-attachments/assets/8c1c4f15-5b61-43c5-b9e3-96272bd89647" />

<img width="2452" height="1153" alt="image" src="https://github.com/user-attachments/assets/cb79e9ee-9e6f-45a2-80f4-bb1c37c21835" />

<img width="2462" height="1225" alt="image" src="https://github.com/user-attachments/assets/cc18db5a-813e-458e-869e-984ab8f30a8f" />

Challenges and solutions:

The tutorial was slightly outdated, so some menu options and configuration settings had changed. I explored the platform and investigated the differences to reproduce the setup in the current interface. During this process, I also identified that one of the data connectors shown in the tutorial had been deprecated.

Deprecated means a feature is being phased out and is no longer recommended for new setups, usually because a newer option replaces it.
It may still work—deprecated doesn’t necessarily mean disabled or removed. Support and removal dates depend on the product.

## 5. Detection Logic

Rule name: Successful RDP logins
Query frequency: 5 minutes
Query lookback period: 5 minutes
Alert threshold: 0

<img width="1411" height="857" alt="image" src="https://github.com/user-attachments/assets/208cee64-09ca-4eb4-a444-2692ec299089" />

**KQL query**

`SecurityEvent
| where EventID == 4624
| where LogonType == 10
| project TimeGenerated, Computer, TargetAccount, IpAddress, EventID, LogonType`

**Explanation**

Event ID 4624 represents a successful logon; Logon Type 10 identifies a remote interactive logon through Remote Desktop or Terminal Services
A successful RDP sign-in is not automatically malicious. This rule identifies activity that requires contextual review.

## 6. Validation

Test procedure:

To perform a simple test I downloaded the associated RDP file to connect to the VM machine with its credentials, after that the rule triggered an alert successfully, showing information of the Source IP (My IP address in this case).

<img width="560" height="583" alt="image" src="https://github.com/user-attachments/assets/dd0a61d9-388c-40ac-8ab5-886bde81b2dc" />

<img width="2455" height="1247" alt="image" src="https://github.com/user-attachments/assets/a3c36e86-c373-4b09-aaf9-1a6079fc4090" />

<img width="2266" height="1131" alt="image" src="https://github.com/user-attachments/assets/9dbf82e2-513c-4bfc-8de4-5ef9d11768e1" />

Assessment:
Since the successfull logins observed were from my own personal device no suspicious activity was observed

Disposition and reasoning:
False Positive - Not Malicious activity

## 9. My Contribution and Lessons Learned

Tutorial-based work:
Azure Virtual Machine deploy and conection to foward the logs to Sentinel


### Key lessons: 

I learned and played with different configurations of the rule, learning how to reduce unnecesary alert noise and how to include automations if it's required

## 10. Cleanup and Next Steps

Cleanup completed: Public RDP Access was restricted and the resources were removed.

Planned improvements:
Adding Threat Intelligence sources to enrich the alerts, as well including more virtual machines and experiment with diferent data connectors.

## Reference

Base tutorial: https://www.youtube.com/watch?v=IJUkGuirTGQ

Microsoft Sentinel Documentation: https://learn.microsoft.com/es-mx/azure/sentinel/connect-services-windows-based#log-analytics-agent-legacy
