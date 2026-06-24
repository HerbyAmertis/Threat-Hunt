# # EmberForge-Source Leak // Full Incident Response Report

## Executive Summary
This report documents a full-spectrum compromise of the EmberForge environment. The attacker achieved initial access via a socially engineered payload, escalated privileges, moved laterally, compromised the Domain Controller, extracted Active Directory credentials, exfiltrated sensitive data, and established persistence.

Despite anti-forensics efforts, complete reconstruction was possible using Sysmon telemetry.

---

## Environment
- Workspace: law-cyber-range
- Log Source: EmberForgeX_CL
- Domain: emberforge.local
- Hosts in Scope: 3 (Workstation, Server, Domain Controller)

---

## Attack Chain Overview
1. Initial Access → ISO-mounted DLL execution
2. Payload Deployment → update.exe
3. Command & Control → cloud-endpoint infrastructure
4. Privilege Escalation → UAC bypass + injection
5. Credential Access → LSASS + NTDS.dit
6. Lateral Movement → SMB + remote service execution
7. Persistence → scheduled task, domain account, AnyDesk
8. Anti-Forensics → log clearing

---

## Phase 1: Initial Access

### Evidence
```kql
EmberForgeX_CL
| where CommandLine_s has "rundll32"
| project TimeCreated_t, ParentImage_s, CommandLine_s
```

### Finding
User executed a DLL from a mounted ISO:
- rundll32.exe loading review.dll from D:\

---

## Phase 2: Payload Deployment

### Evidence
```kql
EmberForgeX_CL
| where TargetFilename_s has "update.exe"
| project TimeCreated_t, TargetFilename_s
```

### Finding
Primary payload dropped:
- C:\Users\Public\update.exe

---

## Phase 3: Command and Control

### Evidence
```kql
EmberForgeX_CL
| where EventCode_s == "22"
| project TimeCreated_t, QueryName_s
```

### Finding
C2 Domain:
- cdn.cloud-endpoint.net

---

## Phase 4: Privilege Escalation

### Evidence
```kql
EmberForgeX_CL
| where EventCode_s == "13"
| project TimeCreated_t, RegistryKey_s
```

### Finding
UAC bypass via registry modification followed by process injection into SYSTEM context.

---

## Phase 5: Credential Access

### LSASS Dump
```kql
EmberForgeX_CL
| where CommandLine_s has "lsass"
| project TimeCreated_t, CommandLine_s
```

### NTDS Extraction (Critical)
```kql
EmberForgeX_CL
| where CommandLine_s has "ntds.dit"
| project TimeCreated_t, CommandLine_s
```

### Finding
- Shadow copy created
- NTDS.dit copied from Volume Shadow Copy

---

## Phase 6: Lateral Movement

### Evidence
```kql
EmberForgeX_CL
| where CommandLine_s has_any ("net share", "copy \\", "certutil")
| project TimeCreated_t, Computer, CommandLine_s
```

### Finding
- Tool staging via SMB
- Remote execution via service creation

---

## Phase 7: Domain Controller Compromise

### Critical Observation
Correct timeline required ordering by:
```kql
| order by TimeCreated_t asc
```

### Key Sequence
- whoami (access validation)
- vssadmin (shadow operations)
- NTDS extraction via copy command

---

## Phase 8: Data Exfiltration

### Evidence
```kql
EmberForgeX_CL
| where CommandLine_s has "rclone"
| project TimeCreated_t, CommandLine_s
```

### Finding
- Tool: rclone.exe
- Destination: MEGA cloud
- Credentials exposed in command line

---

## Phase 9: Persistence

### Evidence
```kql
EmberForgeX_CL
| where CommandLine_s has_any ("schtasks", "net user", "AnyDesk")
| project TimeCreated_t, CommandLine_s
```

### Findings
- Backdoor account: svc_backup
- Scheduled task: WindowsUpdate
- Remote access: AnyDesk

---

## Phase 10: Anti-Forensics

### Evidence
```kql
EmberForgeX_CL
| where CommandLine_s has "wevtutil"
| project TimeCreated_t, CommandLine_s
```

### Finding
Cleared logs:
- Security
- System

---

## Key Lessons Learned

### 1. Time Field Matters
- TimeGenerated = ingestion
- TimeCreated_t = actual execution

### 2. Wrapper Parsing Required
- execute.bat masked true commands
- Required extraction of inner commands

### 3. OPSEC Failures
- Credentials exposed in command line
- Clear attribution possible

---

## MITRE ATT&CK Mapping

| Tactic | Technique |
|------|----------|
| Initial Access | T1566 |
| Execution | T1218 |
| Persistence | T1053 |
| Privilege Escalation | T1548 |
| Defense Evasion | T1070 |
| Credential Access | T1003 |
| Discovery | T1087 |
| Lateral Movement | T1021 |
| Exfiltration | T1041 |

---

## Final Assessment

- Impact: Critical
- Scope: Domain-wide
- Data Exfiltration: Confirmed
- Persistence: Multiple mechanisms
- Detection Gaps: Log clearing succeeded partially

---

## Analyst Reflection

This investigation reinforces a critical principle:

> Accurate timelines depend on selecting the correct data source, not just the correct query.

Misinterpreting ingestion time as execution time can lead to incorrect conclusions, even when all evidence is present.
 // Full Incident Response Report

## Executive Summary
This report documents a full-spectrum compromise of the EmberForge environment. The attacker achieved initial access via a socially engineered payload, escalated privileges, moved laterally, compromised the Domain Controller, extracted Active Directory credentials, exfiltrated sensitive data, and established persistence.

Despite anti-forensics efforts, complete reconstruction was possible using Sysmon telemetry.

---

## Environment
- Workspace: law-cyber-range
- Log Source: EmberForgeX_CL
- Domain: emberforge.local
- Hosts in Scope: 3 (Workstation, Server, Domain Controller)

---

## Attack Chain Overview
1. Initial Access → ISO-mounted DLL execution
2. Payload Deployment → update.exe
3. Command & Control → cloud-endpoint infrastructure
4. Privilege Escalation → UAC bypass + injection
5. Credential Access → LSASS + NTDS.dit
6. Lateral Movement → SMB + remote service execution
7. Persistence → scheduled task, domain account, AnyDesk
8. Anti-Forensics → log clearing

---

## Phase 1: Initial Access

### Evidence
```kql
EmberForgeX_CL
| where CommandLine_s has "rundll32"
| project TimeCreated_t, ParentImage_s, CommandLine_s
```

### Finding
User executed a DLL from a mounted ISO:
- rundll32.exe loading review.dll from D:\

---

## Phase 2: Payload Deployment

### Evidence
```kql
EmberForgeX_CL
| where TargetFilename_s has "update.exe"
| project TimeCreated_t, TargetFilename_s
```

### Finding
Primary payload dropped:
- C:\Users\Public\update.exe

---

## Phase 3: Command and Control

### Evidence
```kql
EmberForgeX_CL
| where EventCode_s == "22"
| project TimeCreated_t, QueryName_s
```

### Finding
C2 Domain:
- cdn.cloud-endpoint.net

---

## Phase 4: Privilege Escalation

### Evidence
```kql
EmberForgeX_CL
| where EventCode_s == "13"
| project TimeCreated_t, RegistryKey_s
```

### Finding
UAC bypass via registry modification followed by process injection into SYSTEM context.

---

## Phase 5: Credential Access

### LSASS Dump
```kql
EmberForgeX_CL
| where CommandLine_s has "lsass"
| project TimeCreated_t, CommandLine_s
```

### NTDS Extraction (Critical)
```kql
EmberForgeX_CL
| where CommandLine_s has "ntds.dit"
| project TimeCreated_t, CommandLine_s
```

### Finding
- Shadow copy created
- NTDS.dit copied from Volume Shadow Copy

---

## Phase 6: Lateral Movement

### Evidence
```kql
EmberForgeX_CL
| where CommandLine_s has_any ("net share", "copy \\", "certutil")
| project TimeCreated_t, Computer, CommandLine_s
```

### Finding
- Tool staging via SMB
- Remote execution via service creation

---

## Phase 7: Domain Controller Compromise

### Critical Observation
Correct timeline required ordering by:
```kql
| order by TimeCreated_t asc
```

### Key Sequence
- whoami (access validation)
- vssadmin (shadow operations)
- NTDS extraction via copy command

---

## Phase 8: Data Exfiltration

### Evidence
```kql
EmberForgeX_CL
| where CommandLine_s has "rclone"
| project TimeCreated_t, CommandLine_s
```

### Finding
- Tool: rclone.exe
- Destination: MEGA cloud
- Credentials exposed in command line

---

## Phase 9: Persistence

### Evidence
```kql
EmberForgeX_CL
| where CommandLine_s has_any ("schtasks", "net user", "AnyDesk")
| project TimeCreated_t, CommandLine_s
```

### Findings
- Backdoor account: svc_backup
- Scheduled task: WindowsUpdate
- Remote access: AnyDesk

---

## Phase 10: Anti-Forensics

### Evidence
```kql
EmberForgeX_CL
| where CommandLine_s has "wevtutil"
| project TimeCreated_t, CommandLine_s
```

### Finding
Cleared logs:
- Security
- System

---

## Key Lessons Learned

### 1. Time Field Matters
- TimeGenerated = ingestion
- TimeCreated_t = actual execution

### 2. Wrapper Parsing Required
- execute.bat masked true commands
- Required extraction of inner commands

### 3. OPSEC Failures
- Credentials exposed in command line
- Clear attribution possible

---

## MITRE ATT&CK Mapping

| Tactic | Technique |
|------|----------|
| Initial Access | T1566 |
| Execution | T1218 |
| Persistence | T1053 |
| Privilege Escalation | T1548 |
| Defense Evasion | T1070 |
| Credential Access | T1003 |
| Discovery | T1087 |
| Lateral Movement | T1021 |
| Exfiltration | T1041 |

---

## Final Assessment

- Impact: Critical
- Scope: Domain-wide
- Data Exfiltration: Confirmed
- Persistence: Multiple mechanisms
- Detection Gaps: Log clearing succeeded partially

---

## Analyst Reflection

This investigation reinforces a critical principle:

> Accurate timelines depend on selecting the correct data source, not just the correct query.

Misinterpreting ingestion time as execution time can lead to incorrect conclusions, even when all evidence is present.
