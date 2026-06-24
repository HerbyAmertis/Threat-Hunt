# The Broker — Cyber Range SOC Threat Hunt

**Scenario:** Ashford Sterling Recruitment  
**Difficulty:** Hard  
**Platform:** Microsoft Defender / Sentinel (KQL-only investigation)  
**Analyst:** Steven Cruz

---

## Executive Summary

This investigation documents a full attack chain observed in the *The Broker* Cyber Range scenario. A threat actor leveraged social engineering to gain initial access, established command-and-control infrastructure, harvested credentials, performed discovery and lateral movement, deployed multiple persistence mechanisms, accessed sensitive financial data, and attempted anti-forensic cleanup prior to exit.

The activity was characterized by **hands-on-keyboard tradecraft**, extensive abuse of **legitimate tools**, and **in-memory execution** designed to evade traditional file-based detection.

---

## Environment Overview

- **Endpoints:** AS-PC1, AS-PC2  
- **Server:** AS-SRV  
- **Primary User Accounts:** Sophie.Turner, david.mitchell  
- **Operating Context:** Windows enterprise environment monitored by Microsoft Defender telemetry

---

## Attack Timeline (High-Level)

1. Initial access via user-executed payload
2. Command-and-control beaconing
3. Credential access from local stores
4. Host and network discovery
5. Persistence via remote access tooling
6. Lateral movement using valid credentials
7. Additional persistence via scheduled task
8. Sensitive data access and staging
9. Anti-forensics and in-memory tooling

---

## Section 1: Initial Access

**Technique:** User Execution / Masquerading

- **Initial Vector:** `daniel_richardson_cv.pdf.exe`
- **SHA256:** `48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5`
- **Execution Method:** `explorer.exe`
- **Decoy Child Process:** `notepad.exe`
- **Command Line:** `notepad.exe ""`

**Assessment:**
A double-extension executable was manually launched from the Downloads directory. The payload spawned Notepad with empty arguments to create the appearance of a benign document open.

---

## Section 2: Command & Control

**Technique:** Application Layer Protocol / Web Traffic

- **C2 Domain:** `cloud-endpoint.net` (subdomains observed: `cdn`, `sync`)
- **C2 Process:** `daniel_richardson_cv.pdf.exe`
- **Staging Infrastructure:** `download.anydesk.com`

**Assessment:**
The malware established outbound communications to attacker-controlled infrastructure. Separate infrastructure was used to stage follow-on tooling, demonstrating disciplined tradecraft.

---

## Section 3: Credential Access

**Technique:** OS Credential Dumping

- **Registry Targets:** `SAM`, `SYSTEM`
- **Local Staging Path:** `C:\Users\Public\`
- **Execution Identity:** `Sophie.Turner`

**Assessment:**
Credential material was harvested from local credential stores and staged in a world-writable directory prior to later use.

---

## Section 4: Discovery

**Technique:** Account & Network Discovery

- **User Context Command:** `whoami`
- **Network Enumeration:** `net view`
- **Privileged Group Queried:** `administrators`

**Assessment:**
The attacker confirmed execution context, enumerated accessible network shares, and identified privileged local group membership to inform next-stage actions.

---

## Section 5: Persistence — Remote Tool

**Technique:** Valid Accounts / Remote Services

- **Tool Installed:** AnyDesk
- **SHA256:** `f42b635d93720d1624c74121b83794d706d4d064bee027650698025703d20532`
- **Download Method:** `certutil.exe`
- **Config File:** `C:\Users\Sophie.Turner\AppData\Roaming\AnyDesk\system.conf`
- **Unattended Password:** `intrud3r!`
- **Deployment Hosts:** AS-PC1, AS-PC2, AS-SRV

**Assessment:**
A legitimate remote administration tool was installed across multiple systems to ensure reliable long-term access.

---

## Section 6: Lateral Movement

**Technique:** Remote Services / RDP

- **Failed Tools:** `wmic.exe`, `psexec.exe`
- **Failed Target:** AS-PC2
- **Successful Pivot:** `mstsc.exe`
- **Movement Path:** AS-PC1 > AS-PC2 > AS-SRV
- **Authenticated Account:** `david.mitchell`
- **Account Activation Flag:** `/active:yes`
- **Activation Context:** `david.mitchell`

**Assessment:**
After unsuccessful remote execution attempts, the attacker pivoted to interactive RDP using valid credentials and moved laterally to a server host.

---

## Section 7: Persistence — Scheduled Task

**Technique:** Scheduled Task / Binary Masquerading

- **Task Name:** `MicrosoftEdgeUpdateCheck`
- **Renamed Binary:** `RuntimeBroker.exe`
- **SHA256:** `48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5`
- **Backdoor Account:** `svc_backup`

**Assessment:**
The attacker reused the original payload under a masqueraded filename and ensured execution via a scheduled task while also creating a new local account.

---

## Section 8: Data Access

**Technique:** Data from Network Shared Drive

- **Sensitive File:** `BACS_Payments_Dec2025.ods`
- **Edit Evidence:** `.~lock.BACS_Payments_Dec2025.ods#`
- **Access Origin:** AS-PC2
- **Archive Created:** `Shares.7z`
- **SHA256:** `6886c0a2e59792e69df94d2cf6ae62c2364fda50a23ab44317548895020ab048`

**Assessment:**
Financial data was accessed from the file server, edited, and staged locally in a compressed archive prior to potential exfiltration.

---

## Section 9: Anti-Forensics & Memory

**Technique:** Defense Evasion / In-Memory Execution

- **Logs Cleared:** Security, System
- **Reflective Load ActionType:** `ClrUnbackedModuleLoaded`
- **Memory Tool:** SharpChrome
- **Host Process:** `notepad.exe`

**Assessment:**
The attacker attempted to remove evidence by clearing logs and executed a .NET credential tool directly in memory, injected into a benign host process.

---

## MITRE ATT&CK Mapping (Selected)

| Tactic | Technique |
|------|---------|
| Initial Access | User Execution (T1204) |
| C2 | Web Protocols (T1071.001) |
| Credential Access | SAM Dumping (T1003.002) |
| Discovery | Network Share Discovery (T1135) |
| Persistence | Scheduled Task (T1053.005) |
| Lateral Movement | Remote Desktop (T1021.001) |
| Defense Evasion | Reflective Loading (T1620) |

---

## Conclusion

This scenario demonstrates a realistic intrusion where no single action was especially noisy, but the **cumulative pattern** clearly indicated malicious intent. The attacker relied heavily on legitimate tooling, valid credentials, and memory-resident execution — emphasizing the importance of behavioral detection, cross-host correlation, and timeline-based threat hunting.

---

*End of Report*
