# MITRE-ATT-CK-SOC-Detection-Lab

A comprehensive, end-to-end telemetry engineering and threat-hunting pipeline built to bridge the gap between offensive adversary simulation and defensive SIEM analysis.

This project maps real-world adversary techniques across five core **MITRE ATT&CK** tactics, handles complex endpoint engineering constraints, and constructs high-fidelity security analytics inside **Splunk Enterprise**.

---

# 🛠️ Lab Architecture & Engineering Pipeline

To simulate an enterprise environment, the telemetry pipeline was engineered using a decoupled architecture focused on **high visibility**, **data isolation**, and **structured parsing**.

### **Endpoint Environment**
- Windows Server / Windows Enterprise Evaluation Instance

### **Adversary Simulation Engine**
- Red Canary's **Atomic Red Team (ART)** Framework

### **Telemetry Collectors**
- Microsoft **Sysmon** (Advanced Endpoint Auditing)
- Native **Windows Security Logging Subsystem**

### **SIEM Ingestion Layer**
- **Splunk Enterprise**
- Indexed local Event Channels using optimized XML rendering configurations (`inputs.conf`)

---

## Architecture Flow

```text
[Adversary Simulation (Atomic Red Team / Native OS)]
                      │
                      ▼
 [Windows Kernel / Process / Registry Subsystems]
                      │
         ┌────────────┴────────────┐
         ▼                         ▼
  [Sysmon Core Logs]      [Windows Security Auditing]
    (EventID 1,10,13)          (EventID 4698,1102)
         │                         │
         └────────────┬────────────┘
                      ▼
          [Splunk Ingestion Pipeline]
           (inputs.conf / renderXml)
                      │
                      ▼
         [Dynamic SPL Analytics Layers]
         (Parsed KPI Dashboard Panels)
```

---

# 🔧 Engineering Ledger: Overcoming Production Roadblocks

Building a production-grade lab required engineering around modern operating system defenses and SIEM ingestion challenges.

## 1. XML Ingestion Mismatch

Modern Windows event channels render complex XML arrays that can cause field mapping issues in traditional SIEM ingestion pipelines.

**Solution**

- Reconfigured Splunk ingestion to parse structured XML natively.
- Enabled:

```ini
renderXml = true
```

This preserved field fidelity and improved event normalization.

---

## 2. Memory Defense Boundary (Credential Guard / RunAsPPL)

Modern Windows systems actively protect **LSASS** memory from unauthorized access, even for administrative users.

### Challenge

- Credential dumping simulations were blocked by:
  - Credential Guard
  - LSA Protection (RunAsPPL)

### Approach

Rather than bypassing protections, detection logic was pivoted toward identifying:

- Registry modifications
- Defensive tampering attempts
- Evasion behavior

---

## 3. Dynamic Log Extraction

Hardcoded Windows path separators (`\`) created parsing conflicts during field extraction.

### Solution

Developed dynamic regular-expression extraction patterns:

```regex
[^\r\n]+
```

This allowed reliable extraction of metadata fields at search time without relying on fragile static parsing.

---

# 🛡️ MITRE ATT&CK Detection Engineering Loops

---

# Technique 1: Command & Scripting Interpreter → PowerShell (T1059.001)

### **MITRE ATT&CK Tactic**
**Execution**

### **Objective**
Simulate internal actors utilizing native execution layers to run Active Directory discovery scripts (**SharpHound.ps1**) targeting domain reconnaissance.

---

## 1. Adversary Simulation

```powershell
# Triggers the download and in-memory compilation of internal discovery modules

Invoke-AtomicTest T1059.001 -TestNumbers 2
```

---

## 2. Splunk Detection Query

```spl
index=windows EventCode=1 "SharpHound"

| rex field=_raw "CommandLine=(?<CommandLine>[^\n]+)"
| rex field=_raw "User=(?<User>[^\n]+)"
| rename ComputerName as Computer

| stats count by _time, Computer, User, Image, CommandLine
```

---

## 3. Telemetry Verification

### SOC Executive Visualization

- Process creation spike monitoring
- Unauthorized binary execution tracking
- Execution chain visibility

### Log Proof-of-Concept

- Full Event ID 1 analysis
- Process context verification
- Command-line auditing

---

# Technique 2: Registry Run Keys (T1547.001)

### **MITRE ATT&CK Tactic**
**Persistence**

### **Objective**
Establish non-volatile persistence through Windows startup registry hives.

---

## 1. Adversary Simulation

```powershell
# Injecting a persistent startup execution path

Invoke-AtomicTest T1547.001 -TestNumbers 1
```

---

## 2. Splunk Detection Query

```spl
index=windows EventCode=13 TargetObject="*CurrentVersion*Run*"

| rex field=_raw "TargetObject=(?<TargetObject>[^\r\n]+)"
| rex field=_raw "Details=(?<Details>[^\r\n]+)"
| rex field=_raw "Image=(?<Image>[^\r\n]+)"

| rename ComputerName as Computer

| stats count by _time, Computer, Image, TargetObject, Details
```

---

## 3. Telemetry Verification

### SOC Executive Visualization

- Real-time monitoring of registry modifications
- Startup persistence tracking

### Log Proof-of-Concept

- Validation of unauthorized registry additions
- Run-key value analysis

---

# Technique 3: Scheduled Task (T1053.005)

### **MITRE ATT&CK Tactic**
**Privilege Escalation / Persistence**

### **Objective**
Register scheduled tasks capable of executing independently under elevated privilege contexts.

---

## 1. Adversary Simulation

```powershell
# Manual task registration

schtasks /Create /TN "SOC_Lab_Test_Task" `
         /TR "C:\Windows\System32\calc.exe" `
         /SC ONLOGON `
         /F
```

---

## 2. Splunk Detection Query

```spl
index=windows EventCode=4698

| xmlkv Message

| eval TaskName=mvindex('Task_Name',0),
       Command=mvindex('Command',0)

| rename ComputerName as Computer

| stats count by _time, Computer, TaskName, Command
```

---

## 3. Telemetry Verification

### SOC Executive Visualization

- Scheduled task registration monitoring
- XML event parsing dashboards

### Log Proof-of-Concept

- Task creation parameter extraction
- Execution target validation

---

# Technique 4: Clear Windows Event Logs (T1070.001)

### **MITRE ATT&CK Tactic**
**Defense Evasion**

### **Objective**
Simulate anti-forensic activity by clearing Windows Security logs.

---

## 1. Adversary Simulation

```powershell
# Clear the Windows Security log

wevtutil.exe cl Security
```

---

## 2. Splunk Detection Query

```spl
index=windows EventCode=1102

| rex field=_raw "LogName=(?<LogName>[^\n]+)"

| rename ComputerName as Computer

| stats count by _time, Computer, LogName, EventCode
```

---

## 3. Telemetry Verification

### SOC Executive Visualization

- High-severity anti-forensic event monitoring
- Security log tampering detection

### Log Proof-of-Concept

- Administrative account attribution
- Event log clearance confirmation

---

# Technique 5: LSA Protection Registry Tampering (T1562.001)

### **MITRE ATT&CK Tactic**
**Defense Evasion / Credential Access**

### **Objective**
Simulate attempts to alter Local Security Authority (LSA) settings associated with memory-protection controls.

---

## 1. Adversary Simulation

```powershell
# Simulated defensive tampering artifact

New-Item -Path "HKLM:\SOFTWARE\MaliciousArtifactMock" -Force

New-ItemProperty `
    -Path "HKLM:\SOFTWARE\MaliciousArtifactMock" `
    -Name "PersistenceCheck" `
    -Value "C:\Windows\System32\cmd.exe" `
    -PropertyType String `
    -Force
```

---

## 2. Splunk Detection Query

```spl
index=windows EventCode=1 "MaliciousArtifactMock"

| rex field=_raw "CommandLine=(?<CommandLine>[^\n]+)"
| rex field=_raw "User=(?<User>[^\n]+)"

| rename ComputerName as Computer

| stats count by _time, Computer, User, CommandLine
```

---

## 3. Telemetry Verification

### SOC Executive Visualization

- Defensive configuration monitoring
- Process timeline analysis

### Log Proof-of-Concept

- Registry modification attribution
- Command-line argument inspection

---

# 📈 Enterprise SOC Dashboard Compilation

The individual detection analytics were consolidated into a centralized Splunk monitoring framework that normalizes heterogeneous telemetry into actionable security metrics.

| ATT&CK Tactic | Event ID | Extraction Methodology | Ingestion Channel | Alert Severity |
|--------------|----------|------------------------|------------------|---------------|
| Execution | Sysmon 1 | Regex Process Parsing | Microsoft-Windows-Sysmon/Operational | Medium |
| Persistence | Sysmon 13 | Key-Value Extraction | Microsoft-Windows-Sysmon/Operational | High |
| Privilege Escalation | Security 4698 | XML Parsing (`xmlkv`) | Security Audit Log | Critical |
| Defense Evasion | Security 1102 | Log Clearance Detection | Security Audit Log | Severe |
| Credential Access | Sysmon 1 | Command Argument Tracking | Microsoft-Windows-Sysmon/Operational | High |

---

# 🧠 Strategic Competencies Developed

### **SIEM Architecture & Data Engineering**
- Configured Splunk ingestion pipelines (`inputs.conf`)
- Managed event channel indexing and XML parsing
- Built structured telemetry workflows

### **Threat Detection Engineering**
- Mapped MITRE ATT&CK techniques to detection logic
- Developed field-level analytics from adversary behaviors
- Created high-fidelity detection rules

### **Splunk Analytics Development**
- Authored optimized SPL searches
- Leveraged:
  - `rex`
  - `xmlkv`
  - `spath`
  - `stats`
  - `eval`

### **Defensive Troubleshooting**
- Evaluated Credential Guard and RunAsPPL protections
- Adapted detection strategies around modern OS security controls
- Focused on identifying evasion and tampering behaviors rather than bypassing defenses

---

# 🚀 Key Outcomes

- Simulated real-world attacker behaviors across **five MITRE ATT&CK tactics**
- Engineered a complete **endpoint-to-SIEM telemetry pipeline**
- Built **Splunk detection analytics and SOC dashboards**
- Validated detections using both **Sysmon** and **Windows Security Auditing**
- Developed practical experience in:
  - Threat Hunting
  - Detection Engineering
  - SIEM Architecture
  - Windows Internals
  - MITRE ATT&CK Mapping
  - Security Analytics Development
