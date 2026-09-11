# Generating Alerts in Your Microsoft Defender Environment

A practical lab guide for validating Microsoft Defender for Endpoint protections, detections, alerts, and Advanced Hunting telemetry.

> [!IMPORTANT]
> Use these tests only on dedicated, authorized lab devices and tenants. Several tests intentionally simulate suspicious or malicious behavior and may create alerts, incidents, device isolation actions, attack disruption, account disablement, or other automated response activity.

## Overview

This project provides reusable test scripts and Microsoft-provided demonstrations that help security teams validate Microsoft Defender behavior in a controlled environment.

The original test collection includes scenarios for:

1. Network Protection
2. EICAR antivirus detection
3. Potentially unwanted application (PUA) protection
4. ORADAD security principal reconnaissance over LDAP
5. Reconnaissance behavior
6. Remote PowerShell and lateral movement behavior
7. Attempted removal or modification of Microsoft Defender protections
8. Suspicious PowerShell behavior

The expanded lab collection can also include:

- AMSI validation
- Behavior monitoring validation
- Endpoint detection and response (EDR) validation
- LSASS credential theft ASR validation
- Obfuscated-script ASR validation
- Office child-process ASR validation
- Office process-injection ASR validation
- PsExec and WMI process-creation ASR validation
- Microsoft Exploit Guard Demo Tool scenarios
- Prompt-injection protection validation, where supported

## Important: A Block Is Not Always an Alert

Microsoft Defender prevention, telemetry, alerts, and incidents are related but separate outcomes.

A test may:

- Be blocked locally without creating a Defender XDR alert.
- Create a Windows Defender Operational event without producing an Advanced Hunting event.
- Produce Advanced Hunting telemetry without creating an alert.
- Create an alert that Defender XDR later correlates into an incident.
- Be affected by platform version, cloud-delivered protection, policy mode, exclusions, licensing, or sensor connectivity.

Do not treat a missing alert as proof that a protection failed. Validate each expected evidence source independently.

## Success Criteria

A test is successful when the observed result matches the documented expectation for that scenario.

Use the following validation sequence:

1. Confirm the required Defender component is enabled and healthy.
2. Confirm the relevant prevention or ASR rule is in the intended mode.
3. Run the test on an authorized lab device.
4. Record whether the behavior ran, was audited, was warned, or was blocked.
5. Review the local Windows Defender Operational log.
6. Review the device timeline in Microsoft Defender XDR.
7. Review relevant Advanced Hunting tables.
8. Review the Alerts and Incidents queues only when an alert is expected.
9. Record the actual result and compare it with the expected result.

## Prerequisites

- A dedicated Windows lab device
- Microsoft Defender Antivirus enabled and healthy
- Microsoft Defender for Endpoint onboarding completed when portal telemetry is required
- Required ASR rules configured in Audit, Warn, or Block mode
- Cloud-delivered protection enabled where required by the scenario
- Tamper Protection configured according to the test goal
- Local administrator rights for tests that require elevation
- Microsoft Office installed for Office-specific ASR scenarios
- Internet access for tests that retrieve Microsoft-hosted demonstration content
- Access to the Microsoft Defender portal for timeline, alert, incident, and Advanced Hunting validation

## Recommended Repository Layout

```text
Defender-Alert-Generation/
├── README.md
├── Run-All-Tests.ps1
├── Scripts/
│   ├── AMSI.ps1
│   ├── BehaviorMonitoring.ps1
│   ├── DownloadEICARFile.ps1
│   ├── DownloadPUAFile.ps1
│   ├── EDRTest.ps1
│   ├── LSASS.ps1
│   ├── NetworkProtection.ps1
│   ├── ObfuscatedScript.ps1
│   ├── OfficeChildProcess.ps1
│   ├── OfficeProcessInjection.ps1
│   ├── ORADAD.ps1
│   ├── Recon.ps1
│   ├── RemotePowerShell.ps1
│   └── RemoveDefender.ps1
├── Test-Files/
│   ├── ASR_Office_Child_Process_Test_Instructions.docx
│   └── supporting lab files
├── Hunting/
│   ├── ASR-Events.kql
│   ├── Alerts.kql
│   └── Device-Timeline.kql
└── Documentation/
    ├── Expected-Results.md
    └── Troubleshooting.md
```

Adjust the names to match the files currently stored in the repository.

## Quick Start

1. Download or clone the repository to a dedicated lab device.
2. Open Windows PowerShell as administrator.
3. Change to the lab directory before each test.
4. Review scripts before running them.
5. Run one scenario at a time until its expected behavior is understood.
6. Use the master test script only after validating the individual scenarios.
7. Review local and portal evidence after every test.

Example working directory:

```powershell
Set-Location 'C:\Tools\Labs'
```

## Test Matrix

The values below are validation guidance, not a guarantee of a specific alert. Update the **Observed Result** column with results from the lab tenant.

| Test | Primary Control | Local Block Expected | Defender Alert Expected | Advanced Hunting Expected | Observed Result |
|---|---|---:|---:|---:|---|
| EICAR | Microsoft Defender Antivirus | Yes, when protection is active | Commonly expected | Commonly expected | Not recorded |
| PUA download | PUA protection | Depends on policy mode | Depends on detection and policy | Depends on telemetry | Not recorded |
| Network Protection | Network Protection | Depends on policy mode | Depends on scenario | Commonly expected when supported | Not recorded |
| AMSI | AMSI and antivirus inspection | Depends on payload and policy | Depends on detection | Depends on telemetry | Not recorded |
| Behavior Monitoring | Behavior monitoring | Depends on behavior | Depends on detection | Depends on telemetry | Not recorded |
| EDR test | MDE sensor and EDR detections | Not always | Expected for supported Microsoft test | Expected | Not recorded |
| ORADAD | Identity and reconnaissance detections | Not necessarily | Depends on product coverage and detection | Depends on data source | Not recorded |
| Reconnaissance | Behavioral detection | Not necessarily | Depends on behavior | Depends on telemetry | Not recorded |
| Remote PowerShell | EDR and behavioral detection | Not necessarily | Depends on behavior | Depends on telemetry | Not recorded |
| Defender modification attempt | Tamper Protection and antivirus | Expected when protected | Depends on activity | Depends on telemetry | Not recorded |
| LSASS ASR | ASR credential-stealing protection | Expected in Block mode | Do not assume | Validate locally and in hunting | Not recorded |
| Obfuscated-script ASR | ASR script protection | Expected in Block mode | Do not assume | Validate locally and in hunting | Not recorded |
| Office child process ASR | Office child-process rule | Expected in Block mode | Do not assume | Validate locally and in hunting | Not recorded |
| Office process injection ASR | Office process-injection rule | Expected in Block mode | Do not assume | Validate locally and in hunting | Not recorded |
| PsExec/WMI ASR | Process creation from PsExec and WMI | Expected in Block mode | Do not assume | Validate locally and in hunting | Not recorded |
| Prompt-injection test | AI protection capability | A block may be visible | An alert was not observed in current lab testing | Availability can vary | Block observed; alert not observed |

> [!NOTE]
> Replace generalized expectations with confirmed results from each supported platform and configuration. The purpose of this matrix is to prevent a successful prevention event from being incorrectly documented as a guaranteed alert.

## Test Details

### Network Protection

**Purpose**

Validate that Microsoft Defender Network Protection evaluates access to a known test destination or scenario.

**What this test proves**

- Network Protection is receiving and evaluating the request.
- The configured policy mode is being applied.
- Local and portal telemetry can be reviewed for the test.

**Validate**

- User-facing block or warning
- Windows Defender Operational events
- Device timeline network events
- Alerts only when the selected scenario is documented to generate one

---

### EICAR Antivirus Test

**Purpose**

Validate basic antivirus detection using the industry-standard EICAR test file.

**What this test proves**

- Microsoft Defender Antivirus is active.
- File inspection is functioning.
- Antivirus remediation and associated telemetry can be tested without real malware.

**Validate**

- Detection or quarantine action
- Protection history
- Windows Defender Operational events
- Device timeline
- Defender XDR alert or incident, when produced

---

### Potentially Unwanted Application Test

**Purpose**

Validate PUA protection with an approved test scenario.

**What this test proves**

- PUA policy is configured.
- The endpoint applies the configured Audit, Warn, or Block behavior.
- Relevant telemetry can be investigated.

**Validate**

- PUA protection state
- Local detection or block
- Device timeline
- Relevant Advanced Hunting events

---

### AMSI Test

**Purpose**

Validate the Antimalware Scan Interface path used to inspect script content.

**What this test proves**

- Script content reaches AMSI-aware protection.
- Microsoft Defender Antivirus evaluates the content.
- The resulting action matches the configured protection state.

**Validate**

- PowerShell or script-host output
- Windows Defender Operational events
- Device timeline
- Alerts only if the selected test produces one

---

### Behavior Monitoring Test

**Purpose**

Validate behavioral inspection independently from a simple file-signature test.

**What this test proves**

- Behavior monitoring is enabled and evaluating activity.
- The endpoint can detect or block the selected behavior.
- Relevant device telemetry is available for investigation.

---

### EDR Test

**Purpose**

Use a supported Microsoft Defender for Endpoint test to validate sensor connectivity and EDR detection.

**What this test proves**

- The device is onboarded and communicating with Microsoft Defender for Endpoint.
- EDR telemetry reaches the Defender portal.
- The supported demonstration can create the expected detection workflow.

---

### ORADAD and Reconnaissance Tests

**Purpose**

Generate authorized directory or system reconnaissance activity in a lab.

**What this test proves**

- Relevant reconnaissance behavior is visible to the enabled Defender products.
- Endpoint, identity, and directory data sources can be reviewed together.

**Caution**

Reconnaissance tests can contribute to a broader attack story. Review automated investigation, attack disruption, affected accounts, and lab cleanup requirements before running these tests.

---

### Remote PowerShell and Lateral Movement Test

**Purpose**

Generate authorized remote-execution behavior for Defender validation.

**What this test proves**

- Remote execution telemetry can be collected.
- Behavioral detections can be evaluated.
- Device timeline and hunting evidence can be correlated across systems.

**Caution**

Use only test accounts and isolated lab devices. Confirm that production systems cannot be reached from the test environment.

---

### Defender Modification and Tamper Protection Test

**Purpose**

Validate protection against unauthorized modification of Microsoft Defender settings or services.

**What this test proves**

- Tamper Protection or related controls resist the attempted change.
- Administrative and security telemetry records the attempted action where supported.

**Caution**

Do not weaken production protection settings to make this scenario run.

---

### LSASS Credential Theft ASR Test

**Purpose**

Validate the ASR rule that blocks credential stealing from the Windows Local Security Authority Subsystem.

**What this test proves**

- The ASR rule is applied to the device.
- The attempted LSASS access is blocked or audited according to policy.
- Local Defender evidence can be reviewed.

**Known gotcha**

A blocked attempt does not guarantee a Defender XDR alert. Validate the rule action, local event, device timeline, and available hunting telemetry separately.

---

### Obfuscated-Script ASR Test

**Purpose**

Validate the ASR rule that blocks potentially obfuscated scripts.

**What this test proves**

- The ASR rule evaluates the script.
- The configured action is enforced.
- Local evidence can be collected even when an alert is not created.

**Known gotcha**

A script may be blocked without the expected ASR event appearing in the Advanced Hunting table being queried. Confirm that another protection layer, such as antivirus or AMSI, did not cause the block.

---

### Office Child-Process ASR Test

**Purpose**

Validate the ASR rule that blocks Microsoft Office applications from creating child processes.

**What this test proves**

- The Office child-process ASR rule is applied.
- An Office application is prevented from starting the test child process when the rule is in Block mode.

**Known gotchas**

- Microsoft Office must be installed.
- Macro controls can prevent the test from reaching the ASR rule.
- Do not weaken production macro policy solely to run the demonstration.
- A prevention event does not guarantee a Defender XDR alert.

The repository can include the file `ASR_Office_Child_Process_Test_Instructions.docx` for transparent lab instructions. The document should not be presented as an automatically executing file.

---

### Office Process-Injection ASR Test

**Purpose**

Validate the ASR rule that blocks Office applications from injecting code into other processes.

**What this test proves**

- The process-injection rule is applied.
- The test behavior is blocked or audited according to policy.

---

### PsExec and WMI Process-Creation ASR Test

**Purpose**

Validate the ASR rule that blocks process creation originating from PsExec and WMI commands.

**What this test proves**

- The rule evaluates process creation from the selected management mechanism.
- The configured action is enforced.

**Known gotcha**

Administrative and diagnostic tools can legitimately use PsExec or WMI. Run the test only on an isolated lab device and document any required exclusions separately from the test.

---

### Prompt-Injection Protection Test

**Purpose**

Validate whether the available Microsoft security control identifies or blocks a supported prompt-injection test scenario.

**Current lab observation**

- A block was observed.
- A Defender alert was not observed.
- The test must not be documented as a guaranteed alert-generation scenario.

**What this test proves**

The current test demonstrates prevention behavior only unless alert or hunting evidence is independently confirmed.

## Microsoft Exploit Guard Demo Tool

The Microsoft Exploit Guard Demo Tool, commonly downloaded as `ASRtool.exe`, provides a graphical interface for testing multiple ASR scenarios.

Observed behavior from the lab version:

- File description: `Test Tool for demoing Exploit Guard`
- Internal name: `AntiMalware.Tools.DemoExploitGuard`
- The interface provides Rule, Mode, Scenario, Delay, Leave Dirty, and All Scenarios options.
- The tool writes a scenario file under `C:\ProgramData\AntiMalwareTest`.
- The tool executes the scenario and then cleans up the generated file.
- For an obfuscated JavaScript test, Windows Script Host displayed `Access is denied` when the ASR rule blocked the generated script.
- Running `ASRtool.exe /?` or `ASRtool.exe -?` did not display command-line help in the tested version.

### Recommended Use

Use the graphical tool for Microsoft-provided ASR validation rather than recreating its generated test artifacts. Keep custom PowerShell automation focused on launching documented scripts, recording timestamps, and collecting evidence.

### Evidence to Capture

- Screenshot of the selected ASR rule and mode
- Screenshot or text from the tool output pane
- Windows Script Host or process error shown during the block
- Defender Operational event
- Device timeline event
- Advanced Hunting result, when available
- Alert or incident, only when one is actually generated

## Advanced Hunting Starter Queries

### Recent ASR-related device events

```kusto
DeviceEvents
| where Timestamp > ago(1h)
| where ActionType contains "Asr"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, ReportId
| order by Timestamp desc
```

### Recent alerts for the test device

Replace `LAB-DEVICE-NAME` with the correct device name.

```kusto
AlertInfo
| where Timestamp > ago(24h)
| join kind=leftouter AlertEvidence on AlertId
| where DeviceName =~ "LAB-DEVICE-NAME"
| project Timestamp, Title, Severity, Category, DetectionSource,
          ServiceSource, DeviceName, AlertId
| order by Timestamp desc
```

### Recent script-host activity

```kusto
DeviceProcessEvents
| where Timestamp > ago(1h)
| where FileName in~ ("powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "cmd.exe")
| project Timestamp, DeviceName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          AccountName, ReportId
| order by Timestamp desc
```

### Recent antivirus events

```kusto
DeviceEvents
| where Timestamp > ago(24h)
| where ActionType has_any ("Antivirus", "Malware", "PotentiallyUnwantedApplication")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath,
          AdditionalFields, ReportId
| order by Timestamp desc
```

> [!NOTE]
> Table and action-type availability can vary. If a local block occurred but a query returns no records, review the device timeline and local Defender Operational log before concluding that the test failed.

## Local Validation

### Review recent Defender Operational events

```powershell
Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' -MaxEvents 200 |
    Where-Object {
        $_.Message -match 'attack surface reduction|ASR|blocked|obfuscat|LSASS|Office|wscript|cscript'
    } |
    Select-Object TimeCreated, Id, LevelDisplayName, Message
```

### Review configured ASR rule actions

```powershell
$Preference = Get-MpPreference

0..([Math]::Min(
    $Preference.AttackSurfaceReductionRules_Ids.Count,
    $Preference.AttackSurfaceReductionRules_Actions.Count
) - 1) | ForEach-Object {
    [PSCustomObject]@{
        RuleId = $Preference.AttackSurfaceReductionRules_Ids[$_]
        Action = $Preference.AttackSurfaceReductionRules_Actions[$_]
    }
} | Format-Table -AutoSize
```

Common action values:

- `0`: Disabled
- `1`: Block
- `2`: Audit
- `6`: Warn

## MITRE ATT&CK Mapping

This mapping is provided as documentation guidance. Confirm the applicable technique for the exact behavior used by each script before publishing a final mapping.

| Test | Candidate MITRE ATT&CK Technique |
|---|---|
| LSASS credential access | T1003, OS Credential Dumping |
| Obfuscated scripts | T1027, Obfuscated Files or Information |
| PowerShell | T1059.001, PowerShell |
| Windows Command Shell | T1059.003, Windows Command Shell |
| JavaScript or JScript | T1059.007, JavaScript/JScript |
| WMI execution | T1047, Windows Management Instrumentation |
| Process injection | T1055, Process Injection |
| Remote services or lateral movement | Confirm against the exact remote-execution method |
| Reconnaissance | Confirm against the exact discovery commands used |

## Known Gotchas

### ASR rules do not always generate alerts

ASR rules are prevention controls. A successful block can appear locally or in device telemetry without producing an alert or incident.

### A blocked script may have been stopped by another control

AMSI, antivirus, script-host policy, application control, or another ASR rule may block the same behavior. Review the evidence to attribute the block correctly.

### Advanced Hunting data can differ by scenario

Do not assume every block will appear in a specific table or under a specific `ActionType`. Search multiple relevant tables and compare results with the device timeline.

### Prompt-injection testing may demonstrate a block without an alert

Document the observed result accurately. Do not claim that the scenario generates an alert unless an alert is present in the tenant.

### Office tests can be stopped before reaching ASR

Macro policy, Protected View, application hardening, antivirus, or application control can prevent the test from reaching the intended Office ASR rule.

### Automated response can disrupt lab access

Some combinations of tests may contribute to an attack story and initiate automated response. Use dedicated test identities and monitor account and device status throughout testing.

## Troubleshooting Checklist

If a test does not produce the expected result:

1. Confirm Microsoft Defender Antivirus is in active mode.
2. Confirm the device is onboarded and sensor health is good.
3. Confirm the intended ASR rule ID and action.
4. Confirm policy reached the device.
5. Check for Defender and ASR exclusions.
6. Confirm the test was launched from the expected parent process.
7. Review Windows Defender Operational events.
8. Review Protection History.
9. Review the Defender device timeline.
10. Search multiple Advanced Hunting tables.
11. Confirm another protection layer did not block the behavior first.
12. Confirm the demonstration is supported on the installed Windows and application versions.
13. Record the difference between expected and observed results.

## Test Result Template

Copy this section for every test run.

```markdown
### Test Run

- Test name:
- Date and time:
- Device name:
- Signed-in test account:
- Windows version:
- Defender platform version:
- Defender engine version:
- Security intelligence version:
- MDE sensor health:
- Policy source:
- Rule or feature mode:
- Script or tool version:
- Local result:
- Operational event ID:
- Device timeline result:
- Advanced Hunting result:
- Alert ID:
- Incident ID:
- Cleanup completed:
- Notes:
```

## Cleanup

- Stop any scheduled tasks created for recurring tests.
- Remove generated test files.
- Remove temporary exclusions created specifically for the lab.
- Restore ASR rules and Defender settings to their intended values.
- Close Microsoft Office applications used during testing.
- Confirm test accounts remain enabled and accessible.
- Confirm the lab device is not isolated unless isolation is intentional.
- Resolve or classify expected test alerts according to the lab process.
- Preserve only the screenshots, event exports, and hunting results required for documentation.

## Microsoft References

- [Microsoft Defender for Endpoint demonstration scenarios](https://learn.microsoft.com/en-us/defender-endpoint/defender-endpoint-demonstration-attack-surface-reduction-rules)
- [Attack surface reduction rules reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference)
- [Microsoft Defender Testground: Attack Surface Reduction](https://demo.wd.microsoft.com/Page/ASR2)
- [Investigate alerts in Microsoft Defender XDR](https://learn.microsoft.com/en-us/defender-xdr/investigate-alerts)
- [Microsoft Defender portal](https://security.microsoft.com/)

## Disclaimer

This repository is intended for authorized security validation in isolated lab environments. Test behavior and resulting telemetry can change as Microsoft Defender components, detections, platform versions, and cloud services evolve. Always review Microsoft documentation and validate current behavior before using the material in a customer demonstration.
