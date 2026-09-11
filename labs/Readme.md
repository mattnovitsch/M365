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

The repository contains the following lab files:

- `AMSITest.ps1`
- `BehaviorMonitoring.ps1`
- `BlockProcessCreationfromWMI.ps1`
- `DownloadASRPackage.ps1`
- `DownloadEICARFile.ps1`
- `DownloadPUAFile.ps1`
- `EDRDetectionTest.ps1`
- `NetworkProtection.ps1`
- `OnDemandRun.ps1`
- `ORADAD.ps1`
- `Prompt-injection-Attack.txt`
- `Ransomware.ps1`
- `Recon.ps1`
- `RemotePowerShell.ps1`
- `RemoveDefender.ps1`
- `SuspiciousPowershell.ps1`

ASR testing is intentionally handled through the Microsoft-provided [Attack Surface Reduction - Microsoft Defender Testground](https://demo.wd.microsoft.com/Page/ASR2) and its downloadable ASR test tool.

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

## Repository Contents

```text
Defender-Alert-Generation/
├── README.md
├── AMSITest.ps1
├── BehaviorMonitoring.ps1
├── BlockProcessCreationfromWMI.ps1
├── DownloadEICARFile.ps1
├── DownloadPUAFile.ps1
├── EDRDetectionTest.ps1
├── NetworkProtection.ps1
├── OnDemandRun.ps1
├── ORADAD.ps1
├── Prompt-injection-Attack.txt
├── Ransomware.ps1
├── Recon.ps1
├── RemotePowerShell.ps1
├── RemoveDefender.ps1
└── SuspiciousPowershell.ps1
```
## Quick Start

1. Download or clone the repository to a dedicated lab device.
2. Open Windows PowerShell as administrator.
3. Change to the lab directory before each test.
4. Review scripts before running them.
5. Run one scenario at a time until its expected behavior is understood.
6. For ASR validation, use `DownloadASRPackage.ps1`, open the downloaded Microsoft ASR test tool, select the desired rule and configuration, and choose **RunScenario**.
7. Use `OnDemandRun.ps1` only after validating the individual repository scripts.
8. Review local and portal evidence after every test.

Example working directory:

```powershell
Set-Location 'C:\Tools\Labs'
```

## Test Matrix

The values below are validation guidance, not a guarantee of a specific alert. Update the **Observed Result** column with results from the lab tenant.

| Test | Test Source | Primary Control | Local Block Expected | Defender Alert Expected | Observed Result |
|---|---|---|---:|---:|---|
| EICAR | `DownloadEICARFile.ps1` | Microsoft Defender Antivirus | Yes, when protection is active | Commonly expected | Not recorded |
| PUA download | `DownloadPUAFile.ps1` | PUA protection | Depends on policy mode | Depends on detection and policy | Not recorded |
| Network Protection | `NetworkProtection.ps1` | Network Protection | Depends on policy mode | Depends on scenario | Not recorded |
| AMSI | `AMSITest.ps1` | AMSI and antivirus inspection | Depends on test and policy | Depends on detection | Not recorded |
| Behavior Monitoring | `BehaviorMonitoring.ps1` | Behavior monitoring | Depends on behavior | Depends on detection | Not recorded |
| EDR test | `EDRDetectionTest.ps1` | MDE sensor and EDR detections | Not always | Expected for the supported test | Not recorded |
| ORADAD | `ORADAD.ps1` | Identity and reconnaissance detections | Not necessarily | Depends on product coverage | Not recorded |
| Reconnaissance | `Recon.ps1` | Behavioral detection | Not necessarily | Depends on behavior | Not recorded |
| Remote PowerShell | `RemotePowerShell.ps1` | EDR and behavioral detection | Not necessarily | Depends on behavior | Not recorded |
| Defender modification attempt | `RemoveDefender.ps1` | Tamper Protection and antivirus | Expected when protected | Depends on activity | Not recorded |
| Suspicious PowerShell | `SuspiciousPowershell.ps1` | AMSI, antivirus, and EDR | Depends on behavior | Depends on detection | Not recorded |
| WMI process creation | `BlockProcessCreationfromWMI.ps1` | ASR process-creation protection | Expected in Block mode | Do not assume | Not recorded |
| Ransomware simulation | `Ransomware.ps1` | Applicable Defender protections | Depends on configuration | Depends on detection | Not recorded |
| Other ASR rules | Microsoft ASR test tool | Selected ASR rule | Expected in Block mode | Do not assume | Not recorded |
| Prompt-injection test | `Prompt-injection-Attack.txt` | AI protection capability | A block may be visible | Alert not observed in current lab testing | Block observed; alert not observed |

> [!NOTE]
> A successful prevention event must not be documented as a guaranteed alert. Confirm local enforcement, device timeline evidence, Advanced Hunting telemetry, and alerts separately.

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

### ORADAD and Reconnaissance Tests (requires access to an Active Directory Domain Controller)

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

### Attack Surface Reduction Testing

**Purpose**

Validate Microsoft Defender Attack Surface Reduction rules with the Microsoft-provided tool instead of maintaining custom ASR payload scripts in this repository.

**Microsoft test site**

Use [Attack Surface Reduction - Microsoft Defender Testground](https://demo.wd.microsoft.com/Page/ASR2) to download the ASR test tool and exercise the available ASR scenarios.

**Repository workflow**

1. Run `DownloadASRPackage.ps1` to obtain the Microsoft ASR test package.
2. Start `ASRtool.exe` on the dedicated lab device.
3. Select the ASR rule to validate.
4. Review the mode shown by the tool. A mode enforced through MDM can appear locked in the interface.
5. Expand **Show Advanced Options** only when scenario selection, delay, cleanup behavior, or multiple scenarios are needed.
6. Select **RunScenario**.
7. Capture the tool output, local Defender evidence, device timeline evidence, and hunting results.
8. Record an alert only if an alert was actually generated.

**Available tool behavior observed during lab testing**

- The tool provides rule and scenario selection in a graphical interface.
- Advanced options include Scenario, Delay, Leave Dirty, and All Scenarios.
- The tested version did not display command-line help when launched with `/?` or `-?`.
- The tool can write temporary scenario content under `C:\ProgramData\AntiMalwareTest`, execute the scenario, and clean up afterward.
- A blocked obfuscated JavaScript scenario displayed an `Access is denied` message from Windows Script Host.

**What this test approach proves**

- The selected ASR rule is evaluated by Defender.
- The configured Audit, Warn, or Block action is applied.
- Microsoft-provided ASR scenarios can be used without publishing custom payload implementations in this repository.

**Known gotchas**

- An ASR block does not guarantee a Defender XDR alert.
- Another protection layer can stop an action before the intended ASR rule evaluates it.
- Advanced Hunting visibility can vary by rule, event type, platform state, and available telemetry.
- Office-specific scenarios can be affected by Office security settings before they reach the intended ASR rule.

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

## Microsoft ASR Test Tool

The supported testing reference for ASR scenarios in this project is [Attack Surface Reduction - Microsoft Defender Testground](https://demo.wd.microsoft.com/Page/ASR2).

The Microsoft Defender Testground page provides the ASR test tool download and directs the tester to select the desired configuration and run the scenario. The project therefore references the Microsoft tool rather than uploading separate custom scripts for ASR rules already represented in the tool.

### Evidence to Capture

- Selected ASR rule
- Configured or MDM-enforced mode
- Selected scenario
- Output shown in the ASR tool
- Any Windows Script Host or process error generated by a block
- Relevant Windows Defender Operational event
- Relevant device timeline event
- Advanced Hunting result, when available
- Alert or incident, only when one is actually generated

### Cleanup

Use the cleanup guidance published on the Microsoft Defender Testground page and return lab policy to its intended state after testing. Do not disable centrally managed organizational policy solely to complete a demonstration.


## Repository File Reference

| File | Intended Validation Area |
|---|---|
| `AMSITest.ps1` | Antimalware Scan Interface inspection |
| `BehaviorMonitoring.ps1` | Defender behavior monitoring |
| `BlockProcessCreationfromWMI.ps1` | Process creation originating from WMI |
| `DownloadEICARFile.ps1` | Antivirus detection with the EICAR test file |
| `DownloadPUAFile.ps1` | Potentially unwanted application protection |
| `EDRDetectionTest.ps1` | Microsoft Defender for Endpoint EDR validation |
| `NetworkProtection.ps1` | Network Protection validation |
| `OnDemandRun.ps1` | On-demand orchestration of repository tests |
| `ORADAD.ps1` | Directory reconnaissance telemetry and detections |
| `Prompt-injection-Attack.txt` | Prompt-injection protection instructions |
| `Ransomware.ps1` | Ransomware-related lab validation |
| `Recon.ps1` | Reconnaissance behavior |
| `RemotePowerShell.ps1` | Remote PowerShell or lateral-movement behavior |
| `RemoveDefender.ps1` | Tamper Protection or Defender modification attempt |
| `SuspiciousPowershell.ps1` | Suspicious PowerShell behavior |

ASR scenarios not represented by `BlockProcessCreationfromWMI.ps1` are tested with the Microsoft ASR test tool from Defender Testground.

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
- [Attack Surface Reduction - Microsoft Defender Testground](https://demo.wd.microsoft.com/Page/ASR2)
- [Investigate alerts in Microsoft Defender XDR](https://learn.microsoft.com/en-us/defender-xdr/investigate-alerts)
- [Microsoft Defender portal](https://security.microsoft.com/)

## Disclaimer

This repository is intended for authorized security validation in isolated lab environments. Test behavior and resulting telemetry can change as Microsoft Defender components, detections, platform versions, and cloud services evolve. Always review Microsoft documentation and validate current behavior before using the material in a customer demonstration.
