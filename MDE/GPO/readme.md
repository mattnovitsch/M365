# Build-WindowsBaselineAV-GPO.ps1

Creates or updates an Active Directory Group Policy Object (GPO) that applies a Microsoft Defender Antivirus baseline converted from the Intune Endpoint Security policy **Windows Baseline AV Policy**.

The script also:

- Sets **Turn off Microsoft Defender Antivirus** to **Disabled**, so the GPO explicitly keeps Defender Antivirus on
- Sets all Attack Surface Reduction (ASR) rules to **Audit**
- Sets Controlled Folder Access (CFA) to **Audit**
- Turns on **EDR in block mode**
- Optionally imports **path**, **process**, and **extension** exclusions from CSV files
- Checks the GPO after writing and exports a native `Backup-GPO` backup

> **Script version:** `2026-10-09 v5 (default cloud level + CSV exclusions)`
> The first line of output shows the version. If it doesn't match, you're running an old copy.

---

## Contents

- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Parameters](#parameters)
- [How the script works](#how-the-script-works)
- [Settings configured](#settings-configured)
- [ASR rules (Audit)](#asr-rules-audit)
- [Exclusions from CSV](#exclusions-from-csv)
- [Verification output](#verification-output)
- [Backup and import](#backup-and-import)
- [Validating on a client](#validating-on-a-client)
- [Troubleshooting](#troubleshooting)
- [Deployment guidance](#deployment-guidance)

---

## Requirements

| Requirement | Details |
|---|---|
| PowerShell | Windows PowerShell 5.1 |
| Modules | `GroupPolicy` and `ActiveDirectory` (RSAT / GPMC) |
| Machine | Domain-joined Windows management server or the domain controller |
| Permissions | Rights to create and edit GPOs in the domain (for example, Domain Admins) |
| ADMX templates | Current Microsoft Defender Antivirus templates in the Central Store, so GPMC shows setting names instead of **Extra Registry Settings** |

---

## Quick start

Create or update the GPO without exclusions:

```powershell
.\Build-WindowsBaselineAV-GPO.ps1 -Force
```

Create or update the GPO with all three exclusion lists:

```powershell
.\Build-WindowsBaselineAV-GPO.ps1 -Force `
    -PathCsv      "C:\tools\PathExclusions.csv" `
    -ProcessCsv   "C:\tools\ProcessExclusions.csv" `
    -ExtensionCsv "C:\tools\ExtensionExclusions.csv"
```

Use a specific backup folder:

```powershell
.\Build-WindowsBaselineAV-GPO.ps1 -Force -BackupPath "D:\GPOBackups\DefenderAV"
```

---

## Parameters

| Parameter | Required | Default | Description |
|---|---|---|---|
| `-GpoName` | No | `SEC - Windows Baseline AV Policy` | Display name of the GPO to create or update |
| `-BackupPath` | No | `GPO-Backup` next to the script, or in the current folder | Where `Backup-GPO` writes the backup |
| `-PathCsv` | No | None | CSV of folder and file exclusions (column `Path`) |
| `-ProcessCsv` | No | None | CSV of process exclusions (column `Process`) |
| `-ExtensionCsv` | No | None | CSV of file extension exclusions (column `Extension`) |
| `-Force` | No | Off | Update the GPO if it already exists. Without it, the script stops when the GPO exists |

---

## How the script works

1. **Sets the backup path.** Uses `-BackupPath` if given. Otherwise uses the script's folder, or the current folder when `$PSScriptRoot` is empty (for example, when pasted into the console or run from ISE).
2. **Finds the domain and PDC Emulator** with `Get-ADDomain`, and stops if either can't be determined.
3. **Finds or creates the GPO on the PDC.** Every Group Policy operation targets the PDC so reads and writes stay on the same domain controller.
4. **Uses the GPO's GUID for every change**, so it never looks the GPO up by name again.
5. **Waits for the GPO's SYSVOL folder** (`\\<PDC>\SYSVOL\<domain>\Policies\{GUID}`) for up to 120 seconds. A newly created GPO also gets a 15-second pause before the first write.
6. **Retries failed writes** up to 6 times, 10 seconds apart, and prints `Retry n for ...` for each attempt. This handles short-lived `Access is denied (0x80070005)` errors.
7. **Writes all settings** into the GPO's `Registry.pol` in SYSVOL.
8. **Imports exclusions** from any CSVs provided.
9. **Checks the GPO** and prints a summary.
10. **Exports a native backup** with `Backup-GPO` and prints the Backup ID.

### The script doesn't change the local registry

Administrative Templates settings are stored as registry values **inside the GPO** (`Registry.pol` in SYSVOL). `Set-GPRegistryValue` writes that file the same way Group Policy Management Editor does. A device's registry only changes when that device applies the GPO. Tamper protection on the machine running the script doesn't block it.

---

## Settings configured

All settings are under **Computer Configuration > Policies > Administrative Templates > Windows Components > Microsoft Defender Antivirus**.

### Microsoft Defender Antivirus

| Setting | Value |
|---|---|
| Turn off Microsoft Defender Antivirus | **Disabled** (`DisableAntiSpyware = 0`). Defender Antivirus stays **on** |

### Real-time protection

| Setting | Value |
|---|---|
| Turn off real-time protection | Disabled (real-time protection **on**) |
| Turn on behavior monitoring | Enabled |
| Scan all downloaded files and attachments | Enabled |
| Turn on script scanning | Enabled |
| On-access protection | On (`DisableOnAccessProtection = 0`) |
| Monitoring direction | All files (`RealtimeScanDirection = 0`) |

### Cloud protection (MAPS)

| Setting | Value |
|---|---|
| Join Microsoft MAPS | Enabled: **Advanced MAPS** |
| Send file samples when further analysis is required | `3` (send all samples, from the Intune source) |
| Cloud protection level | **Not Configured** (Defender default). The script removes Zero Tolerance if an earlier version wrote it |

### Scan

| Setting | Value |
|---|---|
| Scan archive files | Enabled |
| Turn on e-mail scanning | Enabled |
| Scan removable drives | Enabled |
| Configure scanning of network files | Enabled |
| Run full scan on mapped network drives | Disabled |
| Check for the latest security intelligence before running a scheduled scan | Enabled |
| Quick scan time | 02:00 (`ScheduleQuickScanTime = 120`) |

### Protection features

| Setting | Value |
|---|---|
| Network Protection | **Block** (from the Intune source) |
| Potentially unwanted application (PUA) protection | **Block** |
| Enable EDR in block mode | **Enabled** (`Features\PassiveRemediation = 1`) |
| Controlled Folder Access | **Audit** (`EnableControlledFolderAccess = 2`) |
| Intrusion prevention system | On (`DisableIntrusionPreventionSystem = 0`) |
| Protocol parsing (DNS over TCP, HTTP, SSH, TLS) | Not disabled (`0`) |

### Threats and administration

| Setting | Value |
|---|---|
| Threat severity default actions | Enabled. Low, Moderate, High, and Severe all set to **Quarantine** (`2`) |
| Local administrator merge | **Disabled** (`DisableLocalAdminMerge = 1`). Exclusions added by local admins are ignored; only GPO exclusions apply |
| UI lockdown | Off (users can see the Defender UI) |

### A note on Turn off Microsoft Defender Antivirus

Setting this policy to **Disabled** makes the GPO explicitly state that Defender Antivirus must not be turned off, instead of leaving it Not Configured. If another GPO with higher precedence sets it to **Enabled**, that GPO wins, so check `gpresult` on pilot devices.

`DisableAntiSpyware` is a legacy setting, and newer Defender platform versions may ignore it. Don't treat the GPO value alone as proof that Defender is running. Confirm the service and antivirus state on the device (see [Validating on a client](#validating-on-a-client)).

### A note on EDR in block mode

EDR in block mode is designed for devices where a non-Microsoft antivirus is primary and Defender Antivirus runs in passive mode. On devices where Defender is the primary antivirus, which is what this GPO sets up, it adds little. It's included here by request. Cloud protection (MAPS) must be on for the feature to work, and this GPO turns it on.

---

## ASR rules (Audit)

**Configure Attack Surface Reduction rules** is set to **Enabled**, and every rule below is set to `2` (**Audit**). Rules in Audit mode don't block anything. They log events you can review before moving any rule to Block or Warn.

| Rule | GUID |
|---|---|
| Block abuse of exploited vulnerable signed drivers | `56a863a9-875e-4185-98a7-b882c64b5ce5` |
| Block credential stealing from LSASS | `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2` |
| Block persistence through WMI event subscription | `e6db77e5-3df2-4cf1-b95a-636979351e5b` |
| Block Adobe Reader from creating child processes | `7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c` |
| Block all Office applications from creating child processes | `d4f940ab-401b-4efc-aadc-ad5f3c50688a` |
| Block executable content from email client and webmail | `be9ba2d9-53ea-4cdc-84e5-9b1eeee46550` |
| Block executables unless they meet a prevalence, age, or trusted list criterion | `01443614-cd74-433a-b99e-2ecdc07bfc25` |
| Block execution of potentially obfuscated scripts | `5beb7efe-fd9a-4556-801d-275e5ffc04cc` |
| Block JavaScript or VBScript from launching downloaded executable content | `d3e037e1-3eb8-44c8-a917-57927947596d` |
| Block Office applications from creating executable content | `3b576869-a4ec-4529-8536-b80a7769e899` |
| Block Office applications from injecting code into other processes | `75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84` |
| Block Office communication applications from creating child processes | `26190899-1602-49e8-8b27-eb1d0a1ce869` |
| Block process creations from PsExec and WMI commands | `d1e49aac-8f56-4280-b9ba-993a6d77406c` |
| Block rebooting machine in Safe Mode | `33ddedf1-c6e0-47cb-833e-de6133960387` |
| Block untrusted and unsigned processes that run from USB | `b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4` |
| Block use of copied or impersonated system tools | `c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb` |
| Block Win32 API calls from Office macros | `92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b` |
| Use advanced protection against ransomware | `c1db55ab-c21a-4637-bb3f-a12568109d35` |
| Block Webshell creation for Servers | `a8f5898e-1dc8-49a9-9878-85004b8a61e6` |

Operating system support varies by rule. Rules a device doesn't support are ignored on that device.

---

## Exclusions from CSV

Each CSV is optional. Pass one, two, or all three.

| CSV parameter | Required column | GPO setting | Registry key in the GPO |
|---|---|---|---|
| `-PathCsv` | `Path` | Path Exclusions | `Windows Defender\Exclusions\Paths` |
| `-ProcessCsv` | `Process` | Process Exclusions | `Windows Defender\Exclusions\Processes` |
| `-ExtensionCsv` | `Extension` | Extension Exclusions | `Windows Defender\Exclusions\Extensions` |

### Example files

**PathExclusions.csv**

```csv
Path
C:\Program Files\Contoso\App
D:\SQLData
%ProgramData%\Contoso\Cache
"C:\Apps\Vendor, Inc\Bin"
```

**ProcessExclusions.csv**

```csv
Process
C:\Program Files\Contoso\App\ContosoSvc.exe
C:\Program Files\Backup\agent.exe
```

**ExtensionExclusions.csv**

```csv
Extension
.ldf
.mdf
```

### How the import behaves

- **Replaces the list.** Each list you pass replaces that list in the GPO, so removing a row from the CSV removes it from the GPO on the next run.
- **Leaves other lists alone.** Lists you don't pass aren't changed.
- **Cleans the input.** Trims whitespace, skips blank rows, and removes duplicates.
- **Normalizes extensions.** A leading `*` is removed, so `*.log` becomes `.log`.
- **Turns on the policy.** Sets `Exclusions_Paths`, `Exclusions_Processes`, or `Exclusions_Extensions` to `1` so GPMC shows the policy as Enabled.
- **Quotes paths with commas.** A path containing a comma must be in quotes in the CSV.

### Before importing a customer list

- **Avoid broad wildcards.** An entry like `*\isetup.exe` excludes that file name in every folder on every device.
- **Use full paths for processes.** A process exclusion skips files *opened by* that process; the process file itself is still scanned. A name alone, such as `agent.exe`, matches that name anywhere.
- **These are antivirus exclusions only.** They don't apply to ASR rules or Controlled Folder Access, which have their own exclusion and allowed-application settings.
- **Consider a separate GPO.** Application-specific exclusions are easier to scope and review in their own GPO, linked only to the devices that need them.

---

## Verification output

After writing, the script reads the values back from the GPO. A successful run looks like this:

```text
Verifying...
ASR rules in GPO:        19 (expected 19)
ASR rules set to Audit:  19
CFA value:               2 (expected 2 = Audit)
EDR in block mode:       1 (expected 1)
Network Protection:      1 (expected 1 = Block)
Turn off Defender AV:    0 (expected 0 = Disabled)
Cloud protection level:  Not Configured (expected Not Configured)
Paths exclusions:        4 (expected 4)
Processes exclusions:    2 (expected 2)
Extensions exclusions:   2 (expected 2)
```

Exclusion lines appear only for CSVs you passed. If any value doesn't match, the script prints a warning.

---

## Backup and import

Each run exports a native GPO backup and prints the Backup ID and an import command.

To import into another domain or environment, copy the whole backup folder, then run:

```powershell
Import-GPO -BackupId '<Backup ID>' `
    -Path '<Backup folder>' `
    -TargetName 'SEC - Windows Baseline AV Policy' `
    -CreateIfNeeded
```

Always use the **latest** Backup ID. Delete older backup folders so an outdated version isn't imported by mistake.

---

## Validating on a client

On a pilot device, from an elevated prompt:

**1. Apply and report**

```powershell
gpupdate /force
gpresult /h C:\temp\GPResults.html /f
```

In the report, confirm **SEC - Windows Baseline AV Policy** is listed under **Applied GPOs** and is the winning GPO for the Defender settings, including **Turn off Microsoft Defender Antivirus = Disabled**.

**2. Confirm Defender Antivirus is running**

```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name DisableAntiSpyware

Get-Service WinDefend | Select-Object Name, Status, StartType

Get-MpComputerStatus | Select-Object `
    AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled, AMRunningMode
```

Expected: `DisableAntiSpyware = 0`, `WinDefend` is `Running`, `AMServiceEnabled`, `AntivirusEnabled`, and `RealTimeProtectionEnabled` are `True`, and `AMRunningMode = Normal`.

**3. Check the settings Defender is actually using**

```powershell
Get-MpPreference | Select-Object `
    EnableControlledFolderAccess, CloudBlockLevel, EnableNetworkProtection, `
    PUAProtection, ExclusionPath, ExclusionProcess, ExclusionExtension
```

Expected: `EnableControlledFolderAccess = 2`, `CloudBlockLevel = 0`, `EnableNetworkProtection = 1`, `PUAProtection = 1`.

**4. Check ASR rule actions**

```powershell
$p = Get-MpPreference
0..($p.AttackSurfaceReductionRules_Ids.Count - 1) | ForEach-Object {
    [pscustomobject]@{
        Id     = $p.AttackSurfaceReductionRules_Ids[$_]
        Action = $p.AttackSurfaceReductionRules_Actions[$_]
    }
} | Format-Table -AutoSize
```

Every rule should show `Action = 2` (Audit).

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `Retry 1 for ... Access is denied (0x80070005)`, then the script continues | Short-lived lock on the GPO's files in SYSVOL | No action needed; the retry handles it |
| All 6 retries fail on the same setting | Consistent write failure to the GPO | Close any Group Policy Management Editor window open on this GPO. Run the script on the PDC. If it still fails, check replication with `repadmin /replsummary` and `dcdiag /test:sysvolcheck` |
| `Join-Path : Cannot bind argument to parameter 'Path' because it is an empty string` | Old script version; `$PSScriptRoot` is empty when pasted or run from ISE | Use v5, or pass `-BackupPath` |
| `Cannot validate argument on parameter 'Domain'` | Old script version that didn't set `$Domain` | Use v5 |
| `GPO ... already exists. Use -Force` | GPO name already in use | Rerun with `-Force` to update it |
| `CSV must have a '<Column>' column` | Wrong or missing CSV header | Use the headers `Path`, `Process`, and `Extension` |
| Settings appear under **Extra Registry Settings** in GPMC | Local ADMX templates don't include those settings | Install current Defender ADMX templates in the Central Store. The settings still apply |
| `gpresult` shows **Turn off Microsoft Defender Antivirus = Enabled** from another GPO | A higher-precedence GPO is turning Defender off | Find the winning GPO in `gpresult` and set the policy to Disabled or Not Configured there |
| `DisableAntiSpyware = 0` but `WinDefend` isn't running | Something other than this policy is stopping Defender (for example, another antivirus is registered, a service-level GPO, or missing platform components) | Check `Get-MpComputerStatus`, Windows Security Center, and the device's other GPOs and installed security products |
| Multiple GPOs with the same name | Earlier failed runs each created a GPO | List them with `Get-GPO -All | Where-Object DisplayName -eq '<name>'` and remove extras with `Remove-GPO -Guid <Id>` |

---

## Deployment guidance

1. **Pilot first.** Link the GPO to a pilot OU, not the domain root.
2. **Avoid policy conflicts.** Remove the Intune Antivirus and ASR policy assignments from devices that get this GPO. When both configure the same ASR rule, Group Policy takes precedence by default. Also check for older GPOs that set **Turn off Microsoft Defender Antivirus** to Enabled.
3. **Review audit data.** Use the ASR rules report or advanced hunting in the Microsoft Defender portal to see which rules and CFA events trigger.
4. **Add exclusions only when needed.** Scope them as narrowly as possible.
5. **Move rules to Block gradually.** Start with the rules that trigger least, then expand to more devices.
6. **Don't use this GPO for tamper protection.** Tamper protection can't be turned off through Group Policy, and changes to tamper-protected settings are ignored while it's on.
