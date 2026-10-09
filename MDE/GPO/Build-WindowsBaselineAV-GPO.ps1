#requires -Version 5.1
#requires -Modules GroupPolicy, ActiveDirectory
<#
.SYNOPSIS
    Creates/updates a domain GPO from the exported Intune policy "Windows Baseline AV Policy".

.DESCRIPTION
    - Targets the PDC Emulator for every Group Policy operation.
    - Finds the GPO once, then modifies it by GUID.
    - Waits for a new GPO's SYSVOL folder and retries failed writes.
    - Cloud protection level left Not Configured (Defender default).
    - ASR rules and Controlled Folder Access in Audit. EDR in block mode enabled.
    - Optional path, process, and extension exclusions imported from CSV files.
    - Verifies key settings and exports a Backup-GPO backup.

.EXAMPLE
    .\Build-WindowsBaselineAV-GPO.ps1 -Force

.EXAMPLE
    .\Build-WindowsBaselineAV-GPO.ps1 -Force `
        -PathCsv      "C:\tools\PathExclusions.csv" `
        -ProcessCsv   "C:\tools\ProcessExclusions.csv" `
        -ExtensionCsv "C:\tools\ExtensionExclusions.csv"
#>
[CmdletBinding()]
param(
    [string]$GpoName = 'SEC - Windows Baseline AV Policy',
    [string]$BackupPath,
    [string]$PathCsv,
    [string]$ProcessCsv,
    [string]$ExtensionCsv,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$ScriptVersion = '2026-10-09 v5 (default cloud level + CSV exclusions)'

Import-Module GroupPolicy     -ErrorAction Stop
Import-Module ActiveDirectory -ErrorAction Stop

Write-Host "Script version: $ScriptVersion" -ForegroundColor Magenta

#region Backup path (works when $PSScriptRoot is empty)
if (-not $BackupPath) {
    $baseFolder = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $BackupPath = Join-Path $baseFolder 'GPO-Backup'
}
Write-Host "Backup:    $BackupPath" -ForegroundColor Cyan
#endregion

#region Domain and PDC
$ADDomain = Get-ADDomain -ErrorAction Stop
$Domain   = $ADDomain.DNSRoot
$PDC      = $ADDomain.PDCEmulator

if (-not $Domain -or -not $Domain.Trim()) { throw 'Unable to determine the Active Directory DNS domain.' }
if (-not $PDC    -or -not $PDC.Trim())    { throw 'Unable to determine the PDC Emulator.' }

Write-Host "Domain:    $Domain" -ForegroundColor Cyan
Write-Host "PDC:       $PDC"    -ForegroundColor Cyan
#endregion

#region Find or create the GPO on the PDC
$GPO = Get-GPO -All -Domain $Domain -Server $PDC |
    Where-Object { $_.DisplayName -eq $GpoName } |
    Select-Object -First 1

if ($GPO -and -not $Force) {
    throw "GPO '$GpoName' already exists (ID $($GPO.Id)). Use -Force to update it."
}

$NewlyCreated = $false
if (-not $GPO) {
    Write-Host "Creating GPO: $GpoName" -ForegroundColor Yellow
    $GPO = New-GPO -Name $GpoName -Domain $Domain -Server $PDC `
        -Comment 'Converted from Intune Windows Baseline AV Policy. ASR and CFA Audit. EDR in block mode enabled.'
    $NewlyCreated = $true
}
else {
    Write-Host "Found existing GPO: $GpoName" -ForegroundColor Green
}

$GpoId = $GPO.Id
Write-Host "GPO ID:    $GpoId" -ForegroundColor Cyan

$SysvolPath = "\\$PDC\SYSVOL\$Domain\Policies\{$GpoId}"
$waited = 0
while (-not (Test-Path $SysvolPath) -and $waited -lt 120) {
    Write-Host "Waiting for SYSVOL folder: $SysvolPath" -ForegroundColor Yellow
    Start-Sleep -Seconds 10
    $waited += 10
}
if (-not (Test-Path $SysvolPath)) {
    throw "SYSVOL folder for GPO $GpoId not found on $PDC after $waited seconds."
}
if ($NewlyCreated) {
    Write-Host 'New GPO; pausing 15 seconds before writing settings...' -ForegroundColor Yellow
    Start-Sleep -Seconds 15
}
#endregion

#region Helpers
function Invoke-GPWrite {
    param([scriptblock]$Action, [string]$Description)
    for ($i = 1; $i -le 6; $i++) {
        try { & $Action; return }
        catch {
            if ($i -eq 6) { throw "Failed after $i attempts: $Description. $($_.Exception.Message)" }
            Write-Host "Retry $i for $Description ($($_.Exception.Message))" -ForegroundColor Yellow
            Start-Sleep -Seconds 10
        }
    }
}

function Set-Dword {
    param([string]$Key, [string]$Name, [int]$Value)
    Invoke-GPWrite -Description "$Key\$Name" -Action {
        Set-GPRegistryValue -Guid $GpoId -Domain $Domain -Server $PDC `
            -Key $Key -ValueName $Name -Type DWord -Value $Value | Out-Null
    }
}

function Set-String {
    param([string]$Key, [string]$Name, [string]$Value)
    Invoke-GPWrite -Description "$Key\$Name" -Action {
        Set-GPRegistryValue -Guid $GpoId -Domain $Domain -Server $PDC `
            -Key $Key -ValueName $Name -Type String -Value $Value | Out-Null
    }
}

function Remove-GpoValue {
    param([string]$Key, [string]$Name)
    try {
        if ($Name) {
            Remove-GPRegistryValue -Guid $GpoId -Domain $Domain -Server $PDC -Key $Key -ValueName $Name | Out-Null
        }
        else {
            Remove-GPRegistryValue -Guid $GpoId -Domain $Domain -Server $PDC -Key $Key | Out-Null
        }
    }
    catch { }   # value or key not present
}

function Get-GpoValue {
    param([string]$Key, [string]$Name)
    (Get-GPRegistryValue -Guid $GpoId -Domain $Domain -Server $PDC `
        -Key $Key -ValueName $Name -ErrorAction SilentlyContinue).Value
}
#endregion

#region Registry paths (inside the GPO)
$WD       = 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender'
$RTP      = "$WD\Real-Time Protection"
$Scan     = "$WD\Scan"
$Spy      = "$WD\Spynet"
$Mp       = "$WD\MpEngine"
$Threats  = "$WD\Threats"
$Threat   = "$WD\Threats\ThreatSeverityDefaultAction"
$Features = "$WD\Features"
$ExclRoot = "$WD\Exclusions"
$Exploit  = "$WD\Windows Defender Exploit Guard"
$NP       = "$Exploit\Network Protection"
$ASRRoot  = "$Exploit\ASR"
$ASR      = "$Exploit\ASR\Rules"
$CFA      = "$Exploit\Controlled Folder Access"
$NIS      = "$WD\NIS\Consumers\IPS"
#endregion

#region Defender AV settings
Write-Host 'Writing Defender Antivirus settings...' -ForegroundColor Cyan
Set-Dword $Scan 'DisableArchiveScanning' 0                          # Scan archive files
Set-Dword $RTP  'DisableBehaviorMonitoring' 0                       # Behavior monitoring on
Set-Dword $Spy  'SpynetReporting' 2                                 # Advanced MAPS
Set-Dword $Scan 'DisableEmailScanning' 0                            # Email scanning on
Set-Dword $Scan 'DisableScanningMappedNetworkDrivesForFullScan' 1   # No full scan of mapped drives
Set-Dword $Scan 'DisableRemovableDriveScanning' 0                   # Scan removable drives
Set-Dword $WD   'DisableIntrusionPreventionSystem' 0
Set-Dword $RTP  'DisableIOAVProtection' 0                           # Scan downloads and attachments
Set-Dword $RTP  'DisableRealtimeMonitoring' 0                       # Real-time protection on
Set-Dword $Scan 'DisableScanningNetworkFiles' 0                     # Scan network files
Set-Dword $RTP  'DisableScriptScanning' 0                           # Script scanning on
Set-Dword $WD   'UILockdown' 0                                      # Users can see the AV UI
Set-Dword $Scan 'CheckForSignaturesBeforeRunningScan' 1
Set-Dword $NP   'EnableNetworkProtection' 1                         # Block
Set-Dword $WD   'PUAProtection' 1                                   # Block
Set-Dword $RTP  'RealtimeScanDirection' 0                           # Monitor all files
Set-Dword $Scan 'ScheduleQuickScanTime' 120                         # 02:00
Set-Dword $Spy  'SubmitSamplesConsent' 3                            # Send all samples
Set-Dword $WD   'DisableLocalAdminMerge' 1                          # Ignore local admin exclusions
Set-Dword $RTP  'DisableOnAccessProtection' 0

# Cloud protection level: Not Configured (Defender default).
# Removes Zero Tolerance if an earlier run wrote it.
Remove-GpoValue $Mp 'MpCloudBlockLevel'
#endregion

#region Threat severity default actions: Quarantine (2)
Write-Host 'Writing threat severity default actions...' -ForegroundColor Cyan
Set-Dword  $Threats 'Threats_ThreatSeverityDefaultAction' 1
Set-String $Threat '1' '2'   # Low
Set-String $Threat '2' '2'   # Moderate
Set-String $Threat '4' '2'   # High
Set-String $Threat '5' '2'   # Severe
#endregion

#region EDR in block mode
Write-Host 'Enabling EDR in block mode...' -ForegroundColor Cyan
Set-Dword $Features 'PassiveRemediation' 1
#endregion

#region Protocol parsing
Set-Dword $NIS 'DisableDnsOverTcpParsing' 0
Set-Dword $NIS 'DisableHttpParsing' 0
Set-Dword $NIS 'DisableSshParsing' 0
Set-Dword $NIS 'DisableTlsParsing' 0
#endregion

#region Controlled Folder Access: Audit
Write-Host 'Writing Controlled Folder Access (Audit)...' -ForegroundColor Cyan
Set-Dword $CFA 'EnableControlledFolderAccess' 2
#endregion

#region ASR rules: Audit
Write-Host 'Writing ASR rules (Audit)...' -ForegroundColor Cyan
Set-Dword $ASRRoot 'ExploitGuard_ASR_Rules' 1

$AsrRules = @(
    '56a863a9-875e-4185-98a7-b882c64b5ce5'  # Vulnerable signed drivers
    '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'  # LSASS credential stealing
    'e6db77e5-3df2-4cf1-b95a-636979351e5b'  # WMI event subscription persistence
    '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c'  # Adobe Reader child processes
    'd4f940ab-401b-4efc-aadc-ad5f3c50688a'  # Office child processes
    'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550'  # Executable content from email/webmail
    '01443614-cd74-433a-b99e-2ecdc07bfc25'  # Executables unless prevalence/age/trusted
    '5beb7efe-fd9a-4556-801d-275e5ffc04cc'  # Obfuscated scripts
    'd3e037e1-3eb8-44c8-a917-57927947596d'  # JS/VBS launching downloaded executables
    '3b576869-a4ec-4529-8536-b80a7769e899'  # Office creating executable content
    '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84'  # Office code injection
    '26190899-1602-49e8-8b27-eb1d0a1ce869'  # Office communication child processes
    'd1e49aac-8f56-4280-b9ba-993a6d77406c'  # PsExec and WMI process creation
    '33ddedf1-c6e0-47cb-833e-de6133960387'  # Reboot into Safe Mode
    'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4'  # Untrusted/unsigned USB processes
    'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb'  # Copied/impersonated system tools
    '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b'  # Win32 API calls from Office macros
    'c1db55ab-c21a-4637-bb3f-a12568109d35'  # Advanced ransomware protection
    'a8f5898e-1dc8-49a9-9878-85004b8a61e6'  # Webshell creation for servers
)
foreach ($id in $AsrRules) { Set-String $ASR $id '2' }
#endregion

#region Exclusions from CSV (optional)
$ExclusionCounts = @{}

function Set-ExclusionList {
    param(
        [string]$CsvPath,     # CSV file to import
        [string]$Column,      # Path, Process, or Extension
        [string]$SubKey,      # Paths, Processes, or Extensions
        [string]$EnableName   # Exclusions_Paths, Exclusions_Processes, or Exclusions_Extensions
    )

    if (-not $CsvPath) { return }
    if (-not (Test-Path $CsvPath)) { throw "$Column CSV not found: $CsvPath" }

    $rows = @(Import-Csv -Path $CsvPath)
    if ($rows.Count -eq 0) { throw "$Column CSV is empty: $CsvPath" }
    if ($rows[0].PSObject.Properties.Name -notcontains $Column) {
        throw "$CsvPath must have a '$Column' column."
    }

    $values = @($rows |
        ForEach-Object { "$($_.$Column)".Trim() } |
        Where-Object { $_ } |
        ForEach-Object { if ($Column -eq 'Extension') { $_.TrimStart('*') } else { $_ } } |
        Sort-Object -Unique)

    Write-Host "Writing $($values.Count) $Column exclusions from $CsvPath..." -ForegroundColor Cyan

    $key = "$ExclRoot\$SubKey"

    # Clear the existing list so the GPO matches the CSV exactly
    Remove-GpoValue $key

    Set-Dword $ExclRoot $EnableName 1        # turns the policy on
    foreach ($v in $values) {
        Set-String $key $v '0'
        Write-Host "  + $v"
    }

    $script:ExclusionCounts[$SubKey] = $values.Count
}

Set-ExclusionList -CsvPath $PathCsv      -Column 'Path'      -SubKey 'Paths'      -EnableName 'Exclusions_Paths'
Set-ExclusionList -CsvPath $ProcessCsv   -Column 'Process'   -SubKey 'Processes'  -EnableName 'Exclusions_Processes'
Set-ExclusionList -CsvPath $ExtensionCsv -Column 'Extension' -SubKey 'Extensions' -EnableName 'Exclusions_Extensions'
#endregion

#region Verify
Write-Host ''
Write-Host 'Verifying...' -ForegroundColor Cyan

$asrValues  = @(Get-GPRegistryValue -Guid $GpoId -Domain $Domain -Server $PDC -Key $ASR -ErrorAction SilentlyContinue |
    Where-Object { $_.ValueName })
$asrAudit   = @($asrValues | Where-Object { "$($_.Value)" -eq '2' })
$cfaValue   = Get-GpoValue $CFA 'EnableControlledFolderAccess'
$edrValue   = Get-GpoValue $Features 'PassiveRemediation'
$npValue    = Get-GpoValue $NP 'EnableNetworkProtection'
$cloudValue = Get-GpoValue $Mp 'MpCloudBlockLevel'

Write-Host "ASR rules in GPO:        $($asrValues.Count) (expected $($AsrRules.Count))"
Write-Host "ASR rules set to Audit:  $($asrAudit.Count)"
Write-Host "CFA value:               $cfaValue (expected 2 = Audit)"
Write-Host "EDR in block mode:       $edrValue (expected 1)"
Write-Host "Network Protection:      $npValue (expected 1 = Block)"
Write-Host ("Cloud protection level:  {0} (expected Not Configured)" -f $(if ($null -eq $cloudValue) { 'Not Configured' } else { $cloudValue }))

foreach ($sub in $ExclusionCounts.Keys) {
    $actual = @(Get-GPRegistryValue -Guid $GpoId -Domain $Domain -Server $PDC `
        -Key "$ExclRoot\$sub" -ErrorAction SilentlyContinue | Where-Object { $_.ValueName })
    Write-Host ("{0,-24} {1} (expected {2})" -f "$sub exclusions:", $actual.Count, $ExclusionCounts[$sub])
}

if ($asrAudit.Count -ne $AsrRules.Count -or "$cfaValue" -ne '2' -or "$edrValue" -ne '1' -or $null -ne $cloudValue) {
    Write-Warning 'Verification did not match expected values. Review the output above.'
}
#endregion

#region Backup
New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null
$backup = Backup-GPO -Guid $GpoId -Domain $Domain -Server $PDC -Path $BackupPath `
    -Comment 'Intune Windows Baseline AV conversion; ASR and CFA Audit; EDR block mode; default cloud level'

Write-Host ''
Write-Host "GPO updated: $GpoName (ID $GpoId)" -ForegroundColor Green
Write-Host "Backup ID:   $($backup.Id)"
Write-Host "Backup path: $BackupPath"
Write-Host "Import example: Import-GPO -BackupId '$($backup.Id)' -Path '$BackupPath' -TargetName '$GpoName' -CreateIfNeeded"
#endregion
