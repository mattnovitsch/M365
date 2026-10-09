#requires -Version 5.1
#requires -Modules GroupPolicy, ActiveDirectory
<#
.SYNOPSIS
    Creates/updates a domain GPO from the exported Intune policy "Windows Baseline AV Policy".
.DESCRIPTION
    - Targets the PDC Emulator for every Group Policy operation.
    - Finds the GPO once, then modifies it by GUID.
    - Waits for a new GPO's SYSVOL folder and retries failed writes.
    - ASR rules and Controlled Folder Access in Audit. EDR in block mode enabled.
    - Verifies key settings and exports a Backup-GPO backup.
#>
[CmdletBinding()]
param(
    [string]$GpoName    = 'SEC - Windows Baseline AV Policy',
    [string]$BackupPath = (Join-Path $PSScriptRoot 'GPO-Backup'),
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$ScriptVersion = '2026-10-09 v4 (retry + EDR block mode)'

Import-Module GroupPolicy     -ErrorAction Stop
Import-Module ActiveDirectory -ErrorAction Stop

Write-Host "Script version: $ScriptVersion" -ForegroundColor Magenta

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
$Exploit  = "$WD\Windows Defender Exploit Guard"
$NP       = "$Exploit\Network Protection"
$ASRRoot  = "$Exploit\ASR"
$ASR      = "$Exploit\ASR\Rules"
$CFA      = "$Exploit\Controlled Folder Access"
$NIS      = "$WD\NIS\Consumers\IPS"
#endregion

#region Defender AV settings
Write-Host 'Writing Defender Antivirus settings...' -ForegroundColor Cyan
Set-Dword $Scan 'DisableArchiveScanning' 0
Set-Dword $RTP  'DisableBehaviorMonitoring' 0
Set-Dword $Spy  'SpynetReporting' 2
Set-Dword $Scan 'DisableEmailScanning' 0
Set-Dword $Scan 'DisableScanningMappedNetworkDrivesForFullScan' 1
Set-Dword $Scan 'DisableRemovableDriveScanning' 0
Set-Dword $WD   'DisableIntrusionPreventionSystem' 0
Set-Dword $RTP  'DisableIOAVProtection' 0
Set-Dword $RTP  'DisableRealtimeMonitoring' 0
Set-Dword $Scan 'DisableScanningNetworkFiles' 0
Set-Dword $RTP  'DisableScriptScanning' 0
Set-Dword $WD   'UILockdown' 0
Set-Dword $Scan 'CheckForSignaturesBeforeRunningScan' 1
Set-Dword $Mp   'MpCloudBlockLevel' 0
Set-Dword $NP   'EnableNetworkProtection' 1
Set-Dword $WD   'PUAProtection' 1
Set-Dword $RTP  'RealtimeScanDirection' 0
Set-Dword $Scan 'ScheduleQuickScanTime' 120
Set-Dword $Spy  'SubmitSamplesConsent' 3
Set-Dword $WD   'DisableLocalAdminMerge' 1
Set-Dword $RTP  'DisableOnAccessProtection' 0
#endregion

#region Threat severity default actions: Quarantine (2)
Write-Host 'Writing threat severity default actions...' -ForegroundColor Cyan
Set-Dword  $Threats 'Threats_ThreatSeverityDefaultAction' 1
Set-String $Threat '1' '2'
Set-String $Threat '2' '2'
Set-String $Threat '4' '2'
Set-String $Threat '5' '2'
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

#region Verify
Write-Host ''
Write-Host 'Verifying...' -ForegroundColor Cyan
function Get-GpoValue {
    param([string]$Key, [string]$Name)
    (Get-GPRegistryValue -Guid $GpoId -Domain $Domain -Server $PDC `
        -Key $Key -ValueName $Name -ErrorAction SilentlyContinue).Value
}
$asrValues = @(Get-GPRegistryValue -Guid $GpoId -Domain $Domain -Server $PDC -Key $ASR -ErrorAction SilentlyContinue |
    Where-Object { $_.ValueName })
$asrAudit  = @($asrValues | Where-Object { "$($_.Value)" -eq '2' })
$cfaValue  = Get-GpoValue $CFA 'EnableControlledFolderAccess'
$edrValue  = Get-GpoValue $Features 'PassiveRemediation'
$npValue   = Get-GpoValue $NP 'EnableNetworkProtection'

Write-Host "ASR rules in GPO:        $($asrValues.Count) (expected $($AsrRules.Count))"
Write-Host "ASR rules set to Audit:  $($asrAudit.Count)"
Write-Host "CFA value:               $cfaValue (expected 2 = Audit)"
Write-Host "EDR in block mode:       $edrValue (expected 1)"
Write-Host "Network Protection:      $npValue (expected 1 = Block)"
if ($asrAudit.Count -ne $AsrRules.Count -or "$cfaValue" -ne '2' -or "$edrValue" -ne '1') {
    Write-Warning 'Verification did not match expected values.'
}
#endregion

#region Backup
New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null
$backup = Backup-GPO -Guid $GpoId -Domain $Domain -Server $PDC -Path $BackupPath `
    -Comment 'Intune Windows Baseline AV conversion; ASR and CFA Audit; EDR block mode enabled'
Write-Host ''
Write-Host "GPO updated: $GpoName (ID $GpoId)" -ForegroundColor Green
Write-Host "Backup ID:   $($backup.Id)"
Write-Host "Backup path: $BackupPath"
#endregion