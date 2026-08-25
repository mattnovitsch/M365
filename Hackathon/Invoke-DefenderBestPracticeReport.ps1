#Requires -Version 7.0
<#
.SYNOPSIS
    Assesses Microsoft Entra ID, Defender for Cloud, Defender for Endpoint, Defender for
    Identity, Defender for Office 365, Defender for Cloud Apps, and Microsoft Purview
    against best-practice baselines and produces a colour-coded (Green / Yellow / Red)
    self-contained HTML report with a light/dark theme switch.

.DESCRIPTION
    Each workload is evaluated by its own function. Every individual check returns one of
    four states:

        Green   - Setting is enabled / enforced / blocking as recommended
        Yellow  - Setting is partially configured (audit mode, warn mode, simulation,
                  report-only, lower tier/sub-plan, or only some objects compliant)
        Red     - Setting is off, missing, or not configured
        Gray    - Could not be evaluated (no permission, module missing, licensing,
                  or workload skipped)

    Nothing in this script writes to your tenant. All calls are read-only (GET).

    OUTPUT LOCATION: reports are written to the folder the script runs from unless
    -OutputFolder is supplied.

    NOTE ON INTUNE SETTINGS-CATALOG IDs: the Defender AV / ASR checks parse Intune
    settings-catalog policies. Setting definition IDs occasionally change between
    settings-catalog releases. Any ID that is not found is reported as Red
    ("not configured"); any value that cannot be interpreted is reported as Gray so you
    can tune the maps in $script:AvSettingMap / $script:AsrRuleMap without guessing.

    ASR MATCHING: the settings catalog identifies ASR rules by friendly-name setting
    definition IDs (for example BlockAdobeReaderFromCreatingChildProcesses with values
    of off / block / audit / warn), NOT by rule GUID. Matching on GUID alone returns
    nothing and every rule is falsely reported as "not configured". Rules are matched on
    the normalised friendly-name token first, then on the GUID as a fallback for the
    CSP / OMA-URI / legacy surfaces. Per-rule exclusion settings are explicitly skipped
    because their IDs contain the same rule name as the rule itself.

    If a rule still reports incorrectly, run with -DumpSettingIds. That writes every
    setting definition ID your tenant actually returns, its raw value, the interpreted
    state, and which map entry it matched - so the maps can be corrected against real
    data rather than assumptions.

    EXCHANGE / PURVIEW AUTHENTICATION: from ExchangeOnlineManagement 3.7.0, Web Account
    Manager (WAM) is the default authentication broker. In some environments the broker
    cannot be constructed and token acquisition fails with a NullReferenceException at
    RuntimeBroker..ctor. This script retries automatically: standard auth, then
    -DisableWAM, then -ExchangeCredential. The most common fix is simply running from a
    NON-ELEVATED PowerShell console as the signed-in Windows user.

    ENTRA ROLE MATCHING: privileged roles are resolved by reading role definitions from
    Graph and matching on displayName, rather than hardcoding role template GUIDs. Role
    template IDs are stable but easy to transcribe wrongly, and a wrong GUID would
    silently report "no admins" - which is far more dangerous than reporting Gray.

.PARAMETER OutputFolder
    Folder for the HTML/CSV/JSON output. Defaults to the folder the script runs from.
    Created if it does not exist.

.PARAMETER TenantId
    Entra tenant ID. Optional; used for Graph / Az sign-in and stamped on the report.

.PARAMETER SubscriptionId
    One or more Azure subscription IDs to assess for Defender for Cloud.
    Defaults to every enabled subscription visible to the signed-in account.

.PARAMETER Modules
    Which workloads to assess. Defaults to all seven.

.PARAMETER MdaPortalUrl
    Your Defender for Cloud Apps portal URL, e.g. https://contoso.us3.portal.cloudappsecurity.com
    Required only if you also pass -MdaApiToken for the legacy MDA REST checks.

.PARAMETER MdaApiToken
    Legacy Defender for Cloud Apps API token. Optional. Without it the MDA REST-only
    checks are reported as Gray.

.PARAMETER Cloud
    Cloud environment. Global (default), USGov, or USGovDoD. Controls Graph / ARM /
    MDE / Exchange endpoints.

.PARAMETER SkipConnect
    Reuse existing Az / Graph / Exchange sessions instead of prompting for sign-in.

.PARAMETER DumpSettingIds
    Diagnostic. Writes every discovered Intune setting definition ID and its value to a
    CSV alongside the report, including which map entry (if any) it matched.

.PARAMETER InstallMissingModules
    Install any missing or outdated modules without prompting.

.PARAMETER ModuleScope
    Where to install modules. CurrentUser (default, no admin rights) or AllUsers.

.PARAMETER SkipModuleCheck
    Bypass the prerequisite check entirely.

.PARAMETER DisableWam
    Skip the Exchange WAM broker and go straight to the fallback authentication path.

.PARAMETER ExchangeCredential
    Optional credentials for Exchange Online / Security & Compliance, used as the final
    authentication fallback. An MFA-enforced account generally cannot use this path.

.EXAMPLE
    .\Invoke-DefenderBestPracticeReport.ps1

    Runs all seven workloads and writes the reports next to the script.

.EXAMPLE
    .\Invoke-DefenderBestPracticeReport.ps1 -Modules Entra

    Entra ID identity baseline only - no Azure or Exchange sign-in required.

.EXAMPLE
    .\Invoke-DefenderBestPracticeReport.ps1 -Modules DefenderForOffice,Purview -DisableWam

.EXAMPLE
    .\Invoke-DefenderBestPracticeReport.ps1 -Modules DefenderForEndpoint -DumpSettingIds

.NOTES
    Required modules : Az.Accounts 2.12.0+, Microsoft.Graph.Authentication 2.0.0+,
                       ExchangeOnlineManagement 3.0.0+
    Required roles   : Security Reader (Entra) + Global Reader is generally sufficient.
                       Defender for Cloud checks additionally need Reader or Security
                       Reader on each Azure subscription.
                       Purview checks additionally need a compliance read role such as
                       Global Reader, Compliance Administrator, or the narrower
                       View-Only DLP Compliance Management / retention read roles.
                       Entra PIM checks need Global Reader, Security Reader or
                       Privileged Role Administrator.
                       Insider Risk Management and Communication Compliance checks
                       require E5 or the Compliance add-on plus their own role
                       assignments; where those cmdlets are absent the checks report
                       Gray, not Red.
    Graph scopes     : DeviceManagementConfiguration.Read.All,
                       DeviceManagementManagedDevices.Read.All,
                       SecurityIdentitiesHealth.Read.All,
                       SecurityIdentitiesSensors.Read.All,
                       Policy.Read.All,
                       Policy.Read.AuthenticationMethod,
                       RoleManagement.Read.Directory,
                       Directory.Read.All,
                       CloudApp-Discovery.Read.All

    PURVIEW SESSION NOTE: the unified audit log state is read from the Exchange Online
    session on purpose. Get-AdminAuditLogConfig returns UnifiedAuditLogIngestionEnabled
    as False in Security & Compliance PowerShell regardless of the real tenant setting,
    which would otherwise produce a false Red.
#>

[CmdletBinding()]
param(
    # Folder for the HTML/CSV/JSON output. Left empty by design so MAIN can resolve it -
    # a $PSScriptRoot default here would silently become the wrong folder if this script
    # is ever dot-sourced.
    [string] $OutputFolder,

    [string] $TenantId,

    [string[]] $SubscriptionId,

    [ValidateSet('Entra', 'DefenderForCloud', 'DefenderForEndpoint', 'DefenderForIdentity', 'DefenderForOffice', 'DefenderForCloudApps', 'Purview')]
    [string[]] $Modules = @('Entra', 'DefenderForCloud', 'DefenderForEndpoint', 'DefenderForIdentity', 'DefenderForOffice', 'DefenderForCloudApps', 'Purview'),

    [string] $MdaPortalUrl,

    [string] $MdaApiToken,

    [ValidateSet('Global', 'USGov', 'USGovDoD')]
    [string] $Cloud = 'Global',

    [switch] $SkipConnect,

    # Diagnostic: writes every discovered Intune setting definition ID and its value to
    # a CSV alongside the report. Use this to verify what your tenant actually returns
    # before trusting the AV / ASR maps in this script.
    [switch] $DumpSettingIds,

    # Install any missing or outdated modules without prompting.
    [switch] $InstallMissingModules,

    # Where to install modules. CurrentUser needs no admin rights and is the safe
    # default. AllUsers requires an elevated session.
    [ValidateSet('CurrentUser', 'AllUsers')]
    [string] $ModuleScope = 'CurrentUser',

    # Bypass the prerequisite check entirely (for example on a locked-down jump box
    # where modules are managed centrally).
    [switch] $SkipModuleCheck,

    # Skip the Exchange WAM broker entirely and go straight to the fallback auth path.
    [switch] $DisableWam,

    # Optional credentials for Exchange Online / Security & Compliance. Used as the
    # final fallback if broker-based auth cannot complete.
    [System.Management.Automation.PSCredential] $ExchangeCredential
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

# =====================================================================================
# REGION: Globals and endpoint maps
# =====================================================================================
#region Globals

$script:Results     = [System.Collections.Generic.List[object]]::new()
$script:StartTime   = Get-Date
$script:TenantLabel = 'Unknown tenant'

$script:Endpoints = @{
    Global = @{
        Graph    = 'https://graph.microsoft.com'
        Arm      = 'https://management.azure.com'
        Mde      = 'https://api.securitycenter.microsoft.com'
        GraphEnv = 'Global'
        AzEnv    = 'AzureCloud'
        ExoEnv   = 'O365Default'
    }
    USGov = @{
        Graph    = 'https://graph.microsoft.us'
        Arm      = 'https://management.usgovcloudapi.net'
        Mde      = 'https://api-gov.securitycenter.microsoft.us'
        GraphEnv = 'USGov'
        AzEnv    = 'AzureUSGovernment'
        ExoEnv   = 'O365USGovGCCHigh'
    }
    USGovDoD = @{
        Graph    = 'https://graph.microsoft.us'
        Arm      = 'https://management.usgovcloudapi.net'
        Mde      = 'https://api-gov.securitycenter.microsoft.us'
        GraphEnv = 'USGov'
        AzEnv    = 'AzureUSGovernment'
        ExoEnv   = 'O365USGovDoD'
    }
}

$script:Ep = $script:Endpoints[$Cloud]

# Weighted score contribution per state
$script:StateWeight = @{ Green = 2; Yellow = 1; Red = 0 }

#endregion

# =====================================================================================
# REGION: Module prerequisites
# =====================================================================================
#region Prerequisites

<#
    Module requirements, keyed to the workloads that actually need them. Only the
    modules required by the requested -Modules are checked, so running a single
    workload does not demand the full set.

    Minimum versions are deliberate, not arbitrary:

    ExchangeOnlineManagement 3.0.0
        This script calls Get-ConnectionInformation to detect an existing session.
        That cmdlet only exists in module version 3.0.0 or later - it was introduced
        as the replacement for Get-PSSession when the module moved off PowerShell
        Remoting.

    Az.Accounts 2.12.0
        Needed for Get-AzAccessToken -ResourceUrl against the MDE and ARM endpoints.
        NOTE: from Az.Accounts 5.0.0 (Az 14.0.0) the Token property returns a
        SecureString rather than plain text. Get-MdeToken below handles both shapes,
        so either side of that boundary works.

    Microsoft.Graph.Authentication 2.0.0
        Provides Connect-MgGraph and Invoke-MgGraphRequest as used throughout. Only
        the Authentication sub-module is required - the full Microsoft.Graph
        meta-module is large and unnecessary here.
#>
$script:RequiredModules = @(
    @{
        Name           = 'Az.Accounts'
        MinimumVersion = '2.12.0'
        NeededBy       = @('DefenderForCloud', 'DefenderForEndpoint')
        Reason         = 'Azure sign-in, Defender for Cloud ARM calls, and the Defender for Endpoint API token.'
    }
    @{
        Name           = 'Microsoft.Graph.Authentication'
        MinimumVersion = '2.0.0'
        NeededBy       = @('Entra', 'DefenderForEndpoint', 'DefenderForIdentity', 'DefenderForCloudApps')
        Reason         = 'Microsoft Graph calls for Entra policies and roles, Intune policies, MDI sensors, and Cloud Discovery.'
    }
    @{
        Name           = 'ExchangeOnlineManagement'
        MinimumVersion = '3.0.0'
        NeededBy       = @('DefenderForOffice', 'Purview')
        Reason         = 'Exchange Online and Security & Compliance sessions for Defender for Office 365 and Purview.'
    }
)

function Test-IsElevated {
    <# True only on Windows in an elevated session. Non-Windows returns false. #>
    if ($PSVersionTable.PSVersion.Major -ge 6 -and -not $IsWindows) { return $false }

    try {
        $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [Security.Principal.WindowsPrincipal]::new($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function Get-InstalledModuleVersion {
    <# Highest installed version of a module, or $null if not present. #>
    param([Parameter(Mandatory)][string] $Name)

    $found = Get-Module -Name $Name -ListAvailable -ErrorAction SilentlyContinue |
                Sort-Object Version -Descending |
                Select-Object -First 1

    if ($null -eq $found) { return $null }
    return $found.Version
}

function Install-RequiredModule {
    <#
        Installs or updates a single module from the PowerShell Gallery.
        Returns $true on success.

        -Force is used deliberately: it suppresses the "untrusted repository" prompt
        for this call only, rather than permanently changing the InstallationPolicy on
        the machine's PSGallery registration.
    #>
    param(
        [Parameter(Mandatory)][string] $Name,
        [string] $MinimumVersion,
        [Parameter(Mandatory)][string] $Scope
    )

    $effectiveScope = $Scope

    if ($effectiveScope -eq 'AllUsers' -and -not (Test-IsElevated)) {
        Write-Step -Message 'AllUsers scope requires an elevated session - falling back to CurrentUser.' -State 'Warn'
        $effectiveScope = 'CurrentUser'
    }

    $result = Invoke-Safely -Label ("install $Name") -Script {
        $installParams = @{
            Name         = $Name
            Scope        = $effectiveScope
            Force        = $true
            AllowClobber = $true
            ErrorAction  = 'Stop'
        }
        if ($MinimumVersion) { $installParams['MinimumVersion'] = $MinimumVersion }

        Install-Module @installParams
        return $true
    }

    if ($result -ne $true) { return $false }

    Write-Step -Message ('{0} installed to {1} scope.' -f $Name, $effectiveScope) -State 'Done'
    return $true
}

function Test-ModulePrerequisites {
    <#
        Verifies that every module required by the requested workloads is present and
        meets its minimum version. Offers to install or update whatever is missing,
        then imports it.

        Returns $true if all requirements are satisfied, $false if any are still
        outstanding. A $false result is not fatal - the affected workload simply
        reports Gray ("could not be evaluated") rather than a misleading Red.
    #>
    param([Parameter(Mandatory)][string[]] $Requested)

    Write-Step -Message 'Checking module prerequisites' -State 'Start'

    # ---- PowerShell version ----
    $psVersion = $PSVersionTable.PSVersion
    if ($psVersion.Major -lt 7) {
        Write-Step -Message ('PowerShell {0} detected. This script targets PowerShell 7 or later.' -f $psVersion) -State 'Warn'
        Write-Step -Message 'Install from https://aka.ms/powershell-release or run: winget install Microsoft.PowerShell' -State 'Info'
    }
    else {
        Write-Step -Message ('PowerShell {0}' -f $psVersion) -State 'Done'
    }

    # ---- Is Install-Module even available? ----
    $canInstall = $null -ne (Get-Command -Name 'Install-Module' -ErrorAction SilentlyContinue)
    if (-not $canInstall) {
        Write-Step -Message 'Install-Module is unavailable (PowerShellGet missing). Modules must be installed manually.' -State 'Warn'
    }

    # ---- Work out what this run actually needs ----
    $needed = @($script:RequiredModules | Where-Object {
        $module = $_
        @($module.NeededBy | Where-Object { $Requested -contains $_ }).Count -gt 0
    })

    if ($needed.Count -eq 0) {
        Write-Step -Message 'No modules required for the selected workloads.' -State 'Done'
        return $true
    }

    # ---- Evaluate each one ----
    $missing = [System.Collections.Generic.List[object]]::new()

    foreach ($module in $needed) {
        $installed = Get-InstalledModuleVersion -Name $module.Name

        if ($null -eq $installed) {
            Write-Step -Message ('{0} - NOT INSTALLED (minimum {1})' -f $module.Name, $module.MinimumVersion) -State 'Fail'
            $missing.Add(@{ Module = $module; Installed = $null; Action = 'install' })
            continue
        }

        if ([version]$installed -lt [version]$module.MinimumVersion) {
            Write-Step -Message ('{0} {1} - BELOW MINIMUM {2}' -f $module.Name, $installed, $module.MinimumVersion) -State 'Fail'
            $missing.Add(@{ Module = $module; Installed = $installed; Action = 'update' })
            continue
        }

        Write-Step -Message ('{0} {1} - OK' -f $module.Name, $installed) -State 'Done'
        Invoke-Safely -Label ("import $($module.Name)") -Script {
            Import-Module -Name $module.Name -ErrorAction Stop
        } | Out-Null
    }

    if ($missing.Count -eq 0) {
        Write-Step -Message 'All module prerequisites satisfied.' -State 'Done'
        return $true
    }

    # ---- Report the gap ----
    Write-Host ''
    Write-Host ' The following modules need attention:' -ForegroundColor Yellow
    foreach ($item in $missing) {
        $current = $item.Installed
        if ($null -eq $current) { $current = 'not installed' }

        Write-Host ('   - {0} (currently: {1}, required: {2}+)' -f $item.Module.Name, $current, $item.Module.MinimumVersion) -ForegroundColor Yellow
        Write-Host ('     {0}' -f $item.Module.Reason) -ForegroundColor DarkGray
    }
    Write-Host ''

    if (-not $canInstall) {
        Write-Step -Message 'Cannot install automatically. Affected workloads will report Gray.' -State 'Warn'
        return $false
    }

    # ---- Decide whether to install ----
    $proceed = $false

    if ($InstallMissingModules) {
        $proceed = $true
        Write-Step -Message 'InstallMissingModules specified - installing without prompting.' -State 'Info'
    }
    elseif ($Host.UI.RawUI -and -not [System.Console]::IsInputRedirected) {
        $answer = Read-Host ' Install/update these modules now? [Y/N]'
        $proceed = $answer -match '^(?i)y'
    }
    else {
        Write-Step -Message 'Non-interactive session. Re-run with -InstallMissingModules to install automatically.' -State 'Warn'
    }

    if (-not $proceed) {
        Write-Step -Message 'Skipping module installation. Affected workloads will report Gray.' -State 'Warn'
        return $false
    }

    # ---- Install ----
    $allSucceeded = $true

    foreach ($item in $missing) {
        $module = $item.Module
        Write-Step -Message ('{0} {1}...' -f $item.Action, $module.Name) -State 'Info'

        $ok = Install-RequiredModule -Name $module.Name -MinimumVersion $module.MinimumVersion -Scope $ModuleScope

        if (-not $ok) {
            $allSucceeded = $false
            Write-Step -Message ('{0} could not be installed. Its workloads will report Gray.' -f $module.Name) -State 'Fail'
            continue
        }

        Invoke-Safely -Label ("import $($module.Name)") -Script {
            Import-Module -Name $module.Name -Force -ErrorAction Stop
        } | Out-Null
    }

    if ($allSucceeded) {
        Write-Step -Message 'All module prerequisites satisfied.' -State 'Done'
        Write-Host ''
        Write-Host ' NOTE: if a module was updated while already loaded, close this session' -ForegroundColor DarkGray
        Write-Host ' and re-run so the new version loads cleanly.' -ForegroundColor DarkGray
        Write-Host ''
    }

    return $allSucceeded
}

#endregion

# =====================================================================================
# REGION: Core helpers  (console logging, result collection, safe invocation)
# =====================================================================================
#region Helpers

function Write-Step {
    <# Console progress marker. Purely cosmetic - never affects results. #>
    param(
        [Parameter(Mandatory)][string] $Message,
        [ValidateSet('Start', 'Done', 'Info', 'Warn', 'Fail')][string] $State = 'Info'
    )
    $map = @{
        Start = @{ Prefix = '>>>'; Color = 'Cyan' }
        Done  = @{ Prefix = '  +'; Color = 'Green' }
        Info  = @{ Prefix = '  .'; Color = 'Gray' }
        Warn  = @{ Prefix = '  !'; Color = 'Yellow' }
        Fail  = @{ Prefix = '  x'; Color = 'Red' }
    }
    $entry = $map[$State]
    Write-Host ('{0} {1}' -f $entry.Prefix, $Message) -ForegroundColor $entry.Color
}

function Add-Result {
    <#
        Records a single best-practice check. This is the ONLY way results enter the
        report, so every check funnels through here.
    #>
    param(
        [Parameter(Mandatory)][string] $Product,
        [Parameter(Mandatory)][string] $Category,
        [Parameter(Mandatory)][string] $Setting,
        [Parameter(Mandatory)][ValidateSet('Green', 'Yellow', 'Red', 'Gray')][string] $Status,
        [string] $Current        = 'Unknown',
        [string] $Expected       = '',
        [string] $Recommendation = '',
        [string] $Scope          = '',
        [string] $Reference      = ''
    )

    $currentValue = $Current
    if ([string]::IsNullOrWhiteSpace($currentValue)) { $currentValue = 'Unknown' }

    $script:Results.Add([pscustomobject]@{
        Product        = $Product
        Category       = $Category
        Setting        = $Setting
        Scope          = $Scope
        Status         = $Status
        Current        = $currentValue
        Expected       = $Expected
        Recommendation = $Recommendation
        Reference      = $Reference
    })
}

function Add-ModuleFailure {
    <# Marks an entire workload Gray when its connection or module prerequisite fails. #>
    param(
        [Parameter(Mandatory)][string] $Product,
        [Parameter(Mandatory)][string] $Reason,
        [string] $Recommendation = ''
    )
    Add-Result -Product $Product -Category 'Connectivity' -Setting 'Workload assessment' `
        -Status 'Gray' -Current $Reason -Expected 'Workload reachable and readable' `
        -Recommendation $Recommendation
    Write-Step -Message ('{0}: {1}' -f $Product, $Reason) -State 'Fail'
}

function Get-BoolState {
    <#
        Standard tri-state mapper for simple on/off settings.
        $true  -> Green, $false -> Red, $null -> Gray
        Pass -InvertGood for settings where $false is the secure value.
    #>
    param(
        $Value,
        [switch] $InvertGood
    )
    if ($null -eq $Value) { return 'Gray' }

    $asBool = $null
    if ($Value -is [bool]) {
        $asBool = $Value
    }
    else {
        $text = "$Value"
        if ($text -match '^(?i)(true|1|on|enabled|yes)$')       { $asBool = $true }
        elseif ($text -match '^(?i)(false|0|off|disabled|no)$') { $asBool = $false }
    }
    if ($null -eq $asBool) { return 'Gray' }

    if ($InvertGood) { $asBool = -not $asBool }
    if ($asBool) { return 'Green' } else { return 'Red' }
}

function Get-CoverageState {
    <#
        Tri-state for "N of M objects compliant" style checks.
        All compliant -> Green, some -> Yellow, none -> Red, nothing to test -> Gray.
    #>
    param(
        [int] $Compliant,
        [int] $Total
    )
    if ($Total -le 0)          { return 'Gray' }
    if ($Compliant -ge $Total) { return 'Green' }
    if ($Compliant -gt 0)      { return 'Yellow' }
    return 'Red'
}

function ConvertTo-HtmlSafe {
    <#
        Minimal HTML encoder. Written by hand rather than using System.Web.HttpUtility
        because System.Web is not guaranteed to load on PowerShell 7 / cross-platform.
    #>
    param([string] $Text)

    if ([string]::IsNullOrEmpty($Text)) { return '' }

    return $Text.Replace('&', '&amp;').
                 Replace('<', '&lt;').
                 Replace('>', '&gt;').
                 Replace('"', '&quot;').
                 Replace("'", '&#39;')
}

function Test-CmdletAvailable {
    <#
        Returns $true only if the named cmdlet is actually present in the session.
        Purview surfaces different cmdlet sets depending on licensing (E3 vs E5),
        cloud, and role assignment, so every optional check is gated through here
        rather than assuming the cmdlet exists and catching the failure later.
    #>
    param([Parameter(Mandatory)][string] $Name)

    return ($null -ne (Get-Command -Name $Name -ErrorAction SilentlyContinue))
}

function Invoke-Safely {
    <#
        Runs a scriptblock and swallows terminating errors so one bad API call never
        kills the whole run. Returns $null on failure and writes the reason to verbose.
    #>
    param(
        [Parameter(Mandatory)][scriptblock] $Script,
        [string] $Label = 'operation'
    )
    try {
        return & $Script
    }
    catch {
        Write-Verbose ('{0} failed: {1}' -f $Label, $_.Exception.Message)
        Write-Step -Message ('{0} failed: {1}' -f $Label, $_.Exception.Message) -State 'Warn'
        return $null
    }
}

function Invoke-GraphGet {
    <# GET against Microsoft Graph with automatic @odata.nextLink paging. #>
    param(
        [Parameter(Mandatory)][string] $Uri,
        [int] $MaxPages = 25
    )
    if ($Uri -notmatch '^https?://') {
        $Uri = '{0}/{1}' -f $script:Ep.Graph, $Uri.TrimStart('/')
    }

    $items = [System.Collections.Generic.List[object]]::new()
    $next  = $Uri
    $page  = 0

    while ($next -and $page -lt $MaxPages) {
        $page++
        $response = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType PSObject -ErrorAction Stop
        if ($null -eq $response) { break }

        if ($response.PSObject.Properties.Name -contains 'value') {
            foreach ($item in $response.value) { $items.Add($item) }
            $next = $response.'@odata.nextLink'
        }
        else {
            $items.Add($response)
            $next = $null
        }
    }
    return $items
}

function Get-PropertyValue {
    <# Null-safe property read that works for PSObject and hashtable payloads. #>
    param($InputObject, [Parameter(Mandatory)][string] $Name)

    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) { return $InputObject[$Name] }
        return $null
    }
    $prop = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $prop) { return $null }
    return $prop.Value
}

#endregion

# =====================================================================================
# REGION: Connection management
# =====================================================================================
#region Connections

function Test-ParameterSupported {
    <#
        Returns $true if a cmdlet exposes a named parameter in the version of the
        module currently installed.

        -DisableWAM was introduced alongside the WAM integration. Older module versions
        do not have it, and splatting an unknown parameter is a terminating error - so
        it must be probed rather than assumed.
    #>
    param(
        [Parameter(Mandatory)][string] $CommandName,
        [Parameter(Mandatory)][string] $ParameterName
    )

    $command = Get-Command -Name $CommandName -ErrorAction SilentlyContinue
    if ($null -eq $command) { return $false }

    return $command.Parameters.ContainsKey($ParameterName)
}

function Connect-ExchangeWorkloadWithFallback {
    <#
        Connects to Exchange Online or Security & Compliance PowerShell, working
        through progressively more compatible authentication methods.

        Returns $true on success, $false if every attempt failed.

        Background: from ExchangeOnlineManagement 3.7.0 the Web Account Manager (WAM)
        broker is the default. In some environments it cannot be constructed and fails
        with a NullReferenceException at RuntimeBroker..ctor before any network call is
        made. Az and Graph are unaffected because they do not use this broker.

        $BaseParameters carries the connection parameters the caller already determined
        (ConnectionUri, ExchangeEnvironmentName, ShowBanner, etc.). This function only
        layers authentication behaviour on top.
    #>
    param(
        [Parameter(Mandatory)][string] $CommandName,
        [Parameter(Mandatory)][string] $Label,
        [hashtable] $BaseParameters = @{}
    )

    $supportsDisableWam = Test-ParameterSupported -CommandName $CommandName -ParameterName 'DisableWAM'

    # Build the ordered list of attempts for this connection.
    $attempts = [System.Collections.Generic.List[object]]::new()

    if (-not $DisableWam) {
        $attempts.Add(@{ Description = 'standard authentication'; Extra = @{} })
    }

    if ($supportsDisableWam) {
        $attempts.Add(@{ Description = 'WAM disabled'; Extra = @{ DisableWAM = $true } })
    }

    if ($ExchangeCredential) {
        $attempts.Add(@{ Description = 'supplied credentials'; Extra = @{ Credential = $ExchangeCredential } })
    }

    if ($attempts.Count -eq 0) {
        # -DisableWam was requested but this module version has no such switch.
        $attempts.Add(@{ Description = 'standard authentication'; Extra = @{} })
        Write-Step -Message ('{0}: installed module does not support -DisableWAM. Update the module or use -ExchangeCredential.' -f $Label) -State 'Warn'
    }

    $attemptNumber = 0

    foreach ($attempt in $attempts) {
        $attemptNumber++

        $parameters = $BaseParameters.Clone()
        foreach ($key in $attempt.Extra.Keys) {
            $parameters[$key] = $attempt.Extra[$key]
        }

        Write-Step -Message ('{0}: attempt {1} of {2} - {3}' -f $Label, $attemptNumber, $attempts.Count, $attempt.Description) -State 'Info'

        $succeeded = $false
        try {
            & $CommandName @parameters -ErrorAction Stop
            $succeeded = $true
        }
        catch {
            $message = $_.Exception.Message

            # Recognise the broker failure specifically so the guidance is useful
            # rather than a generic "it didn't work".
            if ($message -match 'RuntimeBroker|window handle|Object reference not set') {
                Write-Step -Message ('{0}: authentication broker failed ({1})' -f $Label, $message) -State 'Warn'
            }
            else {
                Write-Step -Message ('{0}: {1}' -f $Label, $message) -State 'Warn'
            }
        }

        if ($succeeded) {
            Write-Step -Message ('{0} connected using {1}.' -f $Label, $attempt.Description) -State 'Done'
            return $true
        }
    }

    # Everything failed - print the practical next steps once, here.
    Write-Step -Message ('{0}: all authentication attempts failed.' -f $Label) -State 'Fail'
    Write-Host ''
    Write-Host '   The Exchange authentication broker could not be initialised. Try, in order:' -ForegroundColor Yellow
    Write-Host '     1. Close this shell and re-run from a NON-ELEVATED PowerShell console,' -ForegroundColor Yellow
    Write-Host '        signed in as the same Windows user. This is the most common fix.' -ForegroundColor Yellow
    Write-Host '     2. Re-run with -DisableWam.' -ForegroundColor Yellow
    Write-Host '     3. Re-run with -ExchangeCredential (Get-Credential). Note that an' -ForegroundColor Yellow
    Write-Host '        MFA-enforced account generally cannot complete this path.' -ForegroundColor Yellow
    Write-Host '     4. If it still fails, the installed module version may be the issue.' -ForegroundColor Yellow
    Write-Host '        Check with: Get-InstalledModule ExchangeOnlineManagement' -ForegroundColor Yellow
    Write-Host ''

    return $false
}

function Connect-Workloads {
    <# Establishes the sessions needed for the requested modules. #>
    param([string[]] $Requested)

    $needAz    = $Requested -contains 'DefenderForCloud'
    $needGraph = @('Entra', 'DefenderForEndpoint', 'DefenderForIdentity', 'DefenderForCloudApps') |
                    Where-Object { $Requested -contains $_ }

    # Purview also needs Exchange Online: UnifiedAuditLogIngestionEnabled must be read
    # from EXO PowerShell, not from Security & Compliance PowerShell.
    $needExo = ($Requested -contains 'DefenderForOffice') -or ($Requested -contains 'Purview')
    $needScc = $Requested -contains 'Purview'

    if ($needAz) {
        Write-Step -Message 'Connecting to Azure (Az.Accounts)' -State 'Start'
        Invoke-Safely -Label 'Az connection' -Script {
            Import-Module Az.Accounts -ErrorAction Stop
            $context = Get-AzContext -ErrorAction SilentlyContinue
            if (-not $context -and -not $SkipConnect) {
                $params = @{ Environment = $script:Ep.AzEnv }
                if ($TenantId) { $params['Tenant'] = $TenantId }
                Connect-AzAccount @params -ErrorAction Stop | Out-Null
                $context = Get-AzContext
            }
            if ($context) {
                Write-Step -Message ('Azure context: {0}' -f $context.Account.Id) -State 'Done'
            }
        } | Out-Null
    }

    if ($needGraph) {
        Write-Step -Message 'Connecting to Microsoft Graph' -State 'Start'
        Invoke-Safely -Label 'Graph connection' -Script {
            Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
            $context = Get-MgContext -ErrorAction SilentlyContinue
            if (-not $context -and -not $SkipConnect) {
                # Entra checks add Policy.Read.AuthenticationMethod, RoleManagement.Read.Directory
                # and Directory.Read.All on top of the Defender scopes.
                $scopes = @(
                    'DeviceManagementConfiguration.Read.All'
                    'DeviceManagementManagedDevices.Read.All'
                    'SecurityIdentitiesHealth.Read.All'
                    'SecurityIdentitiesSensors.Read.All'
                    'Policy.Read.All'
                    'Policy.Read.AuthenticationMethod'
                    'RoleManagement.Read.Directory'
                    'Directory.Read.All'
                    'CloudApp-Discovery.Read.All'
                )
                $params = @{ Scopes = $scopes; Environment = $script:Ep.GraphEnv; NoWelcome = $true }
                if ($TenantId) { $params['TenantId'] = $TenantId }
                Connect-MgGraph @params -ErrorAction Stop
                $context = Get-MgContext
            }
            if ($context) {
                $script:TenantLabel = $context.TenantId
                Write-Step -Message ('Graph context: {0}' -f $context.Account) -State 'Done'
            }
        } | Out-Null
    }

    if ($needExo) {
        Write-Step -Message 'Connecting to Exchange Online' -State 'Start'
        Invoke-Safely -Label 'Exchange Online connection' -Script {
            Import-Module ExchangeOnlineManagement -ErrorAction Stop

            $existing = Get-ConnectionInformation -ErrorAction SilentlyContinue
            if ($existing) {
                Write-Step -Message 'Exchange Online session already present.' -State 'Done'
                return
            }

            if ($SkipConnect) { return }

            $exoParams = @{
                ShowBanner              = $false
                ExchangeEnvironmentName = $script:Ep.ExoEnv
            }

            Connect-ExchangeWorkloadWithFallback `
                -CommandName 'Connect-ExchangeOnline' `
                -Label 'Exchange Online' `
                -BaseParameters $exoParams | Out-Null
        } | Out-Null
    }

    if ($needScc) {
        Write-Step -Message 'Connecting to Security & Compliance PowerShell (Purview)' -State 'Start'
        Invoke-Safely -Label 'Security & Compliance connection' -Script {
            Import-Module ExchangeOnlineManagement -ErrorAction Stop

            # Connect-IPPSSession has no reliable "already connected" probe, so test for
            # a Purview-only cmdlet instead. If it answers, a session already exists.
            if (Get-Command -Name 'Get-DlpCompliancePolicy' -ErrorAction SilentlyContinue) {
                Write-Step -Message 'Security & Compliance session already present.' -State 'Done'
                return
            }

            if ($SkipConnect) { return }

            $sccParams = @{}
            switch ($Cloud) {
                'USGov'    { $sccParams['ConnectionUri'] = 'https://ps.compliance.protection.office365.us/powershell-liveid/' }
                'USGovDoD' { $sccParams['ConnectionUri'] = 'https://l5.ps.compliance.protection.office365.us/powershell-liveid/' }
            }

            Connect-ExchangeWorkloadWithFallback `
                -CommandName 'Connect-IPPSSession' `
                -Label 'Security & Compliance' `
                -BaseParameters $sccParams | Out-Null
        } | Out-Null
    }
}

function Get-ArmToken {
    <# Bearer token for ARM, used by Invoke-AzRestMethod fallbacks. #>
    Invoke-Safely -Label 'ARM token' -Script {
        (Get-AzAccessToken -ResourceUrl $script:Ep.Arm -ErrorAction Stop).Token
    }
}

function Get-MdeToken {
    <#
        Delegated token for the Defender for Endpoint API, obtained through the existing
        Az sign-in. Requires the signed-in user to hold an MDE read role.

        Handles both token shapes: plain string (Az.Accounts before 5.0.0) and
        SecureString (Az.Accounts 5.0.0 / Az 14.0.0 and later).
    #>
    Invoke-Safely -Label 'Defender for Endpoint token' -Script {
        $token = Get-AzAccessToken -ResourceUrl $script:Ep.Mde -ErrorAction Stop
        if ($token.Token -is [System.Security.SecureString]) {
            return [System.Net.NetworkCredential]::new('', $token.Token).Password
        }
        return $token.Token
    }
}

#endregion

# =====================================================================================
# REGION: MODULE 1 - Microsoft Entra ID
# =====================================================================================
#region Entra

<#
    Privileged roles are matched by displayName against the role definitions Graph
    returns, rather than by hardcoded role template GUID. Template IDs are stable but
    trivially easy to transcribe wrongly, and a wrong GUID silently reports "no admins
    hold this role" - a false Green, which is the worst possible failure mode for a
    security baseline. Matching on name means an unmatched role simply does not appear,
    and the roles that do match are provably real.
#>
$script:EntraPrivilegedRoles = @(
    'Global Administrator'
    'Privileged Role Administrator'
    'Privileged Authentication Administrator'
    'Security Administrator'
    'Conditional Access Administrator'
    'Application Administrator'
    'Cloud Application Administrator'
    'Exchange Administrator'
    'SharePoint Administrator'
    'User Administrator'
    'Authentication Administrator'
    'Helpdesk Administrator'
    'Intune Administrator'
    'Billing Administrator'
)

<#
    Authentication methods, split by strength.

    Phishing-resistant methods should be enabled. SMS and Voice are legitimate methods
    but are phishable and interceptable, so they are graded Yellow when enabled rather
    than Red - they are a weaker fallback, not a misconfiguration.
#>
$script:EntraStrongAuthMethods = @(
    @{ Id = 'Fido2';                  Name = 'FIDO2 security keys' }
    @{ Id = 'MicrosoftAuthenticator'; Name = 'Microsoft Authenticator' }
    @{ Id = 'X509Certificate';        Name = 'Certificate-based authentication' }
    @{ Id = 'TemporaryAccessPass';    Name = 'Temporary Access Pass' }
)

$script:EntraWeakAuthMethods = @(
    @{ Id = 'Sms';   Name = 'SMS' }
    @{ Id = 'Voice'; Name = 'Voice call' }
    @{ Id = 'Email'; Name = 'Email OTP' }
)

function Invoke-EntraChecks {
    $product = 'Microsoft Entra ID'
    Write-Step -Message 'START Microsoft Entra ID assessment' -State 'Start'

    if (-not (Get-MgContext -ErrorAction SilentlyContinue)) {
        Add-ModuleFailure -Product $product -Reason 'No Microsoft Graph context available' `
            -Recommendation 'Run Connect-MgGraph with Policy.Read.All, RoleManagement.Read.Directory and Directory.Read.All, then re-run.'
        return
    }

    Test-EntraSecurityDefaults    -Product $product
    Test-EntraConditionalAccess   -Product $product
    Test-EntraAuthMethods         -Product $product
    Test-EntraPrivilegedRoles     -Product $product
    Test-EntraAuthorizationPolicy -Product $product

    Write-Step -Message 'END Microsoft Entra ID assessment' -State 'Done'
}

function Test-EntraSecurityDefaults {
    <#
        Security defaults and Conditional Access are mutually exclusive. Which one is
        "correct" depends on licensing, so this check grades the combination rather
        than either setting in isolation:

          CA policies enabled, security defaults off  -> Green (the mature posture)
          Security defaults on, no CA                 -> Green (correct without P1)
          Neither                                     -> Red   (tenant is unprotected)
    #>
    param([string] $Product)

    $defaults = Invoke-Safely -Label 'security defaults policy' -Script {
        Invoke-GraphGet -Uri '/v1.0/policies/identitySecurityDefaultsEnforcementPolicy'
    }

    if ($null -eq $defaults -or @($defaults).Count -eq 0) {
        Add-Result -Product $Product -Category 'Baseline protection' -Setting 'Security defaults / Conditional Access baseline' `
            -Status 'Gray' -Current 'Could not read identitySecurityDefaultsEnforcementPolicy' `
            -Expected 'Conditional Access policies enabled, or security defaults on' `
            -Recommendation 'Grant Policy.Read.All.'
        return
    }

    $isEnabled = Get-PropertyValue @($defaults)[0] 'isEnabled'

    $caPolicies = Invoke-Safely -Label 'Conditional Access policies (baseline)' -Script {
        Invoke-GraphGet -Uri '/v1.0/identity/conditionalAccess/policies'
    }

    $caEnabled = 0
    if ($null -ne $caPolicies) {
        $caEnabled = @($caPolicies | Where-Object { $_.state -eq 'enabled' }).Count
    }

    if ($caEnabled -gt 0 -and $isEnabled -ne $true) {
        $state   = 'Green'
        $current = ('Conditional Access in use ({0} enabled policies); security defaults off' -f $caEnabled)
        $rec     = 'No action required. Conditional Access supersedes security defaults.'
    }
    elseif ($isEnabled -eq $true -and $caEnabled -eq 0) {
        $state   = 'Green'
        $current = 'Security defaults enabled; no Conditional Access policies'
        $rec     = 'Correct for tenants without Entra ID P1. If you hold P1, move to Conditional Access for granular control.'
    }
    elseif ($isEnabled -eq $true -and $caEnabled -gt 0) {
        $state   = 'Yellow'
        $current = ('Security defaults enabled AND {0} enabled CA policies' -f $caEnabled)
        $rec     = 'These are mutually exclusive - CA policies do not take effect while security defaults are on. Disable security defaults.'
    }
    else {
        $state   = 'Red'
        $current = 'Security defaults off and no enabled Conditional Access policies'
        $rec     = 'The tenant has no baseline identity protection. Enable security defaults, or build Conditional Access policies covering MFA and legacy auth.'
    }

    Add-Result -Product $Product -Category 'Baseline protection' -Setting 'Security defaults / Conditional Access baseline' `
        -Status $state -Current $current `
        -Expected 'Conditional Access policies enabled, or security defaults on' -Recommendation $rec
}

function Test-EntraConditionalAccess {
    <#
        Grades the Conditional Access estate against the policies every tenant should
        have. Each pattern is detected structurally (grant controls, client app types,
        risk levels) rather than by policy name, because names are arbitrary.
    #>
    param([string] $Product)

    $policies = Invoke-Safely -Label 'Conditional Access policies' -Script {
        Invoke-GraphGet -Uri '/v1.0/identity/conditionalAccess/policies'
    }

    if ($null -eq $policies) {
        Add-Result -Product $Product -Category 'Conditional Access' -Setting 'Conditional Access policy inventory' `
            -Status 'Gray' -Current 'Could not read Conditional Access policies' `
            -Expected 'Core policies enabled' -Recommendation 'Grant Policy.Read.All.'
        return
    }

    $total = @($policies).Count

    if ($total -eq 0) {
        Add-Result -Product $Product -Category 'Conditional Access' -Setting 'Conditional Access policy inventory' `
            -Status 'Red' -Current 'No Conditional Access policies configured' `
            -Expected 'Core policies enabled' `
            -Recommendation 'Build the baseline set: MFA for admins, MFA for all users, block legacy authentication, and require compliant or hybrid-joined devices.'
        return
    }

    Write-Step -Message ('Found {0} Conditional Access policies' -f $total) -State 'Info'

    $enabled    = @($policies | Where-Object { $_.state -eq 'enabled' })
    $reportOnly = @($policies | Where-Object { $_.state -eq 'enabledForReportingButNotEnforced' }).Count

    Add-Result -Product $Product -Category 'Conditional Access' -Setting 'Conditional Access policy inventory' `
        -Status (Get-CoverageState -Compliant $enabled.Count -Total $total) `
        -Current ('{0} of {1} policies enabled, {2} report-only' -f $enabled.Count, $total, $reportOnly) `
        -Expected 'Core policies enabled, not left in report-only' `
        -Recommendation 'Report-only policies generate signal but block nothing. Promote validated policies to enabled.'

    # ---- Helper predicates over the policy graph ----
    # Each returns the count of ENABLED policies matching the pattern, plus the count
    # sitting in report-only, so a half-finished rollout grades Yellow rather than Red.
    function Measure-CaPattern {
        param([scriptblock] $Predicate)

        $matched     = @($policies | Where-Object { & $Predicate $_ })
        $matchedOn   = @($matched | Where-Object { $_.state -eq 'enabled' }).Count
        $matchedTest = @($matched | Where-Object { $_.state -eq 'enabledForReportingButNotEnforced' }).Count
        return @{ Enabled = $matchedOn; ReportOnly = $matchedTest }
    }

    function Add-CaPatternResult {
        param(
            [string] $Setting,
            [hashtable] $Counts,
            [string] $Expected,
            [string] $Recommendation
        )

        if ($Counts.Enabled -gt 0) {
            $state   = 'Green'
            $current = ('{0} enabled policy(ies) match' -f $Counts.Enabled)
        }
        elseif ($Counts.ReportOnly -gt 0) {
            $state   = 'Yellow'
            $current = ('{0} matching policy(ies), all report-only' -f $Counts.ReportOnly)
        }
        else {
            $state   = 'Red'
            $current = 'No matching policy found'
        }

        Add-Result -Product $Product -Category 'Conditional Access' -Setting $Setting `
            -Status $state -Current $current -Expected $Expected -Recommendation $Recommendation
    }

    # MFA for administrators - a policy granting MFA scoped to directory roles.
    $adminMfa = Measure-CaPattern {
        param($p)
        $grant = Get-PropertyValue (Get-PropertyValue $p 'grantControls') 'builtInControls'
        $roles = Get-PropertyValue (Get-PropertyValue (Get-PropertyValue $p 'conditions') 'users') 'includeRoles'
        ($grant -contains 'mfa') -and ($null -ne $roles) -and (@($roles).Count -gt 0)
    }
    Add-CaPatternResult -Setting 'MFA required for administrators' -Counts $adminMfa `
        -Expected 'An enabled policy requiring MFA for directory roles' `
        -Recommendation 'Create a Conditional Access policy targeting privileged directory roles with a Require MFA grant. This is the single highest-value CA policy.'

    # MFA for all users.
    $allUserMfa = Measure-CaPattern {
        param($p)
        $grant = Get-PropertyValue (Get-PropertyValue $p 'grantControls') 'builtInControls'
        $users = Get-PropertyValue (Get-PropertyValue (Get-PropertyValue $p 'conditions') 'users') 'includeUsers'
        ($grant -contains 'mfa') -and ($users -contains 'All')
    }
    Add-CaPatternResult -Setting 'MFA required for all users' -Counts $allUserMfa `
        -Expected 'An enabled policy requiring MFA for all users' `
        -Recommendation 'Require MFA for all users, excluding only your break-glass accounts.'

    # Block legacy authentication - targets legacy client app types.
    $legacyAuth = Measure-CaPattern {
        param($p)
        $clientTypes = Get-PropertyValue (Get-PropertyValue $p 'conditions') 'clientAppTypes'
        $grant       = Get-PropertyValue (Get-PropertyValue $p 'grantControls') 'builtInControls'
        $hasLegacy   = ($clientTypes -contains 'exchangeActiveSync') -or ($clientTypes -contains 'other')
        $hasLegacy -and ($grant -contains 'block')
    }
    Add-CaPatternResult -Setting 'Legacy authentication blocked' -Counts $legacyAuth `
        -Expected 'An enabled policy blocking legacy authentication clients' `
        -Recommendation 'Legacy auth protocols cannot present MFA. Block exchangeActiveSync and other clients outright - this closes the most common password-spray path.'

    # Device compliance / hybrid join requirement.
    $deviceTrust = Measure-CaPattern {
        param($p)
        $grant = Get-PropertyValue (Get-PropertyValue $p 'grantControls') 'builtInControls'
        ($grant -contains 'compliantDevice') -or ($grant -contains 'domainJoinedDevice')
    }
    Add-CaPatternResult -Setting 'Compliant or hybrid-joined device required' -Counts $deviceTrust `
        -Expected 'An enabled policy requiring a compliant or hybrid-joined device' `
        -Recommendation 'Requiring device trust stops credential replay from unmanaged machines even when the password and MFA are both satisfied.'

    # Sign-in risk policy (Identity Protection, P2).
    $signInRisk = Measure-CaPattern {
        param($p)
        $levels = Get-PropertyValue (Get-PropertyValue $p 'conditions') 'signInRiskLevels'
        ($null -ne $levels) -and (@($levels).Count -gt 0)
    }
    Add-CaPatternResult -Setting 'Sign-in risk policy' -Counts $signInRisk `
        -Expected 'An enabled policy acting on sign-in risk' `
        -Recommendation 'Requires Entra ID P2. Challenge or block medium and high sign-in risk so token replay and impossible-travel are handled automatically.'

    # User risk policy.
    $userRisk = Measure-CaPattern {
        param($p)
        $levels = Get-PropertyValue (Get-PropertyValue $p 'conditions') 'userRiskLevels'
        ($null -ne $levels) -and (@($levels).Count -gt 0)
    }
    Add-CaPatternResult -Setting 'User risk policy' -Counts $userRisk `
        -Expected 'An enabled policy acting on user risk' `
        -Recommendation 'Requires Entra ID P2. Force a secure password change on high user risk so leaked-credential accounts self-remediate.'

    # Break-glass exclusions. At least one policy should exclude emergency accounts,
    # otherwise a bad CA policy can lock every administrator out of the tenant.
    $withExclusions = @($policies | Where-Object {
        $excluded = Get-PropertyValue (Get-PropertyValue (Get-PropertyValue $_ 'conditions') 'users') 'excludeUsers'
        ($null -ne $excluded) -and (@($excluded).Count -gt 0)
    }).Count

    $breakGlassState = 'Red'
    if ($withExclusions -gt 0) { $breakGlassState = 'Green' }

    Add-Result -Product $Product -Category 'Conditional Access' -Setting 'Break-glass account exclusions' `
        -Status $breakGlassState -Current ('{0} of {1} policies exclude specific users' -f $withExclusions, $total) `
        -Expected 'Emergency access accounts excluded from CA policies' `
        -Recommendation 'Maintain two cloud-only emergency access accounts excluded from all CA policies. Without them a misconfigured policy can lock you out of your own tenant.'
}

function Test-EntraAuthMethods {
    <# Which authentication methods are enabled, split by phishing resistance. #>
    param([string] $Product)

    # authenticationMethodConfigurations is automatically expanded on this GET.
    $policy = Invoke-Safely -Label 'authentication methods policy' -Script {
        Invoke-GraphGet -Uri '/v1.0/policies/authenticationMethodsPolicy'
    }

    if ($null -eq $policy -or @($policy).Count -eq 0) {
        Add-Result -Product $Product -Category 'Authentication methods' -Setting 'Authentication methods policy' `
            -Status 'Gray' -Current 'Could not read authenticationMethodsPolicy' `
            -Expected 'Phishing-resistant methods enabled' `
            -Recommendation 'Grant Policy.Read.AuthenticationMethod or Policy.Read.All. Global Reader or Authentication Policy Administrator is sufficient.'
        return
    }

    $configs = Get-PropertyValue @($policy)[0] 'authenticationMethodConfigurations'

    if ($null -eq $configs) {
        Add-Result -Product $Product -Category 'Authentication methods' -Setting 'Authentication methods policy' `
            -Status 'Gray' -Current 'Policy returned no method configurations' `
            -Expected 'Phishing-resistant methods enabled' `
            -Recommendation 'Review Entra admin center > Authentication methods > Policies.'
        return
    }

    $lookup = @{}
    foreach ($config in @($configs)) {
        $id = "$(Get-PropertyValue $config 'id')"
        if ($id) { $lookup[$id.ToLowerInvariant()] = "$(Get-PropertyValue $config 'state')" }
    }

    Write-Step -Message ('Retrieved {0} authentication method configurations' -f $lookup.Count) -State 'Info'

    # ---- Phishing-resistant / strong methods: should be enabled ----
    $strongEnabled = 0
    foreach ($method in $script:EntraStrongAuthMethods) {
        $key   = $method.Id.ToLowerInvariant()
        $state = $null
        if ($lookup.ContainsKey($key)) { $state = $lookup[$key] }

        if ($null -eq $state) {
            Add-Result -Product $Product -Category 'Authentication methods' -Setting ('Method: {0}' -f $method.Name) `
                -Status 'Gray' -Current 'Not present in the policy response' -Expected 'enabled' `
                -Recommendation 'This method may not be available in your cloud or licence tier. Review in the Entra admin center.'
            continue
        }

        $isOn = ($state -eq 'enabled')
        if ($isOn) { $strongEnabled++ }

        $methodState = 'Red'
        if ($isOn) { $methodState = 'Green' }

        Add-Result -Product $Product -Category 'Authentication methods' -Setting ('Method: {0}' -f $method.Name) `
            -Status $methodState -Current ("state = $state") -Expected 'enabled' `
            -Recommendation ('Enable {0} in Entra admin center > Authentication methods. Phishing-resistant methods are the goal state for privileged users.' -f $method.Name)
    }

    $phishResistantState = 'Red'
    if ($strongEnabled -ge 2)    { $phishResistantState = 'Green' }
    elseif ($strongEnabled -eq 1) { $phishResistantState = 'Yellow' }

    Add-Result -Product $Product -Category 'Authentication methods' -Setting 'Phishing-resistant method coverage' `
        -Status $phishResistantState -Current ('{0} strong method(s) enabled' -f $strongEnabled) `
        -Expected 'At least two strong methods enabled' `
        -Recommendation 'Enable FIDO2 and Microsoft Authenticator at minimum, so privileged users have a phishing-resistant primary and a usable backup.'

    # ---- Weak methods: legitimate but phishable, so Yellow when on ----
    foreach ($method in $script:EntraWeakAuthMethods) {
        $key   = $method.Id.ToLowerInvariant()
        $state = $null
        if ($lookup.ContainsKey($key)) { $state = $lookup[$key] }

        if ($null -eq $state) { continue }

        $weakState = 'Green'
        $weakRec   = ('{0} is disabled. No action required.' -f $method.Name)
        if ($state -eq 'enabled') {
            $weakState = 'Yellow'
            $weakRec   = ('{0} is enabled. It is interceptable and phishable - keep it as a fallback only, and exclude privileged users from it.' -f $method.Name)
        }

        Add-Result -Product $Product -Category 'Authentication methods' -Setting ('Weak method: {0}' -f $method.Name) `
            -Status $weakState -Current ("state = $state") -Expected 'disabled, or restricted to non-privileged users' `
            -Recommendation $weakRec
    }

    # ---- Registration campaign / enforcement ----
    $enforcement = Get-PropertyValue @($policy)[0] 'registrationEnforcement'
    $campaign    = Get-PropertyValue $enforcement 'authenticationMethodsRegistrationCampaign'
    $campaignState = Get-PropertyValue $campaign 'state'

    $regState = 'Gray'
    if ($campaignState -eq 'enabled')       { $regState = 'Green' }
    elseif ($campaignState -eq 'disabled')  { $regState = 'Yellow' }

    Add-Result -Product $Product -Category 'Authentication methods' -Setting 'Registration campaign' `
        -Status $regState -Current ("state = $campaignState") -Expected 'enabled' `
        -Recommendation 'Nudging users to register Microsoft Authenticator at sign-in migrates them off SMS without a helpdesk-driven project.'

    # ---- Policy migration state ----
    $migration = Get-PropertyValue @($policy)[0] 'policyMigrationState'

    $migrationState = 'Gray'
    if ($migration -eq 'migrationComplete')      { $migrationState = 'Green' }
    elseif ($migration -eq 'migrationInProgress') { $migrationState = 'Yellow' }
    elseif ($migration -eq 'premigration')        { $migrationState = 'Red' }

    Add-Result -Product $Product -Category 'Authentication methods' -Setting 'Authentication methods policy migration' `
        -Status $migrationState -Current ("policyMigrationState = $migration") -Expected 'migrationComplete' `
        -Recommendation 'Until migration completes, the legacy per-user MFA and SSPR policies still apply alongside the modern policy. Finish the migration so one policy governs both.'
}

function Test-EntraPrivilegedRoles {
    <#
        Standing privilege is the core identity risk: a permanently assigned Global
        Administrator is a permanently available target. This grades role assignment
        counts and, critically, the ratio of permanent to PIM-eligible assignments.
    #>
    param([string] $Product)

    $definitions = Invoke-Safely -Label 'role definitions' -Script {
        Invoke-GraphGet -Uri '/v1.0/roleManagement/directory/roleDefinitions'
    }

    if ($null -eq $definitions) {
        Add-Result -Product $Product -Category 'Privileged access' -Setting 'Privileged role assignments' `
            -Status 'Gray' -Current 'Could not read role definitions' `
            -Expected 'Few permanent admins, the rest PIM-eligible' `
            -Recommendation 'Grant RoleManagement.Read.Directory or Directory.Read.All.'
        return
    }

    # displayName -> id, and id -> displayName for reverse lookup.
    $roleIdByName = @{}
    $roleNameById = @{}
    foreach ($definition in @($definitions)) {
        $name = "$(Get-PropertyValue $definition 'displayName')"
        $id   = "$(Get-PropertyValue $definition 'id')"
        if ($name -and $id) {
            $roleIdByName[$name] = $id
            $roleNameById[$id]   = $name
        }
    }

    Write-Step -Message ('Retrieved {0} role definitions' -f $roleNameById.Count) -State 'Info'

    $assignments = Invoke-Safely -Label 'role assignments' -Script {
        Invoke-GraphGet -Uri '/v1.0/roleManagement/directory/roleAssignments'
    }

    if ($null -eq $assignments) {
        Add-Result -Product $Product -Category 'Privileged access' -Setting 'Privileged role assignments' `
            -Status 'Gray' -Current 'Could not read role assignments' `
            -Expected 'Few permanent admins, the rest PIM-eligible' `
            -Recommendation 'Grant RoleManagement.Read.Directory or Directory.Read.All.'
        return
    }

    # PIM eligibility. Absent PIM licensing this returns nothing or errors, which is
    # reported as Gray rather than Red - no PIM is a licensing state, not a misconfig.
    $eligible = Invoke-Safely -Label 'PIM eligibility schedules' -Script {
        Invoke-GraphGet -Uri '/v1.0/roleManagement/directory/roleEligibilitySchedules'
    }

    $permanentByRole = @{}
    foreach ($assignment in @($assignments)) {
        $roleId = "$(Get-PropertyValue $assignment 'roleDefinitionId')"
        if (-not $roleId) { continue }
        if (-not $permanentByRole.ContainsKey($roleId)) { $permanentByRole[$roleId] = 0 }
        $permanentByRole[$roleId]++
    }

    $eligibleByRole = @{}
    if ($null -ne $eligible) {
        foreach ($schedule in @($eligible)) {
            $roleId = "$(Get-PropertyValue $schedule 'roleDefinitionId')"
            if (-not $roleId) { continue }
            if (-not $eligibleByRole.ContainsKey($roleId)) { $eligibleByRole[$roleId] = 0 }
            $eligibleByRole[$roleId]++
        }
    }

    # ---- Global Administrator count ----
    # Microsoft's guidance is to keep this small. Too few is also a finding: with fewer
    # than two you have no break-glass path if the sole admin is locked out.
    $gaId = $roleIdByName['Global Administrator']
    if ($gaId) {
        $gaPermanent = 0
        if ($permanentByRole.ContainsKey($gaId)) { $gaPermanent = $permanentByRole[$gaId] }

        $gaEligible = 0
        if ($eligibleByRole.ContainsKey($gaId)) { $gaEligible = $eligibleByRole[$gaId] }

        if ($gaPermanent -ge 2 -and $gaPermanent -le 4) {
            $gaState = 'Green'
            $gaRec   = 'Count is in the recommended range. Confirm these are break-glass accounts and day-to-day admin runs through PIM.'
        }
        elseif ($gaPermanent -lt 2) {
            $gaState = 'Red'
            $gaRec   = 'Fewer than two permanent Global Administrators leaves no emergency access path. Maintain exactly two cloud-only break-glass accounts.'
        }
        elseif ($gaPermanent -le 8) {
            $gaState = 'Yellow'
            $gaRec   = 'More permanent Global Administrators than necessary. Move day-to-day admins to PIM-eligible and keep only break-glass accounts permanent.'
        }
        else {
            $gaState = 'Red'
            $gaRec   = 'Far too many standing Global Administrators. Each one is a permanent high-value target. Move them to PIM-eligible assignments.'
        }

        Add-Result -Product $Product -Category 'Privileged access' -Setting 'Global Administrator count' `
            -Status $gaState -Current ('{0} permanent, {1} PIM-eligible' -f $gaPermanent, $gaEligible) `
            -Expected '2-4 permanent (break-glass only), the rest PIM-eligible' -Recommendation $gaRec
    }

    # ---- Standing privilege across all privileged roles ----
    $totalPermanent = 0
    $totalEligible  = 0

    foreach ($roleName in $script:EntraPrivilegedRoles) {
        $roleId = $roleIdByName[$roleName]
        if (-not $roleId) { continue }

        $permanent = 0
        if ($permanentByRole.ContainsKey($roleId)) { $permanent = $permanentByRole[$roleId] }

        $eligibleCount = 0
        if ($eligibleByRole.ContainsKey($roleId)) { $eligibleCount = $eligibleByRole[$roleId] }

        $totalPermanent += $permanent
        $totalEligible  += $eligibleCount

        # Only report roles that are actually in use, to keep the table meaningful.
        if ($permanent -eq 0 -and $eligibleCount -eq 0) { continue }

        if ($permanent -eq 0 -and $eligibleCount -gt 0) {
            $roleState = 'Green'
            $roleRec   = 'All assignments are just-in-time. No action required.'
        }
        elseif ($eligibleCount -gt 0) {
            $roleState = 'Yellow'
            $roleRec   = 'Mixed model. Move the remaining permanent assignments to PIM-eligible unless they are documented break-glass accounts.'
        }
        else {
            $roleState = 'Red'
            $roleRec   = 'All assignments are permanent. Standing privilege in this role is available to an attacker at any hour without approval or justification.'
        }

        # Global Administrator is graded separately above; skip the duplicate row.
        if ($roleName -eq 'Global Administrator') { continue }

        Add-Result -Product $Product -Category 'Privileged role detail' -Setting ('Role: {0}' -f $roleName) `
            -Status $roleState -Current ('{0} permanent, {1} PIM-eligible' -f $permanent, $eligibleCount) `
            -Expected 'PIM-eligible rather than permanent' -Recommendation $roleRec
    }

    # ---- Overall PIM adoption ----
    if ($null -eq $eligible) {
        Add-Result -Product $Product -Category 'Privileged access' -Setting 'PIM adoption' `
            -Status 'Gray' -Current 'Could not read PIM eligibility schedules' `
            -Expected 'Most privileged assignments PIM-eligible' `
            -Recommendation 'PIM requires Entra ID P2. If you are licensed, grant RoleManagement.Read.Directory and re-run.'
    }
    else {
        $totalAssignments = $totalPermanent + $totalEligible

        if ($totalAssignments -eq 0) {
            $pimState   = 'Gray'
            $pimCurrent = 'No privileged assignments found'
            $pimRec     = 'No assignments were returned for the tracked privileged roles. Verify read permissions.'
        }
        elseif ($totalEligible -eq 0) {
            $pimState   = 'Red'
            $pimCurrent = ('{0} permanent assignments, 0 eligible' -f $totalPermanent)
            $pimRec     = 'No PIM usage at all. Every privileged assignment is standing. Onboard privileged roles into PIM and require approval plus justification on activation.'
        }
        elseif ($totalEligible -ge $totalPermanent) {
            $pimState   = 'Green'
            $pimCurrent = ('{0} eligible vs {1} permanent' -f $totalEligible, $totalPermanent)
            $pimRec     = 'Majority of privileged access is just-in-time. Confirm the remaining permanent assignments are break-glass only.'
        }
        else {
            $pimState   = 'Yellow'
            $pimCurrent = ('{0} eligible vs {1} permanent' -f $totalEligible, $totalPermanent)
            $pimRec     = 'PIM is in use but permanent assignments still outnumber eligible ones. Continue converting standing roles to just-in-time.'
        }

        Add-Result -Product $Product -Category 'Privileged access' -Setting 'PIM adoption' `
            -Status $pimState -Current $pimCurrent `
            -Expected 'Most privileged assignments PIM-eligible' -Recommendation $pimRec
    }
}

function Test-EntraAuthorizationPolicy {
    <#
        Default user permissions and guest access. These are the settings that quietly
        allow any user to register apps, invite guests, or create tenants - each of
        which is a lateral-movement or shadow-IT path.
    #>
    param([string] $Product)

    $policy = Invoke-Safely -Label 'authorization policy' -Script {
        Invoke-GraphGet -Uri '/v1.0/policies/authorizationPolicy'
    }

    if ($null -eq $policy -or @($policy).Count -eq 0) {
        Add-Result -Product $Product -Category 'User settings' -Setting 'Authorization policy' `
            -Status 'Gray' -Current 'Could not read authorizationPolicy' `
            -Expected 'Default user permissions restricted' `
            -Recommendation 'Grant Policy.Read.All.'
        return
    }

    $auth        = @($policy)[0]
    $permissions = Get-PropertyValue $auth 'defaultUserRolePermissions'

    # ---- Default user permissions ----
    $userPermissionChecks = @(
        @{
            Property = 'allowedToCreateApps'
            Label    = 'Users can register applications'
            Rec      = 'Set to No. App registration by standard users is a common consent-phishing and shadow-IT path.'
        }
        @{
            Property = 'allowedToCreateSecurityGroups'
            Label    = 'Users can create security groups'
            Rec      = 'Set to No unless self-service groups are a deliberate design decision. Security groups can grant access.'
        }
        @{
            Property = 'allowedToCreateTenants'
            Label    = 'Users can create tenants'
            Rec      = 'Set to No. A user-created tenant is completely outside your governance, monitoring and DLP.'
        }
        @{
            Property = 'allowedToReadOtherUsers'
            Label    = 'Users can read other users'
            Rec      = 'Usually left on for directory usability. Restrict only if you have a specific confidentiality requirement.'
        }
    )

    foreach ($check in $userPermissionChecks) {
        $value = Get-PropertyValue $permissions $check.Property

        if ($null -eq $value) {
            Add-Result -Product $Product -Category 'User settings' -Setting $check.Label `
                -Status 'Gray' -Current 'Property not returned' -Expected 'False' `
                -Recommendation 'Review in Entra admin center > Users > User settings.'
            continue
        }

        # allowedToReadOtherUsers being true is normal and expected, so it is not
        # graded as a failure - it is informational and reported Green either way.
        if ($check.Property -eq 'allowedToReadOtherUsers') {
            Add-Result -Product $Product -Category 'User settings' -Setting $check.Label `
                -Status 'Green' -Current ("$value") -Expected 'True (default) unless restricted by design' `
                -Recommendation $check.Rec
            continue
        }

        Add-Result -Product $Product -Category 'User settings' -Setting $check.Label `
            -Status (Get-BoolState $value -InvertGood) -Current ("$value") -Expected 'False' `
            -Recommendation $check.Rec
    }

    # ---- Legacy MSOnline PowerShell ----
    $blockMsol = Get-PropertyValue $auth 'blockMsolPowerShell'
    Add-Result -Product $Product -Category 'User settings' -Setting 'Legacy MSOnline PowerShell blocked' `
        -Status (Get-BoolState $blockMsol) -Current ("blockMsolPowerShell = $blockMsol") -Expected 'True' `
        -Recommendation 'Block the deprecated MSOnline module. It supports legacy authentication patterns and bypasses modern controls.'

    # ---- Self-service sign-up ----
    $emailJoin = Get-PropertyValue $auth 'allowEmailVerifiedUsersToJoinOrganization'
    Add-Result -Product $Product -Category 'User settings' -Setting 'Email-verified users can join the tenant' `
        -Status (Get-BoolState $emailJoin -InvertGood) -Current ("allowEmailVerifiedUsersToJoinOrganization = $emailJoin") `
        -Expected 'False' `
        -Recommendation 'Set to False. Otherwise anyone who can verify an email address in a matching domain can self-provision an account.'

    # ---- Guest invitation restrictions ----
    $allowInvitesFrom = "$(Get-PropertyValue $auth 'allowInvitesFrom')"

    switch -Regex ($allowInvitesFrom) {
        '^(?i)none$' {
            $inviteState = 'Green'
            $inviteRec   = 'Guest invitations are blocked entirely. No action required.'
        }
        '^(?i)adminsAndGuestInviters$' {
            $inviteState = 'Green'
            $inviteRec   = 'Only admins and designated inviters can invite guests. This is the recommended setting.'
        }
        '^(?i)adminsGuestInvitersAndAllMembers$' {
            $inviteState = 'Yellow'
            $inviteRec   = 'All members can invite guests. Acceptable for collaboration-heavy tenants, but it removes any gate on external access.'
        }
        '^(?i)everyone$' {
            $inviteState = 'Red'
            $inviteRec   = 'Existing guests can invite further guests. Restrict to adminsAndGuestInviters so external access stays governed.'
        }
        default {
            $inviteState = 'Gray'
            $inviteRec   = 'Value not recognised. Review in Entra admin center > External Identities > External collaboration settings.'
        }
    }

    Add-Result -Product $Product -Category 'External access' -Setting 'Who can invite guests' `
        -Status $inviteState -Current ("allowInvitesFrom = $allowInvitesFrom") `
        -Expected 'adminsAndGuestInviters (or none)' -Recommendation $inviteRec

    # ---- Guest permission level ----
    # These three template IDs are the documented guest role options. An unrecognised
    # value reports Gray rather than being guessed at.
    $guestRoleId = "$(Get-PropertyValue $auth 'guestUserRoleId')"

    $guestRoles = @{
        '2af84b1e-32c8-42b7-82bc-daa82404023b' = @{ Name = 'Restricted Guest'; State = 'Green';  Rec = 'Most restrictive guest access. No action required.' }
        '10dae51f-b6af-4016-8d66-8c2a99b929b3' = @{ Name = 'Guest User';       State = 'Yellow'; Rec = 'Default guest access. Consider Restricted Guest, which blocks directory enumeration by external users.' }
        'a0b1b346-4d3e-4e8b-98f8-753987be4970' = @{ Name = 'Same as member';   State = 'Red';    Rec = 'Guests have the same directory permissions as employees. Change this to Restricted Guest.' }
    }

    if ($guestRoles.ContainsKey($guestRoleId)) {
        $guest = $guestRoles[$guestRoleId]
        Add-Result -Product $Product -Category 'External access' -Setting 'Guest user permission level' `
            -Status $guest.State -Current $guest.Name -Expected 'Restricted Guest' -Recommendation $guest.Rec
    }
    else {
        Add-Result -Product $Product -Category 'External access' -Setting 'Guest user permission level' `
            -Status 'Gray' -Current ("guestUserRoleId = $guestRoleId") -Expected 'Restricted Guest' `
            -Recommendation 'Guest role ID not recognised. Review in Entra admin center > External Identities > External collaboration settings.'
    }

    # ---- User consent to applications ----
    $grantPolicies = Get-PropertyValue $permissions 'permissionGrantPoliciesAssigned'
    $grantText     = (@($grantPolicies) -join ';')

    if ([string]::IsNullOrWhiteSpace($grantText)) {
        $consentState = 'Green'
        $consentRec   = 'Users cannot consent to applications. Admin consent is required throughout.'
        $consentText  = 'No user consent policy assigned (consent disabled)'
    }
    elseif ($grantText -match '(?i)legacy') {
        $consentState = 'Red'
        $consentRec   = 'The legacy consent policy lets users consent to any app requesting any non-admin permission. Move to the low-risk permission set, or require admin consent.'
        $consentText  = $grantText
    }
    elseif ($grantText -match '(?i)low') {
        $consentState = 'Green'
        $consentRec   = 'Users can consent only to low-risk permissions from verified publishers. This is the recommended setting.'
        $consentText  = $grantText
    }
    else {
        $consentState = 'Yellow'
        $consentRec   = 'A custom consent policy is in force. Confirm it limits consent to low-risk permissions from verified publishers.'
        $consentText  = $grantText
    }

    Add-Result -Product $Product -Category 'Application governance' -Setting 'User consent to applications' `
        -Status $consentState -Current $consentText `
        -Expected 'Low-risk permissions only, or admin consent required' -Recommendation $consentRec

    # ---- Admin consent workflow ----
    # If user consent is restricted but there is no request workflow, users have no
    # sanctioned route and will work around the control.
    $consentPolicy = Invoke-Safely -Label 'admin consent request policy' -Script {
        Invoke-GraphGet -Uri '/v1.0/policies/adminConsentRequestPolicy'
    }

    if ($null -eq $consentPolicy -or @($consentPolicy).Count -eq 0) {
        Add-Result -Product $Product -Category 'Application governance' -Setting 'Admin consent request workflow' `
            -Status 'Gray' -Current 'Could not read adminConsentRequestPolicy' -Expected 'Enabled' `
            -Recommendation 'Grant Policy.Read.All.'
        return
    }

    $consentWorkflow = Get-PropertyValue @($consentPolicy)[0] 'isEnabled'

    Add-Result -Product $Product -Category 'Application governance' -Setting 'Admin consent request workflow' `
        -Status (Get-BoolState $consentWorkflow) -Current ("isEnabled = $consentWorkflow") -Expected 'True' `
        -Recommendation 'Enable the admin consent workflow so users have a sanctioned path to request app access instead of finding workarounds.'
}

#endregion

# =====================================================================================
# REGION: MODULE 2 - Microsoft Defender for Cloud
# =====================================================================================
#region Defender for Cloud

# Plans that should be on for a well-covered subscription.
$script:MdcExpectedPlans = @(
    'CloudPosture', 'VirtualMachines', 'StorageAccounts', 'SqlServers',
    'SqlServerVirtualMachines', 'KeyVaults', 'Dns', 'Arm', 'Containers',
    'OpenSourceRelationalDatabases', 'CosmosDbs', 'AppServices', 'Api'
)

function Invoke-DefenderForCloudChecks {
    $product = 'Defender for Cloud'
    Write-Step -Message 'START Defender for Cloud assessment' -State 'Start'

    $context = Invoke-Safely -Label 'Get-AzContext' -Script { Get-AzContext -ErrorAction Stop }
    if (-not $context) {
        Add-ModuleFailure -Product $product -Reason 'No Azure context available' `
            -Recommendation 'Run Connect-AzAccount, or install Az.Accounts, then re-run without -SkipConnect.'
        return
    }

    $subs = @()
    if ($SubscriptionId) {
        $subs = $SubscriptionId
    }
    else {
        $found = Invoke-Safely -Label 'Get-AzSubscription' -Script {
            Get-AzSubscription -ErrorAction Stop | Where-Object { $_.State -eq 'Enabled' }
        }
        if ($found) { $subs = $found.Id }
    }

    if (-not $subs -or $subs.Count -eq 0) {
        Add-ModuleFailure -Product $product -Reason 'No enabled subscriptions visible to this account' `
            -Recommendation 'Grant Reader or Security Reader on the target subscriptions, or pass -SubscriptionId explicitly.'
        return
    }

    Write-Step -Message ('Assessing {0} subscription(s)' -f $subs.Count) -State 'Info'

    foreach ($sub in $subs) {
        $scopeLabel = "Subscription $sub"
        Invoke-Safely -Label "Set context $sub" -Script { Set-AzContext -Subscription $sub -ErrorAction Stop | Out-Null } | Out-Null

        Test-MdcPricingPlans     -Subscription $sub -Scope $scopeLabel -Product $product
        Test-MdcSecurityContacts -Subscription $sub -Scope $scopeLabel -Product $product
        Test-MdcIntegrations     -Subscription $sub -Scope $scopeLabel -Product $product
        Test-MdcAutoProvision    -Subscription $sub -Scope $scopeLabel -Product $product
        Test-MdcSecureScore      -Subscription $sub -Scope $scopeLabel -Product $product
    }

    Write-Step -Message 'END Defender for Cloud assessment' -State 'Done'
}

function Test-MdcPricingPlans {
    <# Reads Microsoft.Security/pricings and grades each Defender plan. #>
    param([string] $Subscription, [string] $Scope, [string] $Product)

    $uri = "/subscriptions/$Subscription/providers/Microsoft.Security/pricings?api-version=2024-01-01"
    $raw = Invoke-Safely -Label 'MDC pricings' -Script {
        $response = Invoke-AzRestMethod -Method GET -Path $uri -ErrorAction Stop
        if ($response.StatusCode -ne 200) { throw "HTTP $($response.StatusCode): $($response.Content)" }
        ($response.Content | ConvertFrom-Json).value
    }

    if (-not $raw) {
        Add-Result -Product $Product -Category 'Defender plans' -Setting 'Plan enablement' -Scope $Scope `
            -Status 'Gray' -Current 'Could not read Microsoft.Security/pricings' `
            -Expected 'All relevant plans on Standard' `
            -Recommendation 'Confirm the account has Security Reader or Reader on this subscription.'
        return
    }

    $planLookup = @{}
    foreach ($plan in $raw) { $planLookup[$plan.name] = $plan }

    foreach ($expected in $script:MdcExpectedPlans) {
        $plan = $planLookup[$expected]

        if (-not $plan) {
            Add-Result -Product $Product -Category 'Defender plans' -Setting ('Plan: {0}' -f $expected) -Scope $Scope `
                -Status 'Red' -Current 'Not present / not configured' -Expected 'Standard' `
                -Recommendation ('Enable the {0} plan in Defender for Cloud > Environment settings.' -f $expected)
            continue
        }

        $tier    = Get-PropertyValue $plan.properties 'pricingTier'
        $subPlan = Get-PropertyValue $plan.properties 'subPlan'

        if ($tier -eq 'Standard') {
            # Servers P1 is partial coverage compared with P2.
            if ($expected -eq 'VirtualMachines' -and $subPlan -eq 'P1') {
                Add-Result -Product $Product -Category 'Defender plans' -Setting 'Plan: VirtualMachines (Servers)' -Scope $Scope `
                    -Status 'Yellow' -Current 'Standard - Plan 1' -Expected 'Standard - Plan 2' `
                    -Recommendation 'Plan 1 covers MDE onboarding only. Plan 2 adds file integrity monitoring, agentless scanning and JIT.'
            }
            else {
                $current = 'Standard'
                if ($subPlan) { $current = "Standard ($subPlan)" }

                Add-Result -Product $Product -Category 'Defender plans' -Setting ('Plan: {0}' -f $expected) -Scope $Scope `
                    -Status 'Green' -Current $current -Expected 'Standard' `
                    -Recommendation 'No action required.'
            }
        }
        else {
            Add-Result -Product $Product -Category 'Defender plans' -Setting ('Plan: {0}' -f $expected) -Scope $Scope `
                -Status 'Red' -Current ("$tier") -Expected 'Standard' `
                -Recommendation ('Turn on the {0} plan in Defender for Cloud > Environment settings > Defender plans.' -f $expected)
        }

        # Defender CSPM extensions (agentless scanning, sensitive data discovery, etc.)
        if ($expected -eq 'CloudPosture') {
            $extensions = Get-PropertyValue $plan.properties 'extensions'
            if ($extensions) {
                foreach ($ext in $extensions) {
                    $extEnabled = Get-PropertyValue $ext 'isEnabled'
                    $state      = Get-BoolState $extEnabled

                    Add-Result -Product $Product -Category 'Defender CSPM extensions' `
                        -Setting ('Extension: {0}' -f (Get-PropertyValue $ext 'name')) -Scope $Scope `
                        -Status $state -Current ("Enabled = $extEnabled") -Expected 'Enabled' `
                        -Recommendation 'Enable the extension under Defender CSPM plan settings for full posture coverage.'
                }
            }
        }
    }
}

function Test-MdcSecurityContacts {
    <# Security contacts drive alert email notification. No contact = no one gets told. #>
    param([string] $Subscription, [string] $Scope, [string] $Product)

    $uri = "/subscriptions/$Subscription/providers/Microsoft.Security/securityContacts?api-version=2023-12-01-preview"
    $contacts = Invoke-Safely -Label 'MDC security contacts' -Script {
        $response = Invoke-AzRestMethod -Method GET -Path $uri -ErrorAction Stop
        if ($response.StatusCode -ne 200) { throw "HTTP $($response.StatusCode)" }
        ($response.Content | ConvertFrom-Json).value
    }

    if ($null -eq $contacts) {
        Add-Result -Product $Product -Category 'Notifications' -Setting 'Security contact configured' -Scope $Scope `
            -Status 'Gray' -Current 'Could not read security contacts' -Expected 'At least one contact with alert notifications on' `
            -Recommendation 'Check permissions on Microsoft.Security/securityContacts.'
        return
    }

    $withEmail = @($contacts | Where-Object { -not [string]::IsNullOrWhiteSpace((Get-PropertyValue $_.properties 'emails')) })

    if ($withEmail.Count -eq 0) {
        Add-Result -Product $Product -Category 'Notifications' -Setting 'Security contact configured' -Scope $Scope `
            -Status 'Red' -Current 'No security contact email set' -Expected 'Security contact email set' `
            -Recommendation 'Defender for Cloud > Environment settings > Email notifications - add a distribution list, not an individual.'
        return
    }

    Add-Result -Product $Product -Category 'Notifications' -Setting 'Security contact configured' -Scope $Scope `
        -Status 'Green' -Current ('{0} contact(s) with email' -f $withEmail.Count) -Expected 'At least one contact' `
        -Recommendation 'No action required.'

    foreach ($contact in $withEmail) {
        $alertNotifications = Get-PropertyValue $contact.properties 'alertNotifications'
        $notifyState        = Get-PropertyValue $alertNotifications 'state'
        $minimalSeverity    = Get-PropertyValue $alertNotifications 'minimalSeverity'

        if ($notifyState -ne 'On') {
            $status = 'Red'
            $rec    = 'Turn alert notifications On so email is actually delivered.'
        }
        elseif ($minimalSeverity -eq 'High') {
            $status = 'Yellow'
            $rec    = 'Only High severity alerts are emailed. Lower the threshold to Medium so escalating attacks are not missed.'
        }
        else {
            $status = 'Green'
            $rec    = 'No action required.'
        }

        Add-Result -Product $Product -Category 'Notifications' -Setting 'Alert notification severity' -Scope $Scope `
            -Status $status -Current ("State=$notifyState; MinimalSeverity=$minimalSeverity") `
            -Expected 'State=On; MinimalSeverity=Medium or Low' -Recommendation $rec
    }
}

function Test-MdcIntegrations {
    <# MDE, MDA and Sentinel integration toggles under Microsoft.Security/settings. #>
    param([string] $Subscription, [string] $Scope, [string] $Product)

    $uri = "/subscriptions/$Subscription/providers/Microsoft.Security/settings?api-version=2022-05-01"
    $settings = Invoke-Safely -Label 'MDC integration settings' -Script {
        $response = Invoke-AzRestMethod -Method GET -Path $uri -ErrorAction Stop
        if ($response.StatusCode -ne 200) { throw "HTTP $($response.StatusCode)" }
        ($response.Content | ConvertFrom-Json).value
    }

    if (-not $settings) {
        Add-Result -Product $Product -Category 'Integrations' -Setting 'Integration settings' -Scope $Scope `
            -Status 'Gray' -Current 'Could not read Microsoft.Security/settings' -Expected 'MDE and MDA integrations enabled' `
            -Recommendation 'Verify read permission on Microsoft.Security/settings.'
        return
    }

    $friendly = @{
        WDATP                              = 'Defender for Endpoint integration'
        WDATP_EXCLUDE_LINUX_PUBLIC_PREVIEW = 'MDE Linux onboarding'
        MCAS                               = 'Defender for Cloud Apps integration'
        Sentinel                           = 'Microsoft Sentinel integration'
    }

    foreach ($setting in $settings) {
        $name  = Get-PropertyValue $setting 'name'
        $label = $name
        if ($friendly.ContainsKey($name)) { $label = $friendly[$name] }

        $enabled = Get-PropertyValue $setting.properties 'enabled'
        $state   = Get-BoolState $enabled

        Add-Result -Product $Product -Category 'Integrations' -Setting $label -Scope $Scope `
            -Status $state -Current ("Enabled = $enabled") -Expected 'Enabled' `
            -Recommendation 'Enable under Defender for Cloud > Environment settings > Integrations so signals flow into the XDR portal.'
    }
}

function Test-MdcAutoProvision {
    <# Agent / extension auto-provisioning. Off means new resources land unmonitored. #>
    param([string] $Subscription, [string] $Scope, [string] $Product)

    $uri = "/subscriptions/$Subscription/providers/Microsoft.Security/autoProvisioningSettings?api-version=2017-08-01-preview"
    $settings = Invoke-Safely -Label 'MDC auto-provisioning' -Script {
        $response = Invoke-AzRestMethod -Method GET -Path $uri -ErrorAction Stop
        if ($response.StatusCode -ne 200) { throw "HTTP $($response.StatusCode)" }
        ($response.Content | ConvertFrom-Json).value
    }

    if (-not $settings) {
        Add-Result -Product $Product -Category 'Auto-provisioning' -Setting 'Agent auto-provisioning' -Scope $Scope `
            -Status 'Gray' -Current 'Could not read auto-provisioning settings' -Expected 'On' `
            -Recommendation 'Verify read permission on Microsoft.Security/autoProvisioningSettings.'
        return
    }

    foreach ($setting in $settings) {
        $autoProvision = Get-PropertyValue $setting.properties 'autoProvision'

        $state = 'Gray'
        if ($autoProvision -eq 'On')      { $state = 'Green' }
        elseif ($autoProvision -eq 'Off') { $state = 'Red' }

        Add-Result -Product $Product -Category 'Auto-provisioning' `
            -Setting ('Auto-provisioning: {0}' -f (Get-PropertyValue $setting 'name')) -Scope $Scope `
            -Status $state -Current ("$autoProvision") -Expected 'On' `
            -Recommendation 'Turn on auto-provisioning so newly created resources are monitored without manual onboarding.'
    }
}

function Test-MdcSecureScore {
    <# Overall secure score as a rolled-up posture indicator. #>
    param([string] $Subscription, [string] $Scope, [string] $Product)

    $uri = "/subscriptions/$Subscription/providers/Microsoft.Security/secureScores/ascScore?api-version=2020-01-01"
    $score = Invoke-Safely -Label 'MDC secure score' -Script {
        $response = Invoke-AzRestMethod -Method GET -Path $uri -ErrorAction Stop
        if ($response.StatusCode -ne 200) { throw "HTTP $($response.StatusCode)" }
        ($response.Content | ConvertFrom-Json)
    }

    if (-not $score) {
        Add-Result -Product $Product -Category 'Posture' -Setting 'Secure score' -Scope $Scope `
            -Status 'Gray' -Current 'Could not read secure score' -Expected '>= 80%' `
            -Recommendation 'Verify read permission on Microsoft.Security/secureScores.'
        return
    }

    $percentage = [math]::Round(((Get-PropertyValue $score.properties 'score').percentage) * 100, 1)

    $state = 'Red'
    if ($percentage -ge 80)     { $state = 'Green' }
    elseif ($percentage -ge 50) { $state = 'Yellow' }

    Add-Result -Product $Product -Category 'Posture' -Setting 'Secure score' -Scope $Scope `
        -Status $state -Current ('{0}%' -f $percentage) -Expected '>= 80%' `
        -Recommendation 'Work the highest-value recommendations in Defender for Cloud > Recommendations to raise the score.'
}

#endregion

# =====================================================================================
# REGION: MODULE 3 - Microsoft Defender for Endpoint
# =====================================================================================
#region Defender for Endpoint

# Defender AV settings-catalog IDs -> friendly name.
# Value suffix meaning: _0 = off/disabled, _1 = enabled/block, _2 = audit, _6 = warn.
$script:AvSettingMap = @{
    'device_vendor_msft_policy_config_defender_allowrealtimemonitoring'             = 'Real-time protection'
    'device_vendor_msft_policy_config_defender_allowcloudprotection'                = 'Cloud-delivered protection (MAPS)'
    'device_vendor_msft_policy_config_defender_allowbehaviormonitoring'             = 'Behaviour monitoring'
    'device_vendor_msft_policy_config_defender_allowioavprotection'                 = 'Scan downloaded files and attachments'
    'device_vendor_msft_policy_config_defender_allowscriptscanning'                 = 'Script scanning'
    'device_vendor_msft_policy_config_defender_allowonaccessprotection'             = 'On-access protection'
    'device_vendor_msft_policy_config_defender_puaprotection'                       = 'Potentially unwanted app (PUA) protection'
    'device_vendor_msft_policy_config_defender_enablenetworkprotection'             = 'Network protection'
    'device_vendor_msft_policy_config_defender_disablelocaladminmerge'              = 'Disable local admin merge'
    'device_vendor_msft_policy_config_defender_checkforsignaturesbeforerunningscan' = 'Check signatures before scan'
    'device_vendor_msft_defender_configuration_tamperprotection'                    = 'Tamper protection'
}

# The standard ASR rule set.
#
# IMPORTANT: the Intune settings catalog does NOT identify ASR rules by GUID. Setting
# definition IDs use friendly names, e.g.
#   ..._asr_blockadobereaderfromcreatingchildprocesses
# with values such as _off, _block, _audit, _warn. Matching on GUID alone therefore
# matches nothing and every rule gets reported as "not configured".
#
# Each entry carries BOTH identifiers so matching succeeds regardless of which surface
# the policy came from:
#   Guid  - used by the Defender CSP / OMA-URI / PowerShell surfaces, shown in the report
#   Token - the normalised friendly-name fragment used by the settings catalog
$script:AsrRuleMap = @(
    @{ Guid = 'd4f940ab-401b-4efc-aadc-ad5f3c50688a'; Token = 'blockallofficeapplicationsfromcreatingchildprocesses';                       Name = 'Block all Office applications from creating child processes' }
    @{ Guid = '3b576869-a4ec-4529-8536-b80a7769e899'; Token = 'blockofficeapplicationsfromcreatingexecutablecontent';                       Name = 'Block Office applications from creating executable content' }
    @{ Guid = '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84'; Token = 'blockofficeapplicationsfrominjectingcodeintootherprocesses';                 Name = 'Block Office applications from injecting code into other processes' }
    @{ Guid = '5beb7efe-fd9a-4556-801d-275e5ffc04cc'; Token = 'blockexecutionofpotentiallyobfuscatedscripts';                               Name = 'Block execution of potentially obfuscated scripts' }
    @{ Guid = 'd3e037e1-3eb8-44c8-a917-57927947596d'; Token = 'blockjavascriptorvbscriptfromlaunchingdownloadedexecutablecontent';          Name = 'Block JavaScript or VBScript from launching downloaded executable content' }
    @{ Guid = 'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550'; Token = 'blockexecutablecontentfromemailclientandwebmail';                            Name = 'Block executable content from email client and webmail' }
    @{ Guid = '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b'; Token = 'blockwin32apicallsfromofficemacros';                                         Name = 'Block Win32 API calls from Office macros' }
    @{ Guid = '01443614-cd74-433a-b99e-2ecdc07bfc25'; Token = 'blockexecutablefilesrunningunlesstheymeetprevalenceagetrustedlistcriterion'; Name = 'Block executable files unless they meet prevalence/age/trusted-list criteria' }
    @{ Guid = 'c1db55ab-c21a-4637-bb3f-a12568109d35'; Token = 'useadvancedprotectionagainstransomware';                                     Name = 'Use advanced protection against ransomware' }
    @{ Guid = '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'; Token = 'blockcredentialstealingfromwindowslocalsecurityauthoritysubsystem';          Name = 'Block credential stealing from LSASS' }
    @{ Guid = 'd1e49aac-8f56-4280-b9ba-993a6d77406c'; Token = 'blockprocesscreationsfrompsexecandwmicommands';                              Name = 'Block process creations from PSExec and WMI commands' }
    @{ Guid = 'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4'; Token = 'blockuntrustedunsignedprocessesthatrunfromusb';                              Name = 'Block untrusted and unsigned processes that run from USB' }
    @{ Guid = '26190899-1602-49e8-8b27-eb1d0a1ce869'; Token = 'blockofficecommunicationappfromcreatingchildprocesses';                      Name = 'Block Office communication app from creating child processes' }
    @{ Guid = '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c'; Token = 'blockadobereaderfromcreatingchildprocesses';                                 Name = 'Block Adobe Reader from creating child processes' }
    @{ Guid = 'e6db77e5-3df2-4cf1-b95a-636979351e5b'; Token = 'blockpersistencethroughwmieventsubscription';                                Name = 'Block persistence through WMI event subscription' }
    @{ Guid = '56a863a9-875e-4185-98a7-b882c64b5ce5'; Token = 'blockabuseofexploitedvulnerablesigneddrivers';                               Name = 'Block abuse of exploited vulnerable signed drivers' }
    @{ Guid = '33ddedf1-c6e0-47cb-833e-de6133960387'; Token = 'blockrebootingmachineinsafemode';                                            Name = 'Block rebooting machine in Safe Mode' }
    @{ Guid = 'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb'; Token = 'blockuseofcopiedorimpersonatedsystemtools';                                  Name = 'Block use of copied or impersonated system tools' }
    @{ Guid = 'a8f5898e-1dc8-49a9-9878-85004b8a61e6'; Token = 'blockwebshellcreationforservers';                                            Name = 'Block Webshell creation for Servers' }
)

function ConvertTo-NormalizedSettingId {
    <#
        Strips every non-alphanumeric character and lowercases, so that
        "Block-Adobe_Reader", "blockadobereader" and
        "device_vendor_msft_.._asr_blockadobereaderfromcreatingchildprocesses"
        all reduce to a comparable form. GUIDs reduce to their undashed hex string.
    #>
    param([string] $Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
    return ($Value -replace '[^A-Za-z0-9]', '').ToLowerInvariant()
}

function ConvertTo-ModeState {
    <#
        Maps a settings-catalog value to a traffic-light state.
        Block/enable = Green, audit or warn = Yellow, off/disabled = Red.
    #>
    param([string] $Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return 'Gray' }

    # Reduce the full definition ID to its trailing token, e.g.
    # "..._enablenetworkprotection_1" -> "1", "..._asr_<rule>_block" -> "block"
    $token = ($Value -split '_')[-1]

    # Enabled / blocking states
    if ($token -match '^(?i)(1|5|block|enable|enabled|on|true)$') { return 'Green' }

    # Partial states: audit and warn are "watching but not stopping"
    if ($token -match '^(?i)(2|6|audit|warn|auditmode)$') { return 'Yellow' }

    # Explicitly off
    if ($token -match '^(?i)(0|off|disable|disabled|false|notconfigured)$') { return 'Red' }

    return 'Gray'
}

function Invoke-DefenderForEndpointChecks {
    $product = 'Defender for Endpoint'
    Write-Step -Message 'START Defender for Endpoint assessment' -State 'Start'

    if (-not (Get-MgContext -ErrorAction SilentlyContinue)) {
        Add-ModuleFailure -Product $product -Reason 'No Microsoft Graph context available' `
            -Recommendation 'Run Connect-MgGraph with DeviceManagementConfiguration.Read.All, then re-run.'
    }
    else {
        Test-MdeIntunePolicies -Product $product
    }

    Test-MdeDevicePosture -Product $product

    Write-Step -Message 'END Defender for Endpoint assessment' -State 'Done'
}

function Get-SettingsCatalogValues {
    <#
        Flattens an Intune settings-catalog policy's setting tree into
        definitionId -> value string pairs. Handles choice, simple and group settings
        plus nested children, which covers the Defender AV / ASR templates.
    #>
    param($SettingInstance, [hashtable] $Accumulator)

    if ($null -eq $SettingInstance) { return }

    $definitionId = Get-PropertyValue $SettingInstance 'settingDefinitionId'

    $choice = Get-PropertyValue $SettingInstance 'choiceSettingValue'
    if ($choice) {
        if ($definitionId) { $Accumulator[$definitionId] = "$(Get-PropertyValue $choice 'value')" }
        foreach ($child in @(Get-PropertyValue $choice 'children')) {
            Get-SettingsCatalogValues -SettingInstance $child -Accumulator $Accumulator
        }
    }

    $simple = Get-PropertyValue $SettingInstance 'simpleSettingValue'
    if ($simple -and $definitionId) {
        $Accumulator[$definitionId] = "$(Get-PropertyValue $simple 'value')"
    }

    $collection = Get-PropertyValue $SettingInstance 'simpleSettingCollectionValue'
    if ($collection -and $definitionId) {
        $Accumulator[$definitionId] = (@($collection | ForEach-Object { Get-PropertyValue $_ 'value' }) -join ';')
    }

    $group = Get-PropertyValue $SettingInstance 'groupSettingCollectionValue'
    if ($group) {
        foreach ($groupItem in $group) {
            foreach ($child in @(Get-PropertyValue $groupItem 'children')) {
                Get-SettingsCatalogValues -SettingInstance $child -Accumulator $Accumulator
            }
        }
    }
}

function Test-MdeIntunePolicies {
    <#
        Pulls Intune settings-catalog policies, flattens their settings, then grades
        Defender AV settings and the full ASR rule set.
    #>
    param([string] $Product)

    Write-Step -Message 'Reading Intune settings-catalog policies' -State 'Info'

    $policies = Invoke-Safely -Label 'configurationPolicies' -Script {
        Invoke-GraphGet -Uri '/beta/deviceManagement/configurationPolicies?$expand=settings&$top=100'
    }

    if (-not $policies -or $policies.Count -eq 0) {
        Add-Result -Product $Product -Category 'Policy baseline' -Setting 'Endpoint security policies' `
            -Status 'Red' -Current 'No settings-catalog policies found' -Expected 'Defender AV and ASR policies deployed' `
            -Recommendation 'Create Antivirus and Attack Surface Reduction policies under Intune > Endpoint security.'
        return
    }

    Write-Step -Message ('Found {0} configuration policies' -f $policies.Count) -State 'Info'

    # Merge every policy's settings into one effective view. Strongest value wins so a
    # rule set to Block in any policy is not downgraded by a weaker policy elsewhere.
    $effective = @{}
    foreach ($policy in $policies) {
        $policyValues = @{}
        $policyName   = Get-PropertyValue $policy 'name'
        $policyId     = Get-PropertyValue $policy 'id'
        $settings     = @(Get-PropertyValue $policy 'settings')

        # $expand=settings on the collection endpoint does not always hydrate settings,
        # particularly for endpoint security template policies (such as the Attack
        # Surface Reduction Rules profile). When it comes back empty, fetch the
        # settings for that policy individually.
        if ($settings.Count -eq 0 -and $policyId) {
            Write-Step -Message ('Settings not expanded for "{0}" - fetching individually' -f $policyName) -State 'Info'
            $settings = @(Invoke-Safely -Label ('settings for ' + $policyName) -Script {
                Invoke-GraphGet -Uri ("/beta/deviceManagement/configurationPolicies('$policyId')/settings")
            })
        }

        foreach ($setting in $settings) {
            Get-SettingsCatalogValues -SettingInstance (Get-PropertyValue $setting 'settingInstance') -Accumulator $policyValues
        }

        if ($policyValues.Count -gt 0) {
            Write-Step -Message ('  "{0}": {1} setting(s)' -f $policyName, $policyValues.Count) -State 'Info'
        }

        foreach ($key in $policyValues.Keys) {
            $incoming = $policyValues[$key]
            if (-not $effective.ContainsKey($key)) {
                $effective[$key] = $incoming
            }
            else {
                $rank         = @{ Green = 3; Yellow = 2; Red = 1; Gray = 0 }
                $currentRank  = $rank[(ConvertTo-ModeState $effective[$key])]
                $incomingRank = $rank[(ConvertTo-ModeState $incoming)]
                if ($incomingRank -gt $currentRank) { $effective[$key] = $incoming }
            }
        }
    }

    Write-Step -Message ('Flattened {0} distinct settings' -f $effective.Count) -State 'Info'

    # Diagnostic dump: lets you see exactly what your tenant returns, and whether each
    # discovered setting matched one of the maps in this script.
    if ($DumpSettingIds) {
        $dumpPath = Join-Path $OutputFolder ("IntuneSettingIds-{0}.csv" -f $script:StartTime.ToString('yyyyMMdd-HHmmss'))

        $dump = foreach ($key in ($effective.Keys | Sort-Object)) {
            $normalized = ConvertTo-NormalizedSettingId $key

            $matchedRule = $script:AsrRuleMap |
                Where-Object {
                    $normalized -notmatch 'exclusion' -and
                    ($normalized -like "*$($_.Token)*" -or
                     $normalized -like "*$(ConvertTo-NormalizedSettingId $_.Guid)*")
                } |
                Select-Object -First 1

            $matchedRuleName = ''
            if ($matchedRule) { $matchedRuleName = $matchedRule.Name }

            $matchedAvName = ''
            if ($script:AvSettingMap.ContainsKey($key)) { $matchedAvName = $script:AvSettingMap[$key] }

            [pscustomobject]@{
                SettingDefinitionId = $key
                Value               = $effective[$key]
                InterpretedState    = ConvertTo-ModeState $effective[$key]
                MatchedAsrRule      = $matchedRuleName
                MatchedAvSetting    = $matchedAvName
            }
        }

        $dump | Export-Csv -Path $dumpPath -NoTypeInformation -Encoding utf8
        Write-Step -Message ('Setting ID dump written to {0}' -f $dumpPath) -State 'Done'
    }

    # ---- Defender antivirus core settings ----
    foreach ($definitionId in $script:AvSettingMap.Keys) {
        $label = $script:AvSettingMap[$definitionId]

        # Exact match first (this is how the IDs are published), then a normalised
        # fallback in case punctuation or casing shifts in a future catalog release.
        $match = $effective.Keys | Where-Object { $_ -eq $definitionId } | Select-Object -First 1

        if (-not $match) {
            $normalizedTarget = ConvertTo-NormalizedSettingId $definitionId
            $match = $effective.Keys |
                        Where-Object { (ConvertTo-NormalizedSettingId $_) -eq $normalizedTarget } |
                        Select-Object -First 1
        }

        if (-not $match) {
            Add-Result -Product $Product -Category 'Defender antivirus' -Setting $label `
                -Status 'Red' -Current 'Not configured in any settings-catalog policy' -Expected 'Enabled' `
                -Recommendation ('Configure "{0}" in an Intune > Endpoint security > Antivirus policy.' -f $label)
            continue
        }

        $value = $effective[$match]
        $state = ConvertTo-ModeState $value

        $expected = 'Enabled'
        if ($label -match 'Network protection|PUA') { $expected = 'Block (enabled)' }

        $rec = switch ($state) {
            'Green'  { 'No action required.' }
            'Yellow' { ('"{0}" is in audit/warn mode. Move it to block once you have validated the audit telemetry.' -f $label) }
            'Red'    { ('"{0}" is turned off. Enable it in your Antivirus policy.' -f $label) }
            default  { 'Value could not be interpreted - review the policy manually.' }
        }

        Add-Result -Product $Product -Category 'Defender antivirus' -Setting $label `
            -Status $state -Current $value -Expected $expected -Recommendation $rec
    }

    # ---- Attack surface reduction rules ----
    #
    # Build a normalised lookup of every candidate ASR setting. Two things matter here:
    #  1. We normalise the definition ID (strip punctuation, lowercase) so friendly-name
    #     IDs and GUID-bearing IDs both become matchable.
    #  2. We drop the per-rule exclusion settings. Each ASR rule in the settings catalog
    #     is accompanied by an "ASR Only Per Rule Exclusions" child setting whose ID
    #     contains the same rule name - matching it would mask the real rule value.
    $asrLookup = @{}
    foreach ($key in $effective.Keys) {
        $normalizedKey = ConvertTo-NormalizedSettingId $key

        # Skip exclusion / exclusion-list settings, they are not the rule state.
        if ($normalizedKey -match 'exclusion') { continue }

        $asrLookup[$normalizedKey] = @{ OriginalId = $key; Value = $effective[$key] }
    }

    foreach ($rule in $script:AsrRuleMap) {
        $label          = $rule.Name
        $normalizedGuid = ConvertTo-NormalizedSettingId $rule.Guid
        $token          = $rule.Token

        # Match on the friendly-name token first (settings catalog / endpoint security
        # templates), then fall back to the GUID (CSP, OMA-URI and legacy surfaces).
        $matchKey = $asrLookup.Keys |
                        Where-Object { $_ -like "*$token*" } |
                        Select-Object -First 1

        if (-not $matchKey) {
            $matchKey = $asrLookup.Keys |
                            Where-Object { $_ -like "*$normalizedGuid*" } |
                            Select-Object -First 1
        }

        if (-not $matchKey) {
            Add-Result -Product $Product -Category 'Attack surface reduction' -Setting $label `
                -Status 'Red' -Current 'Rule not configured' -Expected 'Block' `
                -Recommendation ('Add ASR rule {0} to an Intune > Endpoint security > Attack surface reduction policy. Start in audit, then move to block.' -f $rule.Guid)
            continue
        }

        $value = $asrLookup[$matchKey].Value
        $state = ConvertTo-ModeState $value

        $rec = switch ($state) {
            'Green'  { 'No action required.' }
            'Yellow' { 'Rule is in audit or warn mode. Review audit telemetry in advanced hunting, add exclusions, then switch to block.' }
            'Red'    { 'Rule is disabled. Enable in audit mode first, then move to block.' }
            default  { 'Rule mode could not be interpreted - review the policy manually.' }
        }

        Add-Result -Product $Product -Category 'Attack surface reduction' -Setting $label `
            -Status $state -Current $value -Expected 'Block' -Recommendation $rec
    }
}

function Test-MdeDevicePosture {
    <#
        Uses the Defender for Endpoint API to grade onboarding coverage, sensor health
        and outstanding device risk.
    #>
    param([string] $Product)

    $token = Get-MdeToken
    if (-not $token) {
        Add-Result -Product $Product -Category 'Device posture' -Setting 'Onboarded device inventory' `
            -Status 'Gray' -Current 'Could not acquire a Defender for Endpoint API token' `
            -Expected 'Devices onboarded and reporting' `
            -Recommendation 'Sign in with Connect-AzAccount using an account that holds an MDE read role, or query the portal directly.'
        return
    }

    $headers = @{ Authorization = "Bearer $token"; Accept = 'application/json' }

    $machines = Invoke-Safely -Label 'MDE machines' -Script {
        $uri = '{0}/api/machines?$top=10000' -f $script:Ep.Mde
        (Invoke-RestMethod -Uri $uri -Headers $headers -Method GET -ErrorAction Stop).value
    }

    if (-not $machines) {
        Add-Result -Product $Product -Category 'Device posture' -Setting 'Onboarded device inventory' `
            -Status 'Gray' -Current 'No device data returned' -Expected 'Devices onboarded and reporting' `
            -Recommendation 'Confirm MDE API permissions, or check Devices in the Defender portal.'
        return
    }

    $total = @($machines).Count
    Write-Step -Message ('Retrieved {0} MDE devices' -f $total) -State 'Info'

    $inventoryState = 'Red'
    if ($total -gt 0) { $inventoryState = 'Green' }

    Add-Result -Product $Product -Category 'Device posture' -Setting 'Onboarded device inventory' `
        -Status $inventoryState `
        -Current ('{0} device(s) onboarded' -f $total) -Expected 'All in-scope devices onboarded' `
        -Recommendation 'Reconcile this count against your Intune / AD device inventory to find onboarding gaps.'

    # Sensor health - Active vs Inactive / misconfigured
    $active = @($machines | Where-Object { $_.healthStatus -eq 'Active' }).Count
    Add-Result -Product $Product -Category 'Device posture' -Setting 'Sensor health (Active)' `
        -Status (Get-CoverageState -Compliant $active -Total $total) `
        -Current ('{0} of {1} devices Active' -f $active, $total) `
        -Expected 'All devices Active' `
        -Recommendation 'Investigate Inactive, ImpairedCommunications and NoSensorData devices under Devices > Health state.'

    # Onboarding status
    $onboarded = @($machines | Where-Object { $_.onboardingStatus -eq 'Onboarded' }).Count
    Add-Result -Product $Product -Category 'Device posture' -Setting 'Onboarding status' `
        -Status (Get-CoverageState -Compliant $onboarded -Total $total) `
        -Current ('{0} of {1} fully onboarded' -f $onboarded, $total) -Expected 'All devices onboarded' `
        -Recommendation 'Re-run onboarding on devices showing CanBeOnboarded or Unsupported.'

    # Outstanding high-risk devices
    $highRisk = @($machines | Where-Object { $_.riskScore -in @('High', 'Medium') }).Count

    $riskState = 'Red'
    if ($highRisk -eq 0) { $riskState = 'Green' }
    elseif ($highRisk -le [math]::Ceiling($total * 0.05)) { $riskState = 'Yellow' }

    Add-Result -Product $Product -Category 'Device posture' -Setting 'Devices at Medium/High risk' `
        -Status $riskState -Current ('{0} of {1} devices' -f $highRisk, $total) -Expected '0 devices' `
        -Recommendation 'Triage active incidents on these devices in the Defender portal and drive them back to Low risk.'

    # Exposure level
    $exposed = @($machines | Where-Object { $_.exposureLevel -in @('High', 'Medium') }).Count

    $exposureState = 'Red'
    if ($exposed -eq 0) { $exposureState = 'Green' }
    elseif ($exposed -le [math]::Ceiling($total * 0.10)) { $exposureState = 'Yellow' }

    Add-Result -Product $Product -Category 'Device posture' -Setting 'Devices at Medium/High exposure' `
        -Status $exposureState -Current ('{0} of {1} devices' -f $exposed, $total) -Expected '0 devices' `
        -Recommendation 'Work the Vulnerability Management recommendations to reduce exposure on these devices.'
}

#endregion

# =====================================================================================
# REGION: MODULE 4 - Microsoft Defender for Identity
# =====================================================================================
#region Defender for Identity

function Invoke-DefenderForIdentityChecks {
    $product = 'Defender for Identity'
    Write-Step -Message 'START Defender for Identity assessment' -State 'Start'

    if (-not (Get-MgContext -ErrorAction SilentlyContinue)) {
        Add-ModuleFailure -Product $product -Reason 'No Microsoft Graph context available' `
            -Recommendation 'Run Connect-MgGraph with SecurityIdentitiesSensors.Read.All and SecurityIdentitiesHealth.Read.All.'
        return
    }

    Test-MdiSensors      -Product $product
    Test-MdiHealthIssues -Product $product

    Write-Step -Message 'END Defender for Identity assessment' -State 'Done'
}

function Test-MdiSensors {
    <# Sensor inventory, version currency, service state and delayed-update posture. #>
    param([string] $Product)

    $sensors = Invoke-Safely -Label 'MDI sensors' -Script {
        Invoke-GraphGet -Uri '/beta/security/identities/sensors'
    }

    if ($null -eq $sensors) {
        Add-Result -Product $Product -Category 'Sensors' -Setting 'Sensor inventory' `
            -Status 'Gray' -Current 'Could not read /security/identities/sensors' `
            -Expected 'A sensor on every domain controller, AD FS, AD CS and Entra Connect server' `
            -Recommendation 'Grant SecurityIdentitiesSensors.Read.All and confirm the workspace is provisioned.'
        return
    }

    $total = @($sensors).Count

    if ($total -eq 0) {
        Add-Result -Product $Product -Category 'Sensors' -Setting 'Sensor inventory' `
            -Status 'Red' -Current 'No sensors deployed' `
            -Expected 'A sensor on every domain controller, AD FS, AD CS and Entra Connect server' `
            -Recommendation 'Deploy Defender for Identity sensors from Defender portal > Settings > Identities > Sensors.'
        return
    }

    Write-Step -Message ('Retrieved {0} MDI sensors' -f $total) -State 'Info'

    Add-Result -Product $Product -Category 'Sensors' -Setting 'Sensor inventory' `
        -Status 'Green' -Current ('{0} sensor(s) registered' -f $total) `
        -Expected 'A sensor on every DC, AD FS, AD CS and Entra Connect server' `
        -Recommendation 'Reconcile this count against your domain controller list to confirm full coverage.'

    # Version currency
    $upToDate = @($sensors | Where-Object { $_.deploymentStatus -eq 'upToDate' }).Count
    Add-Result -Product $Product -Category 'Sensors' -Setting 'Sensor version currency' `
        -Status (Get-CoverageState -Compliant $upToDate -Total $total) `
        -Current ('{0} of {1} up to date' -f $upToDate, $total) -Expected 'All sensors up to date' `
        -Recommendation 'Update sensors flagged outdated, updateFailed or unreachable.'

    # Health
    $healthy = @($sensors | Where-Object { $_.healthStatus -eq 'healthy' }).Count
    Add-Result -Product $Product -Category 'Sensors' -Setting 'Sensor health status' `
        -Status (Get-CoverageState -Compliant $healthy -Total $total) `
        -Current ('{0} of {1} healthy' -f $healthy, $total) -Expected 'All sensors healthy' `
        -Recommendation 'Open each unhealthy sensor in the portal and resolve its health issues.'

    # Service state
    $running = @($sensors | Where-Object { $_.serviceStatus -eq 'running' }).Count
    Add-Result -Product $Product -Category 'Sensors' -Setting 'Sensor service running' `
        -Status (Get-CoverageState -Compliant $running -Total $total) `
        -Current ('{0} of {1} running' -f $running, $total) -Expected 'All sensor services running' `
        -Recommendation 'Restart or reinstall sensors reporting stopped, startFailure or disabled.'

    # Delayed updates should be the exception, not the norm
    $delayed = @($sensors | Where-Object { (Get-PropertyValue $_.settings 'isDelayedDeploymentEnabled') -eq $true }).Count

    $delayState = 'Red'
    if ($delayed -eq 0)          { $delayState = 'Green' }
    elseif ($delayed -lt $total) { $delayState = 'Yellow' }

    Add-Result -Product $Product -Category 'Sensors' -Setting 'Delayed sensor updates' `
        -Status $delayState -Current ('{0} of {1} sensors have delayed updates enabled' -f $delayed, $total) `
        -Expected 'Delayed updates on a small canary set only' `
        -Recommendation 'Keep delayed updates on a handful of canary sensors. Every sensor delayed means the whole estate lags behind detections.'
}

function Test-MdiHealthIssues {
    <# Open health issues, graded by highest open severity. #>
    param([string] $Product)

    $issues = Invoke-Safely -Label 'MDI health issues' -Script {
        Invoke-GraphGet -Uri "/beta/security/identities/healthIssues?`$filter=status eq 'open'"
    }

    if ($null -eq $issues) {
        Add-Result -Product $Product -Category 'Health' -Setting 'Open health issues' `
            -Status 'Gray' -Current 'Could not read /security/identities/healthIssues' -Expected 'No open health issues' `
            -Recommendation 'Grant SecurityIdentitiesHealth.Read.All.'
        return
    }

    $total  = @($issues).Count
    $high   = @($issues | Where-Object { $_.severity -eq 'high' }).Count
    $medium = @($issues | Where-Object { $_.severity -eq 'medium' }).Count
    $low    = @($issues | Where-Object { $_.severity -eq 'low' }).Count

    $state = 'Yellow'
    if ($total -eq 0)    { $state = 'Green' }
    elseif ($high -gt 0) { $state = 'Red' }

    Add-Result -Product $Product -Category 'Health' -Setting 'Open health issues' `
        -Status $state -Current ('{0} open (High: {1}, Medium: {2}, Low: {3})' -f $total, $high, $medium, $low) `
        -Expected 'No open health issues' `
        -Recommendation 'Resolve open issues under Defender portal > Settings > Identities > Health issues. High severity issues usually mean lost detection coverage.'

    # Break out the global (workspace-wide) issues separately - these hit every sensor.
    $globalIssues = @($issues | Where-Object { $_.healthIssueType -eq 'global' }).Count

    $globalState = 'Red'
    if ($globalIssues -eq 0) { $globalState = 'Green' }

    Add-Result -Product $Product -Category 'Health' -Setting 'Global (workspace-wide) health issues' `
        -Status $globalState `
        -Current ('{0} global issue(s)' -f $globalIssues) -Expected '0 global issues' `
        -Recommendation 'Global issues such as missing directory service accounts or unresolved NNR affect every sensor. Fix these first.'
}

#endregion

# =====================================================================================
# REGION: MODULE 5 - Microsoft Defender for Office 365
# =====================================================================================
#region Defender for Office

function Invoke-DefenderForOfficeChecks {
    $product = 'Defender for Office 365'
    Write-Step -Message 'START Defender for Office 365 assessment' -State 'Start'

    $connection = Invoke-Safely -Label 'EXO connection check' -Script { Get-ConnectionInformation -ErrorAction Stop }
    if (-not $connection) {
        Add-ModuleFailure -Product $product -Reason 'No Exchange Online session' `
            -Recommendation 'Install ExchangeOnlineManagement and run Connect-ExchangeOnline. If token acquisition fails, re-run from a non-elevated console or use -DisableWam.'
        return
    }

    Test-MdoPresetPolicies  -Product $product
    Test-MdoAntiPhish       -Product $product
    Test-MdoSafeLinks       -Product $product
    Test-MdoSafeAttachments -Product $product
    Test-MdoMalwareFilter   -Product $product
    Test-MdoAntiSpam        -Product $product
    Test-MdoOutboundSpam    -Product $product
    Test-MdoTenantHygiene   -Product $product

    Write-Step -Message 'END Defender for Office 365 assessment' -State 'Done'
}

function Test-MdoPresetPolicies {
    <# Preset security policies are the fastest route to a good baseline. #>
    param([string] $Product)

    $eop = Invoke-Safely -Label 'Get-EOPProtectionPolicyRule' -Script { Get-EOPProtectionPolicyRule -ErrorAction Stop }
    $atp = Invoke-Safely -Label 'Get-ATPProtectionPolicyRule' -Script { Get-ATPProtectionPolicyRule -ErrorAction Stop }

    foreach ($pair in @(
        @{ Label = 'EOP preset security policy'; Data = $eop },
        @{ Label = 'Defender for Office preset security policy'; Data = $atp }
    )) {
        if ($null -eq $pair.Data) {
            Add-Result -Product $Product -Category 'Preset policies' -Setting $pair.Label `
                -Status 'Gray' -Current 'Could not read preset policy rules' -Expected 'Standard or Strict enabled' `
                -Recommendation 'Confirm the account holds a Security Reader or Global Reader role in Exchange Online.'
            continue
        }

        $enabled = @($pair.Data | Where-Object { $_.State -eq 'Enabled' })
        $strict  = @($enabled | Where-Object { $_.Identity -match 'Strict' })

        if ($strict.Count -gt 0) {
            $state   = 'Green'
            $current = 'Strict preset enabled'
            $rec     = 'No action required.'
        }
        elseif ($enabled.Count -gt 0) {
            $state   = 'Green'
            $current = ('{0} preset policy rule(s) enabled' -f $enabled.Count)
            $rec     = 'Standard preset is enabled. Consider Strict for high-risk users such as executives and finance.'
        }
        else {
            $state   = 'Red'
            $current = 'No preset policy enabled'
            $rec     = 'Enable the Standard preset at minimum in Defender portal > Policies & rules > Preset security policies.'
        }

        Add-Result -Product $Product -Category 'Preset policies' -Setting $pair.Label `
            -Status $state -Current $current -Expected 'Standard or Strict enabled' -Recommendation $rec
    }
}

function Test-MdoAntiPhish {
    <# Impersonation, mailbox intelligence, spoof intelligence and DMARC handling. #>
    param([string] $Product)

    $policies = Invoke-Safely -Label 'Get-AntiPhishPolicy' -Script { Get-AntiPhishPolicy -ErrorAction Stop }
    if (-not $policies) {
        Add-Result -Product $Product -Category 'Anti-phishing' -Setting 'Anti-phishing policy' `
            -Status 'Gray' -Current 'Could not read anti-phishing policies' -Expected 'Configured' `
            -Recommendation 'Verify Exchange Online read permissions.'
        return
    }

    $enabledPolicies = @($policies | Where-Object { $_.Enabled -eq $true })
    if ($enabledPolicies.Count -eq 0) { $enabledPolicies = @($policies) }
    $total = $enabledPolicies.Count

    $booleanChecks = @(
        @{ Property = 'EnableSpoofIntelligence';             Label = 'Spoof intelligence' }
        @{ Property = 'EnableMailboxIntelligence';           Label = 'Mailbox intelligence' }
        @{ Property = 'EnableMailboxIntelligenceProtection'; Label = 'Mailbox intelligence impersonation protection' }
        @{ Property = 'EnableTargetedUserProtection';        Label = 'User impersonation protection' }
        @{ Property = 'EnableTargetedDomainsProtection';     Label = 'Domain impersonation protection' }
        @{ Property = 'EnableOrganizationDomainsProtection'; Label = 'Owned-domain impersonation protection' }
        @{ Property = 'EnableFirstContactSafetyTips';        Label = 'First contact safety tip' }
        @{ Property = 'EnableSimilarUsersSafetyTips';        Label = 'Similar users safety tip' }
        @{ Property = 'EnableSimilarDomainsSafetyTips';      Label = 'Similar domains safety tip' }
        @{ Property = 'EnableUnusualCharactersSafetyTips';   Label = 'Unusual characters safety tip' }
        @{ Property = 'EnableUnauthenticatedSender';         Label = 'Unauthenticated sender (question mark) indicator' }
        @{ Property = 'EnableViaTag';                        Label = 'Via tag indicator' }
        @{ Property = 'HonorDmarcPolicy';                    Label = 'Honor DMARC policy' }
    )

    foreach ($check in $booleanChecks) {
        $compliant = @($enabledPolicies | Where-Object { (Get-PropertyValue $_ $check.Property) -eq $true }).Count
        Add-Result -Product $Product -Category 'Anti-phishing' -Setting $check.Label `
            -Status (Get-CoverageState -Compliant $compliant -Total $total) `
            -Current ('Enabled in {0} of {1} policies' -f $compliant, $total) -Expected 'Enabled in all policies' `
            -Recommendation ('Turn on "{0}" in every anti-phishing policy, or adopt the Standard/Strict preset.' -f $check.Label)
    }

    # Phishing threshold: 1 Standard, 2 Aggressive, 3 More aggressive, 4 Most aggressive
    $goodThreshold = @($enabledPolicies | Where-Object { [int](Get-PropertyValue $_ 'PhishThresholdLevel') -ge 2 }).Count
    Add-Result -Product $Product -Category 'Anti-phishing' -Setting 'Advanced phishing threshold' `
        -Status (Get-CoverageState -Compliant $goodThreshold -Total $total) `
        -Current ('{0} of {1} policies at level 2 or higher' -f $goodThreshold, $total) `
        -Expected 'Level 2 (Aggressive) or higher' `
        -Recommendation 'Raise the advanced phishing threshold to at least 2. Strict preset uses 3.'

    # Actions - quarantine is the strong answer, junk folder is partial
    $actionChecks = @(
        @{ Property = 'AuthenticationFailAction';            Label = 'Spoof detection action' }
        @{ Property = 'MailboxIntelligenceProtectionAction'; Label = 'Mailbox intelligence impersonation action' }
        @{ Property = 'TargetedUserProtectionAction';        Label = 'User impersonation action' }
        @{ Property = 'TargetedDomainProtectionAction';      Label = 'Domain impersonation action' }
    )

    foreach ($check in $actionChecks) {
        $quarantine = @($enabledPolicies | Where-Object { (Get-PropertyValue $_ $check.Property) -eq 'Quarantine' }).Count
        $softAction = @($enabledPolicies | Where-Object { (Get-PropertyValue $_ $check.Property) -in @('MoveToJmf', 'BccMessage', 'Redirect') }).Count

        if ($quarantine -ge $total) {
            $state   = 'Green'
            $current = 'Quarantine in all policies'
        }
        elseif (($quarantine + $softAction) -gt 0) {
            $state   = 'Yellow'
            $current = ('Quarantine in {0}, softer action in {1} of {2}' -f $quarantine, $softAction, $total)
        }
        else {
            $state   = 'Red'
            $current = 'No protective action configured'
        }

        Add-Result -Product $Product -Category 'Anti-phishing' -Setting $check.Label `
            -Status $state -Current $current -Expected 'Quarantine' `
            -Recommendation ('Set "{0}" to Quarantine. Move-to-junk leaves the message reachable by the user.' -f $check.Label)
    }

    # DMARC handling for p=reject and p=quarantine
    $dmarcReject = @($enabledPolicies | Where-Object { (Get-PropertyValue $_ 'DmarcRejectAction') -eq 'Reject' }).Count
    Add-Result -Product $Product -Category 'Anti-phishing' -Setting 'DMARC p=reject action' `
        -Status (Get-CoverageState -Compliant $dmarcReject -Total $total) `
        -Current ('Reject in {0} of {1} policies' -f $dmarcReject, $total) -Expected 'Reject' `
        -Recommendation 'Honour the sending domain''s published DMARC policy by setting the reject action to Reject.'

    $dmarcQuarantine = @($enabledPolicies | Where-Object { (Get-PropertyValue $_ 'DmarcQuarantineAction') -eq 'Quarantine' }).Count
    Add-Result -Product $Product -Category 'Anti-phishing' -Setting 'DMARC p=quarantine action' `
        -Status (Get-CoverageState -Compliant $dmarcQuarantine -Total $total) `
        -Current ('Quarantine in {0} of {1} policies' -f $dmarcQuarantine, $total) -Expected 'Quarantine' `
        -Recommendation 'Set the DMARC quarantine action to Quarantine rather than junk.'
}

function Test-MdoSafeLinks {
    <# Safe Links coverage across email, Teams and Office clients. #>
    param([string] $Product)

    $policies = Invoke-Safely -Label 'Get-SafeLinksPolicy' -Script { Get-SafeLinksPolicy -ErrorAction Stop }
    if (-not $policies) {
        Add-Result -Product $Product -Category 'Safe Links' -Setting 'Safe Links policy' `
            -Status 'Red' -Current 'No Safe Links policies found' -Expected 'Safe Links enabled for email, Teams and Office apps' `
            -Recommendation 'Create a Safe Links policy, or enable a preset security policy which includes one.'
        return
    }

    $total = @($policies).Count

    $checks = @(
        @{ Property = 'EnableSafeLinksForEmail';  Label = 'Safe Links for email';           Invert = $false }
        @{ Property = 'EnableSafeLinksForTeams';  Label = 'Safe Links for Teams';           Invert = $false }
        @{ Property = 'EnableSafeLinksForOffice'; Label = 'Safe Links for Office 365 apps'; Invert = $false }
        @{ Property = 'ScanUrls';                 Label = 'Real-time URL scanning';         Invert = $false }
        @{ Property = 'DeliverMessageAfterScan';  Label = 'Wait for scan before delivery';  Invert = $false }
        @{ Property = 'EnableForInternalSenders'; Label = 'Apply to internal senders';      Invert = $false }
        @{ Property = 'TrackClicks';              Label = 'Track user clicks';              Invert = $false }
        @{ Property = 'AllowClickThrough';        Label = 'Block user click-through';       Invert = $true  }
        @{ Property = 'DisableUrlRewrite';        Label = 'URL rewriting enabled';          Invert = $true  }
    )

    foreach ($check in $checks) {
        $target    = -not $check.Invert
        $compliant = @($policies | Where-Object { (Get-PropertyValue $_ $check.Property) -eq $target }).Count

        $expectedText = "$($check.Property) = True"
        if ($check.Invert) { $expectedText = "$($check.Property) = False" }

        Add-Result -Product $Product -Category 'Safe Links' -Setting $check.Label `
            -Status (Get-CoverageState -Compliant $compliant -Total $total) `
            -Current ('Compliant in {0} of {1} policies' -f $compliant, $total) -Expected $expectedText `
            -Recommendation ('Set "{0}" correctly in every Safe Links policy, or adopt the Standard/Strict preset.' -f $check.Label)
    }
}

function Test-MdoSafeAttachments {
    <# Safe Attachments for email plus Safe Documents / SharePoint-OneDrive-Teams. #>
    param([string] $Product)

    $policies = Invoke-Safely -Label 'Get-SafeAttachmentPolicy' -Script { Get-SafeAttachmentPolicy -ErrorAction Stop }

    if (-not $policies) {
        Add-Result -Product $Product -Category 'Safe Attachments' -Setting 'Safe Attachments policy' `
            -Status 'Red' -Current 'No Safe Attachments policies found' -Expected 'Enabled with Block action' `
            -Recommendation 'Create a Safe Attachments policy, or enable a preset security policy which includes one.'
    }
    else {
        $total   = @($policies).Count
        $enabled = @($policies | Where-Object { $_.Enable -eq $true }).Count

        Add-Result -Product $Product -Category 'Safe Attachments' -Setting 'Safe Attachments enabled' `
            -Status (Get-CoverageState -Compliant $enabled -Total $total) `
            -Current ('Enabled in {0} of {1} policies' -f $enabled, $total) -Expected 'Enabled in all policies' `
            -Recommendation 'Enable Safe Attachments in every policy.'

        $blockAction   = @($policies | Where-Object { $_.Action -eq 'Block' }).Count
        $partialAction = @($policies | Where-Object { $_.Action -in @('DynamicDelivery', 'Replace') }).Count

        if ($blockAction -ge $total) {
            $state   = 'Green'
            $current = 'Block in all policies'
        }
        elseif (($blockAction + $partialAction) -gt 0) {
            $state   = 'Yellow'
            $current = ('Block in {0}, Replace/DynamicDelivery in {1} of {2}' -f $blockAction, $partialAction, $total)
        }
        else {
            $state   = 'Red'
            $current = 'Action is Allow / monitor only'
        }

        Add-Result -Product $Product -Category 'Safe Attachments' -Setting 'Unknown malware response' `
            -Status $state -Current $current -Expected 'Block' `
            -Recommendation 'Set the Safe Attachments action to Block. Allow/monitor-only delivers unscanned malware to the mailbox.'
    }

    # Safe Documents and SharePoint / OneDrive / Teams protection
    $atpPolicy = Invoke-Safely -Label 'Get-AtpPolicyForO365' -Script { Get-AtpPolicyForO365 -ErrorAction Stop }
    if (-not $atpPolicy) {
        Add-Result -Product $Product -Category 'Safe Attachments' -Setting 'SharePoint / OneDrive / Teams protection' `
            -Status 'Gray' -Current 'Could not read Get-AtpPolicyForO365' -Expected 'Enabled' `
            -Recommendation 'Verify Exchange Online read permissions.'
        return
    }

    $atp = @($atpPolicy)[0]

    Add-Result -Product $Product -Category 'Safe Attachments' -Setting 'SharePoint / OneDrive / Teams protection' `
        -Status (Get-BoolState (Get-PropertyValue $atp 'EnableATPForSPOTeamsODB')) `
        -Current ("EnableATPForSPOTeamsODB = $(Get-PropertyValue $atp 'EnableATPForSPOTeamsODB')") -Expected 'True' `
        -Recommendation 'Enable Safe Attachments for SharePoint, OneDrive and Teams to catch malware stored in files.'

    Add-Result -Product $Product -Category 'Safe Attachments' -Setting 'Safe Documents' `
        -Status (Get-BoolState (Get-PropertyValue $atp 'EnableSafeDocs')) `
        -Current ("EnableSafeDocs = $(Get-PropertyValue $atp 'EnableSafeDocs')") -Expected 'True' `
        -Recommendation 'Enable Safe Documents so files opened in Protected View are scanned before trust is granted.'

    Add-Result -Product $Product -Category 'Safe Attachments' -Setting 'Block Safe Docs click-through' `
        -Status (Get-BoolState (Get-PropertyValue $atp 'AllowSafeDocsOpen') -InvertGood) `
        -Current ("AllowSafeDocsOpen = $(Get-PropertyValue $atp 'AllowSafeDocsOpen')") -Expected 'False' `
        -Recommendation 'Set AllowSafeDocsOpen to False so users cannot leave Protected View on a malicious file.'
}

function Test-MdoMalwareFilter {
    <# Common attachment filter and malware ZAP. #>
    param([string] $Product)

    $policies = Invoke-Safely -Label 'Get-MalwareFilterPolicy' -Script { Get-MalwareFilterPolicy -ErrorAction Stop }
    if (-not $policies) {
        Add-Result -Product $Product -Category 'Anti-malware' -Setting 'Anti-malware policy' `
            -Status 'Gray' -Current 'Could not read anti-malware policies' -Expected 'Configured' `
            -Recommendation 'Verify Exchange Online read permissions.'
        return
    }

    $total = @($policies).Count

    $fileFilter = @($policies | Where-Object { $_.EnableFileFilter -eq $true }).Count
    Add-Result -Product $Product -Category 'Anti-malware' -Setting 'Common attachment filter' `
        -Status (Get-CoverageState -Compliant $fileFilter -Total $total) `
        -Current ('Enabled in {0} of {1} policies' -f $fileFilter, $total) -Expected 'Enabled in all policies' `
        -Recommendation 'Enable the common attachment filter to block executable file types outright.'

    $zap = @($policies | Where-Object { $_.ZapEnabled -eq $true }).Count
    Add-Result -Product $Product -Category 'Anti-malware' -Setting 'Malware zero-hour auto purge (ZAP)' `
        -Status (Get-CoverageState -Compliant $zap -Total $total) `
        -Current ('Enabled in {0} of {1} policies' -f $zap, $total) -Expected 'Enabled in all policies' `
        -Recommendation 'Enable malware ZAP so already-delivered malicious mail is retracted.'

    $quarantineNotify = @($policies | Where-Object { $_.QuarantineTag }).Count
    Add-Result -Product $Product -Category 'Anti-malware' -Setting 'Quarantine policy assigned' `
        -Status (Get-CoverageState -Compliant $quarantineNotify -Total $total) `
        -Current ('Quarantine policy set in {0} of {1} policies' -f $quarantineNotify, $total) `
        -Expected 'Quarantine policy assigned in all policies' `
        -Recommendation 'Assign an explicit quarantine policy so end-user release and notification behaviour is deliberate.'
}

function Test-MdoAntiSpam {
    <# Inbound spam handling, bulk threshold, ZAP and quarantine retention. #>
    param([string] $Product)

    $policies = Invoke-Safely -Label 'Get-HostedContentFilterPolicy' -Script { Get-HostedContentFilterPolicy -ErrorAction Stop }
    if (-not $policies) {
        Add-Result -Product $Product -Category 'Anti-spam (inbound)' -Setting 'Anti-spam policy' `
            -Status 'Gray' -Current 'Could not read anti-spam policies' -Expected 'Configured' `
            -Recommendation 'Verify Exchange Online read permissions.'
        return
    }

    $total = @($policies).Count

    # Verdict actions - quarantine strong, junk folder partial
    $verdicts = @(
        @{ Property = 'SpamAction';                Label = 'Spam verdict action' }
        @{ Property = 'HighConfidenceSpamAction';  Label = 'High-confidence spam action' }
        @{ Property = 'PhishSpamAction';           Label = 'Phishing verdict action' }
        @{ Property = 'HighConfidencePhishAction'; Label = 'High-confidence phishing action' }
        @{ Property = 'BulkSpamAction';            Label = 'Bulk mail action' }
    )

    foreach ($verdict in $verdicts) {
        $quarantine = @($policies | Where-Object { (Get-PropertyValue $_ $verdict.Property) -eq 'Quarantine' }).Count
        $junk       = @($policies | Where-Object { (Get-PropertyValue $_ $verdict.Property) -eq 'MoveToJmf' }).Count

        if ($quarantine -ge $total) {
            $state   = 'Green'
            $current = 'Quarantine in all policies'
        }
        elseif (($quarantine + $junk) -gt 0) {
            $state   = 'Yellow'
            $current = ('Quarantine in {0}, junk folder in {1} of {2}' -f $quarantine, $junk, $total)
        }
        else {
            $state   = 'Red'
            $current = 'No protective action (delivered to inbox)'
        }

        # Bulk mail to junk is an accepted baseline, so do not mark it down as harshly.
        if ($verdict.Property -eq 'BulkSpamAction' -and $state -eq 'Yellow') {
            $rec = 'Junk folder is acceptable for bulk mail. Quarantine only if your users tolerate it.'
        }
        else {
            $rec = ('Set "{0}" to Quarantine so the message is never reachable from the mailbox.' -f $verdict.Label)
        }

        Add-Result -Product $Product -Category 'Anti-spam (inbound)' -Setting $verdict.Label `
            -Status $state -Current $current -Expected 'Quarantine' -Recommendation $rec
    }

    # Bulk complaint level threshold - 6 or lower is the recommended range
    $goodBulk = @($policies | Where-Object { [int](Get-PropertyValue $_ 'BulkThreshold') -le 6 }).Count
    Add-Result -Product $Product -Category 'Anti-spam (inbound)' -Setting 'Bulk complaint level threshold' `
        -Status (Get-CoverageState -Compliant $goodBulk -Total $total) `
        -Current ('{0} of {1} policies at BCL 6 or lower' -f $goodBulk, $total) -Expected 'BCL 6 or lower' `
        -Recommendation 'Standard preset uses BCL 6, Strict uses 5. Higher values let more bulk mail through.'

    # ZAP
    foreach ($zapCheck in @(
        @{ Property = 'SpamZapEnabled';  Label = 'Spam ZAP' },
        @{ Property = 'PhishZapEnabled'; Label = 'Phishing ZAP' }
    )) {
        $compliant = @($policies | Where-Object { (Get-PropertyValue $_ $zapCheck.Property) -eq $true }).Count
        Add-Result -Product $Product -Category 'Anti-spam (inbound)' -Setting $zapCheck.Label `
            -Status (Get-CoverageState -Compliant $compliant -Total $total) `
            -Current ('Enabled in {0} of {1} policies' -f $compliant, $total) -Expected 'Enabled in all policies' `
            -Recommendation 'Enable ZAP so mail that turns out to be malicious after delivery is pulled back.'
    }

    # Quarantine retention
    $retention = @($policies | Where-Object { [int](Get-PropertyValue $_ 'QuarantineRetentionPeriod') -ge 30 }).Count
    Add-Result -Product $Product -Category 'Anti-spam (inbound)' -Setting 'Quarantine retention period' `
        -Status (Get-CoverageState -Compliant $retention -Total $total) `
        -Current ('{0} of {1} policies retain for 30 days' -f $retention, $total) -Expected '30 days' `
        -Recommendation 'Set quarantine retention to the 30-day maximum so investigations are not blocked by expiry.'

    # Safety tips
    $tips = @($policies | Where-Object { (Get-PropertyValue $_ 'InlineSafetyTipsEnabled') -eq $true }).Count
    Add-Result -Product $Product -Category 'Anti-spam (inbound)' -Setting 'Inline safety tips' `
        -Status (Get-CoverageState -Compliant $tips -Total $total) `
        -Current ('Enabled in {0} of {1} policies' -f $tips, $total) -Expected 'Enabled in all policies' `
        -Recommendation 'Keep inline safety tips on - they are a cheap and effective user cue.'
}

function Test-MdoOutboundSpam {
    <# Outbound spam limits and, critically, automatic forwarding. #>
    param([string] $Product)

    $policies = Invoke-Safely -Label 'Get-HostedOutboundSpamFilterPolicy' -Script { Get-HostedOutboundSpamFilterPolicy -ErrorAction Stop }
    if (-not $policies) {
        Add-Result -Product $Product -Category 'Anti-spam (outbound)' -Setting 'Outbound spam policy' `
            -Status 'Gray' -Current 'Could not read outbound spam policies' -Expected 'Configured' `
            -Recommendation 'Verify Exchange Online read permissions.'
        return
    }

    $total = @($policies).Count

    $forwardOff       = @($policies | Where-Object { (Get-PropertyValue $_ 'AutoForwardingMode') -eq 'Off' }).Count
    $forwardAutomatic = @($policies | Where-Object { (Get-PropertyValue $_ 'AutoForwardingMode') -eq 'Automatic' }).Count

    if ($forwardOff -ge $total) {
        $state   = 'Green'
        $current = 'Disabled in all policies'
    }
    elseif (($forwardOff + $forwardAutomatic) -gt 0) {
        $state   = 'Yellow'
        $current = ('Off in {0}, Automatic in {1} of {2}' -f $forwardOff, $forwardAutomatic, $total)
    }
    else {
        $state   = 'Red'
        $current = 'Automatic forwarding is On'
    }

    Add-Result -Product $Product -Category 'Anti-spam (outbound)' -Setting 'External automatic forwarding' `
        -Status $state -Current $current -Expected 'Off' `
        -Recommendation 'Set AutoForwardingMode to Off. External auto-forward is the standard exfiltration path after a mailbox compromise.'

    $notify = @($policies | Where-Object {
        (Get-PropertyValue $_ 'BccSuspiciousOutboundAdditionalRecipients') -or
        (Get-PropertyValue $_ 'NotifyOutboundSpamRecipients')
    }).Count
    Add-Result -Product $Product -Category 'Anti-spam (outbound)' -Setting 'Outbound spam notification recipients' `
        -Status (Get-CoverageState -Compliant $notify -Total $total) `
        -Current ('Recipients set in {0} of {1} policies' -f $notify, $total) -Expected 'Set in all policies' `
        -Recommendation 'Add a security distribution list so the SOC hears about outbound spam before the recipient domain blocks you.'

    $restrictAction = @($policies | Where-Object {
        (Get-PropertyValue $_ 'ActionWhenThresholdReached') -match 'BlockUser'
    }).Count
    Add-Result -Product $Product -Category 'Anti-spam (outbound)' -Setting 'Action when send limit is reached' `
        -Status (Get-CoverageState -Compliant $restrictAction -Total $total) `
        -Current ('Blocks the user in {0} of {1} policies' -f $restrictAction, $total) -Expected 'Restrict the user from sending mail' `
        -Recommendation 'Set the threshold action to restrict the user so a compromised mailbox stops sending immediately.'
}

function Test-MdoTenantHygiene {
    <# Mailbox auditing and DKIM signing - tenant-wide settings that underpin the rest. #>
    param([string] $Product)

    $org = Invoke-Safely -Label 'Get-OrganizationConfig' -Script { Get-OrganizationConfig -ErrorAction Stop }
    if ($org) {
        Add-Result -Product $Product -Category 'Tenant hygiene' -Setting 'Mailbox auditing' `
            -Status (Get-BoolState (Get-PropertyValue $org 'AuditDisabled') -InvertGood) `
            -Current ("AuditDisabled = $(Get-PropertyValue $org 'AuditDisabled')") -Expected 'AuditDisabled = False' `
            -Recommendation 'Keep mailbox auditing on. Without it you lose the forensic record after a BEC incident.'
    }
    else {
        Add-Result -Product $Product -Category 'Tenant hygiene' -Setting 'Mailbox auditing' `
            -Status 'Gray' -Current 'Could not read organization config' -Expected 'AuditDisabled = False' `
            -Recommendation 'Verify Exchange Online read permissions.'
    }

    $dkim = Invoke-Safely -Label 'Get-DkimSigningConfig' -Script { Get-DkimSigningConfig -ErrorAction Stop }
    if ($dkim) {
        $custom = @($dkim | Where-Object { $_.Domain -notmatch 'onmicrosoft\.com$' })
        if ($custom.Count -eq 0) { $custom = @($dkim) }
        $enabled = @($custom | Where-Object { $_.Enabled -eq $true }).Count

        Add-Result -Product $Product -Category 'Tenant hygiene' -Setting 'DKIM signing' `
            -Status (Get-CoverageState -Compliant $enabled -Total $custom.Count) `
            -Current ('Enabled on {0} of {1} custom domains' -f $enabled, $custom.Count) -Expected 'Enabled on all sending domains' `
            -Recommendation 'Enable DKIM on every custom sending domain. DMARC enforcement depends on it.'
    }
    else {
        Add-Result -Product $Product -Category 'Tenant hygiene' -Setting 'DKIM signing' `
            -Status 'Gray' -Current 'Could not read DKIM configuration' -Expected 'Enabled on all sending domains' `
            -Recommendation 'Verify Exchange Online read permissions.'
    }
}

#endregion

# =====================================================================================
# REGION: MODULE 6 - Microsoft Defender for Cloud Apps
# =====================================================================================
#region Defender for Cloud Apps

function Invoke-DefenderForCloudAppsChecks {
    $product = 'Defender for Cloud Apps'
    Write-Step -Message 'START Defender for Cloud Apps assessment' -State 'Start'

    if (Get-MgContext -ErrorAction SilentlyContinue) {
        Test-MdaCloudDiscovery    -Product $product
        Test-MdaConditionalAccess -Product $product
    }
    else {
        Add-ModuleFailure -Product $product -Reason 'No Microsoft Graph context available' `
            -Recommendation 'Run Connect-MgGraph with CloudApp-Discovery.Read.All and Policy.Read.All.'
    }

    Test-MdaLegacyApi -Product $product

    Write-Step -Message 'END Defender for Cloud Apps assessment' -State 'Done'
}

function Test-MdaCloudDiscovery {
    <# Cloud Discovery only works if log streams are actually arriving. #>
    param([string] $Product)

    $streams = Invoke-Safely -Label 'MDA uploaded streams' -Script {
        Invoke-GraphGet -Uri '/beta/security/dataDiscovery/cloudAppDiscovery/uploadedStreams'
    }

    if ($null -eq $streams) {
        Add-Result -Product $Product -Category 'Cloud Discovery' -Setting 'Discovery data streams' `
            -Status 'Gray' -Current 'Could not read cloudAppDiscovery/uploadedStreams' -Expected 'At least one continuous stream' `
            -Recommendation 'Grant CloudApp-Discovery.Read.All, or review Cloud Discovery in the Defender portal.'
        return
    }

    $total = @($streams).Count

    if ($total -eq 0) {
        Add-Result -Product $Product -Category 'Cloud Discovery' -Setting 'Discovery data streams' `
            -Status 'Red' -Current 'No discovery streams found' -Expected 'At least one continuous stream' `
            -Recommendation 'Enable the Defender for Endpoint integration for Cloud Discovery, or configure a log collector / firewall stream.'
        return
    }

    # The built-in "Win10 Endpoint Users" stream indicates the MDE integration is live.
    $mdeStream = @($streams | Where-Object { "$($_.displayName)" -match 'Win10|Endpoint' }).Count

    Add-Result -Product $Product -Category 'Cloud Discovery' -Setting 'Discovery data streams' `
        -Status 'Green' -Current ('{0} stream(s) present' -f $total) -Expected 'At least one continuous stream' `
        -Recommendation 'No action required.'

    $mdeStreamState   = 'Yellow'
    $mdeStreamCurrent = 'No endpoint-sourced stream detected'
    if ($mdeStream -gt 0) {
        $mdeStreamState   = 'Green'
        $mdeStreamCurrent = 'Endpoint-sourced stream present'
    }

    Add-Result -Product $Product -Category 'Cloud Discovery' -Setting 'Defender for Endpoint discovery integration' `
        -Status $mdeStreamState `
        -Current $mdeStreamCurrent `
        -Expected 'Endpoint-sourced discovery stream present' `
        -Recommendation 'Turn on the MDE integration in Settings > Cloud Apps > Microsoft Defender for Endpoint so roaming devices are covered without a log collector.'
}

function Test-MdaConditionalAccess {
    <# Session and access control depend on CA policies routing traffic through MDA. #>
    param([string] $Product)

    $policies = Invoke-Safely -Label 'Conditional Access policies (MDA)' -Script {
        Invoke-GraphGet -Uri '/v1.0/identity/conditionalAccess/policies'
    }

    if ($null -eq $policies) {
        Add-Result -Product $Product -Category 'App control' -Setting 'Conditional Access App Control' `
            -Status 'Gray' -Current 'Could not read Conditional Access policies' -Expected 'At least one enabled session policy using MDA' `
            -Recommendation 'Grant Policy.Read.All.'
        return
    }

    $mdaPolicies = @($policies | Where-Object {
        $null -ne (Get-PropertyValue (Get-PropertyValue $_ 'sessionControls') 'cloudAppSecurity')
    })

    $enabled    = @($mdaPolicies | Where-Object { $_.state -eq 'enabled' }).Count
    $reportOnly = @($mdaPolicies | Where-Object { $_.state -eq 'enabledForReportingButNotEnforced' }).Count

    if ($enabled -gt 0) {
        $state   = 'Green'
        $current = ('{0} enabled MDA session policy(ies)' -f $enabled)
    }
    elseif ($reportOnly -gt 0) {
        $state   = 'Yellow'
        $current = ('{0} MDA session policy(ies) in report-only' -f $reportOnly)
    }
    else {
        $state   = 'Red'
        $current = 'No Conditional Access App Control policy found'
    }

    Add-Result -Product $Product -Category 'App control' -Setting 'Conditional Access App Control' `
        -Status $state -Current $current -Expected 'At least one enabled session policy routing apps through MDA' `
        -Recommendation 'Create a Conditional Access policy with a Conditional Access App Control session control, then move it from report-only to enabled.'
}

function Test-MdaLegacyApi {
    <#
        Optional checks against the classic MDA REST API. Requires -MdaPortalUrl and
        -MdaApiToken. Without them these render Gray rather than falsely passing.
    #>
    param([string] $Product)

    if ([string]::IsNullOrWhiteSpace($MdaPortalUrl) -or [string]::IsNullOrWhiteSpace($MdaApiToken)) {
        Add-Result -Product $Product -Category 'Policy coverage' -Setting 'MDA policy inventory' `
            -Status 'Gray' -Current 'MDA API token not supplied' `
            -Expected 'Anomaly detection, file and activity policies in place' `
            -Recommendation 'Re-run with -MdaPortalUrl and -MdaApiToken to grade MDA policies, or review Policies in the Defender portal.'
        return
    }

    $base    = $MdaPortalUrl.TrimEnd('/')
    $headers = @{ Authorization = "Token $MdaApiToken"; 'Content-Type' = 'application/json' }

    $alerts = Invoke-Safely -Label 'MDA alerts' -Script {
        Invoke-RestMethod -Uri "$base/api/v1/alerts/" -Headers $headers -Method GET -ErrorAction Stop
    }

    if ($null -eq $alerts) {
        Add-Result -Product $Product -Category 'Policy coverage' -Setting 'MDA API connectivity' `
            -Status 'Gray' -Current 'MDA API call failed' -Expected 'API reachable' `
            -Recommendation 'Confirm the portal URL and that the API token is still valid.'
        return
    }

    Add-Result -Product $Product -Category 'Policy coverage' -Setting 'MDA API connectivity' `
        -Status 'Green' -Current 'API reachable' -Expected 'API reachable' -Recommendation 'No action required.'

    $openAlerts = Invoke-Safely -Label 'MDA open alerts' -Script {
        $body = @{ filters = @{ resolutionStatus = @{ eq = @(0) } }; limit = 1 } | ConvertTo-Json -Depth 6
        Invoke-RestMethod -Uri "$base/api/v1/alerts/" -Headers $headers -Method POST -Body $body -ErrorAction Stop
    }

    if ($openAlerts) {
        $count = [int](Get-PropertyValue $openAlerts 'total')

        $state = 'Red'
        if ($count -eq 0)      { $state = 'Green' }
        elseif ($count -le 25) { $state = 'Yellow' }

        Add-Result -Product $Product -Category 'Policy coverage' -Setting 'Open MDA alerts' `
            -Status $state -Current ('{0} open alert(s)' -f $count) -Expected 'Open alert backlog triaged' `
            -Recommendation 'Work the open alert queue. A large untouched backlog usually means policies are noisy and need tuning.'
    }
}

#endregion

# =====================================================================================
# REGION: MODULE 7 - Microsoft Purview
# =====================================================================================
#region Purview

function Invoke-PurviewChecks {
    $product = 'Microsoft Purview'
    Write-Step -Message 'START Microsoft Purview assessment' -State 'Start'

    # Audit is read from the Exchange Online session, everything else from the
    # Security & Compliance session. They are graded independently so one missing
    # session does not blank out the whole module.
    Test-PurviewAudit -Product $product

    if (-not (Test-CmdletAvailable -Name 'Get-DlpCompliancePolicy')) {
        Add-ModuleFailure -Product $product -Reason 'No Security & Compliance PowerShell session' `
            -Recommendation 'Run Connect-IPPSSession with a Compliance Administrator or Global Reader account. If token acquisition fails, re-run from a non-elevated console or use -DisableWam.'
        return
    }

    Test-PurviewDlp               -Product $product
    Test-PurviewRetention         -Product $product
    Test-PurviewRetentionLabels   -Product $product
    Test-PurviewSensitivityLabels -Product $product
    Test-PurviewInsiderRisk       -Product $product

    Write-Step -Message 'END Microsoft Purview assessment' -State 'Done'
}

function ConvertTo-DlpModeState {
    <#
        Maps a DLP policy Mode to a traffic light.
        Enable                   -> Green  (rules enforced)
        TestWithNotifications    -> Yellow (simulation, user is warned, nothing blocked)
        TestWithoutNotifications -> Yellow (silent simulation)
        Disable                  -> Red    (policy does nothing)
    #>
    param([string] $Mode)

    if ([string]::IsNullOrWhiteSpace($Mode)) { return 'Gray' }

    switch -Regex ($Mode) {
        '^(?i)enable$'                    { return 'Green' }
        '^(?i)testwithnotifications$'     { return 'Yellow' }
        '^(?i)testwithoutnotifications$'  { return 'Yellow' }
        '^(?i)(pendingdeletion|disable)$' { return 'Red' }
        default                           { return 'Gray' }
    }
}

function ConvertTo-RetentionModeState {
    <#
        Maps a retention policy Mode to a traffic light.
        Enforce        -> Green  (all aspects enabled and enforced)
        AuditAndNotify -> Yellow (matches notify, but the rule is not enforced)
        Test           -> Yellow (content tested, no rules enforced)
    #>
    param([string] $Mode)

    if ([string]::IsNullOrWhiteSpace($Mode)) { return 'Gray' }

    switch -Regex ($Mode) {
        '^(?i)enforce$'        { return 'Green' }
        '^(?i)auditandnotify$' { return 'Yellow' }
        '^(?i)test$'           { return 'Yellow' }
        default                { return 'Gray' }
    }
}

function Test-PurviewAudit {
    <#
        Unified audit log ingestion. This is the single most important Purview setting -
        with it off, Purview audit search, Search-UnifiedAuditLog, the Management
        Activity API and Sentinel all return nothing.

        IMPORTANT: Get-AdminAuditLogConfig must be run from the Exchange Online session.
        In Security & Compliance PowerShell the UnifiedAuditLogIngestionEnabled value is
        always False regardless of the real tenant state, which would produce a false Red.
    #>
    param([string] $Product)

    $exoSession = Invoke-Safely -Label 'EXO session check for audit' -Script { Get-ConnectionInformation -ErrorAction Stop }

    if (-not $exoSession) {
        Add-Result -Product $Product -Category 'Audit' -Setting 'Unified audit log ingestion' `
            -Status 'Gray' -Current 'No Exchange Online session to read audit config from' `
            -Expected 'UnifiedAuditLogIngestionEnabled = True' `
            -Recommendation 'Connect-ExchangeOnline is required. This value cannot be read reliably from Security & Compliance PowerShell.'
        return
    }

    $config = Invoke-Safely -Label 'Get-AdminAuditLogConfig' -Script { Get-AdminAuditLogConfig -ErrorAction Stop }

    if (-not $config) {
        Add-Result -Product $Product -Category 'Audit' -Setting 'Unified audit log ingestion' `
            -Status 'Gray' -Current 'Could not read Get-AdminAuditLogConfig' `
            -Expected 'UnifiedAuditLogIngestionEnabled = True' `
            -Recommendation 'The account needs the Audit Logs role in Exchange Online to read or change this.'
        return
    }

    $ingestion = Get-PropertyValue @($config)[0] 'UnifiedAuditLogIngestionEnabled'

    Add-Result -Product $Product -Category 'Audit' -Setting 'Unified audit log ingestion' `
        -Status (Get-BoolState $ingestion) `
        -Current ("UnifiedAuditLogIngestionEnabled = $ingestion") -Expected 'True' `
        -Recommendation 'Turn auditing on in the Purview portal, or run Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true. Without it there is no forensic record to investigate.'

    # Audit retention policies (Audit Premium / E5) extend retention beyond the default.
    if (Test-CmdletAvailable -Name 'Get-UnifiedAuditLogRetentionPolicy') {
        $retention = Invoke-Safely -Label 'Get-UnifiedAuditLogRetentionPolicy' -Script {
            Get-UnifiedAuditLogRetentionPolicy -ErrorAction Stop
        }

        if ($null -eq $retention) {
            Add-Result -Product $Product -Category 'Audit' -Setting 'Custom audit retention policy' `
                -Status 'Gray' -Current 'Could not read audit retention policies' `
                -Expected 'At least one policy retaining high-value activity beyond the default' `
                -Recommendation 'Verify the account holds an audit read role.'
        }
        else {
            $count   = @($retention).Count
            $enabled = @($retention | Where-Object { (Get-PropertyValue $_ 'Enabled') -ne $false }).Count

            if ($count -eq 0) {
                $state   = 'Yellow'
                $current = 'No custom audit retention policy (default retention only)'
                $rec     = 'Default retention may be shorter than your investigation window. Create an audit retention policy for high-value activities if you are licensed for it.'
            }
            else {
                $state   = Get-CoverageState -Compliant $enabled -Total $count
                $current = ('{0} of {1} audit retention policies enabled' -f $enabled, $count)
                $rec     = 'Confirm the retention duration matches your regulatory and investigation requirements.'
            }

            Add-Result -Product $Product -Category 'Audit' -Setting 'Custom audit retention policy' `
                -Status $state -Current $current `
                -Expected 'Retention aligned to your investigation window' -Recommendation $rec
        }
    }
    else {
        Add-Result -Product $Product -Category 'Audit' -Setting 'Custom audit retention policy' `
            -Status 'Gray' -Current 'Get-UnifiedAuditLogRetentionPolicy not available in this session' `
            -Expected 'Retention aligned to your investigation window' `
            -Recommendation 'This cmdlet requires Audit Premium licensing and a Security & Compliance session.'
    }
}

function Test-PurviewDlp {
    <# DLP policy modes, workload coverage and whether any rule actually blocks. #>
    param([string] $Product)

    $policies = Invoke-Safely -Label 'Get-DlpCompliancePolicy' -Script { Get-DlpCompliancePolicy -ErrorAction Stop }

    if ($null -eq $policies) {
        Add-Result -Product $Product -Category 'Data loss prevention' -Setting 'DLP policy inventory' `
            -Status 'Gray' -Current 'Could not read DLP policies' -Expected 'At least one enforced DLP policy' `
            -Recommendation 'Confirm the account holds a DLP read role such as View-Only DLP Compliance Management.'
        return
    }

    # Exclude policies already flagged for deletion from the coverage maths.
    $active = @($policies | Where-Object { (Get-PropertyValue $_ 'Mode') -ne 'PendingDeletion' })
    $total  = $active.Count

    if ($total -eq 0) {
        Add-Result -Product $Product -Category 'Data loss prevention' -Setting 'DLP policy inventory' `
            -Status 'Red' -Current 'No DLP policies configured' -Expected 'At least one enforced DLP policy' `
            -Recommendation 'Create a DLP policy in Purview > Data loss prevention. Start in TestWithNotifications, then move to Enable.'
        return
    }

    Write-Step -Message ('Found {0} DLP policies' -f $total) -State 'Info'

    $enforced   = @($active | Where-Object { (Get-PropertyValue $_ 'Mode') -eq 'Enable' }).Count
    $simulation = @($active | Where-Object { (Get-PropertyValue $_ 'Mode') -match '^(?i)testwith' }).Count
    $disabled   = @($active | Where-Object { (Get-PropertyValue $_ 'Mode') -eq 'Disable' }).Count

    if ($enforced -ge $total) {
        $state   = 'Green'
        $current = ('All {0} policies enforced' -f $total)
    }
    elseif (($enforced + $simulation) -gt 0) {
        $state   = 'Yellow'
        $current = ('{0} enforced, {1} in simulation, {2} disabled (of {3})' -f $enforced, $simulation, $disabled, $total)
    }
    else {
        $state   = 'Red'
        $current = ('All {0} policies disabled' -f $total)
    }

    Add-Result -Product $Product -Category 'Data loss prevention' -Setting 'DLP policy enforcement mode' `
        -Status $state -Current $current -Expected 'Mode = Enable' `
        -Recommendation 'Policies left in TestWithNotifications or TestWithoutNotifications detect but never block. Review simulation results, then switch Mode to Enable.'

    # Per-policy detail so you can see exactly which policy is stuck in simulation.
    foreach ($policy in $active) {
        $name = Get-PropertyValue $policy 'Name'
        $mode = Get-PropertyValue $policy 'Mode'

        Add-Result -Product $Product -Category 'DLP policy detail' -Setting ('Policy: {0}' -f $name) `
            -Status (ConvertTo-DlpModeState $mode) -Current ("Mode = $mode") -Expected 'Enable' `
            -Recommendation 'Move validated policies out of simulation into Enable so the configured actions take effect.'
    }

    # Workload coverage - a policy covering only Exchange leaves SPO/OneDrive/Teams/endpoints open.
    $workloads = @(
        @{ Property = 'ExchangeLocation';    Label = 'Exchange Online' }
        @{ Property = 'SharePointLocation';  Label = 'SharePoint Online' }
        @{ Property = 'OneDriveLocation';    Label = 'OneDrive for Business' }
        @{ Property = 'TeamsLocation';       Label = 'Teams chat and channel messages' }
        @{ Property = 'EndpointDlpLocation'; Label = 'Endpoint DLP (devices)' }
    )

    foreach ($workload in $workloads) {
        $covered = @($active | Where-Object {
            $value = Get-PropertyValue $_ $workload.Property
            $null -ne $value -and @($value).Count -gt 0
        }).Count

        $workloadState = 'Red'
        if ($covered -gt 0) { $workloadState = 'Green' }

        Add-Result -Product $Product -Category 'DLP coverage' -Setting ('DLP coverage: {0}' -f $workload.Label) `
            -Status $workloadState -Current ('Covered by {0} of {1} policies' -f $covered, $total) `
            -Expected 'At least one policy covering this location' `
            -Recommendation ('Add {0} as a location to a DLP policy, otherwise sensitive data can leave through that channel unchecked.' -f $workload.Label)
    }

    # Do any rules actually block, or is everything notify-only?
    if (Test-CmdletAvailable -Name 'Get-DlpComplianceRule') {
        $rules = Invoke-Safely -Label 'Get-DlpComplianceRule' -Script { Get-DlpComplianceRule -ErrorAction Stop }

        if ($null -eq $rules -or @($rules).Count -eq 0) {
            Add-Result -Product $Product -Category 'Data loss prevention' -Setting 'DLP rules with blocking action' `
                -Status 'Red' -Current 'No DLP rules found' -Expected 'At least one rule with BlockAccess enabled' `
                -Recommendation 'A DLP policy with no rules does nothing. Add rules defining the sensitive info types and the block action.'
        }
        else {
            $ruleTotal = @($rules).Count
            $blocking  = @($rules | Where-Object { (Get-PropertyValue $_ 'BlockAccess') -eq $true }).Count
            $notifying = @($rules | Where-Object {
                (Get-PropertyValue $_ 'NotifyUser') -or (Get-PropertyValue $_ 'GenerateAlert')
            }).Count

            if ($blocking -gt 0) {
                $ruleState   = 'Green'
                $ruleCurrent = ('{0} of {1} rules block access' -f $blocking, $ruleTotal)
            }
            elseif ($notifying -gt 0) {
                $ruleState   = 'Yellow'
                $ruleCurrent = ('0 blocking, {0} of {1} rules notify or alert only' -f $notifying, $ruleTotal)
            }
            else {
                $ruleState   = 'Red'
                $ruleCurrent = ('{0} rules, none block or notify' -f $ruleTotal)
            }

            Add-Result -Product $Product -Category 'Data loss prevention' -Setting 'DLP rules with blocking action' `
                -Status $ruleState -Current $ruleCurrent -Expected 'At least one rule with BlockAccess enabled' `
                -Recommendation 'Notify-only rules build awareness but stop nothing. Set BlockAccess on rules covering your highest-risk sensitive info types.'

            $incidentReports = @($rules | Where-Object { Get-PropertyValue $_ 'IncidentReportContent' }).Count
            Add-Result -Product $Product -Category 'Data loss prevention' -Setting 'DLP incident reports' `
                -Status (Get-CoverageState -Compliant $incidentReports -Total $ruleTotal) `
                -Current ('Incident report configured on {0} of {1} rules' -f $incidentReports, $ruleTotal) `
                -Expected 'Incident reports configured' `
                -Recommendation 'Configure incident reports so DLP matches reach the SOC rather than sitting only in the Purview portal.'
        }
    }
}

function Test-PurviewRetention {
    <# Retention policies for both the classic and the newer (app) locations. #>
    param([string] $Product)

    $policies = Invoke-Safely -Label 'Get-RetentionCompliancePolicy' -Script {
        Get-RetentionCompliancePolicy -ErrorAction Stop
    }

    if ($null -eq $policies) {
        Add-Result -Product $Product -Category 'Data lifecycle' -Setting 'Retention policy inventory' `
            -Status 'Gray' -Current 'Could not read retention policies' -Expected 'At least one enforced retention policy' `
            -Recommendation 'Confirm the account holds a retention management read role.'
        return
    }

    $total = @($policies).Count

    if ($total -eq 0) {
        Add-Result -Product $Product -Category 'Data lifecycle' -Setting 'Retention policy inventory' `
            -Status 'Red' -Current 'No retention policies configured' -Expected 'At least one enforced retention policy' `
            -Recommendation 'Create a retention policy in Purview > Data lifecycle management to meet your regulatory retention obligations.'
        return
    }

    Write-Step -Message ('Found {0} retention policies' -f $total) -State 'Info'

    $enabled = @($policies | Where-Object { (Get-PropertyValue $_ 'Enabled') -eq $true }).Count
    Add-Result -Product $Product -Category 'Data lifecycle' -Setting 'Retention policies enabled' `
        -Status (Get-CoverageState -Compliant $enabled -Total $total) `
        -Current ('{0} of {1} policies enabled' -f $enabled, $total) -Expected 'All policies enabled' `
        -Recommendation 'A disabled retention policy retains nothing. Enable or remove policies that are switched off.'

    $enforced = @($policies | Where-Object { (Get-PropertyValue $_ 'Mode') -eq 'Enforce' }).Count
    $testing  = @($policies | Where-Object { (Get-PropertyValue $_ 'Mode') -match '^(?i)(test|auditandnotify)$' }).Count

    if ($enforced -ge $total) {
        $modeState   = 'Green'
        $modeCurrent = ('All {0} policies enforcing' -f $total)
    }
    elseif (($enforced + $testing) -gt 0) {
        $modeState   = 'Yellow'
        $modeCurrent = ('{0} enforcing, {1} in test or audit-and-notify (of {2})' -f $enforced, $testing, $total)
    }
    else {
        $modeState   = 'Red'
        $modeCurrent = 'No policies in Enforce mode'
    }

    Add-Result -Product $Product -Category 'Data lifecycle' -Setting 'Retention policy mode' `
        -Status $modeState -Current $modeCurrent -Expected 'Mode = Enforce' `
        -Recommendation 'Test and AuditAndNotify modes evaluate content but do not enforce retention or deletion. Move validated policies to Enforce.'

    # Per-policy detail so you can see exactly which policy is stuck in test mode.
    foreach ($policy in $policies) {
        $policyName    = Get-PropertyValue $policy 'Name'
        $policyMode    = Get-PropertyValue $policy 'Mode'
        $policyEnabled = Get-PropertyValue $policy 'Enabled'

        # A disabled policy is Red no matter what mode it claims to be in.
        if ($policyEnabled -eq $false) {
            $detailState   = 'Red'
            $detailCurrent = "Enabled = False; Mode = $policyMode"
        }
        else {
            $detailState   = ConvertTo-RetentionModeState $policyMode
            $detailCurrent = "Enabled = True; Mode = $policyMode"
        }

        Add-Result -Product $Product -Category 'Retention policy detail' -Setting ('Policy: {0}' -f $policyName) `
            -Status $detailState -Current $detailCurrent -Expected 'Enabled = True; Mode = Enforce' `
            -Recommendation 'Move validated policies to Enforce so retention and deletion actually apply.'
    }

    # Distribution errors mean the policy exists but was never applied to its locations.
    $errored = @($policies | Where-Object {
        "$(Get-PropertyValue $_ 'DistributionStatus')" -match '(?i)error|fail'
    }).Count

    $distributionState = 'Red'
    if ($errored -eq 0) { $distributionState = 'Green' }

    Add-Result -Product $Product -Category 'Data lifecycle' -Setting 'Retention policy distribution' `
        -Status $distributionState -Current ('{0} of {1} policies report a distribution error' -f $errored, $total) `
        -Expected 'No distribution errors' `
        -Recommendation 'Re-run with Get-RetentionCompliancePolicy -DistributionDetail to see the DistributionResults detail. A policy that failed to distribute is not protecting anything.'

    # Newer locations (Teams private channels, Viva Engage, Copilot / AI app interactions)
    # use a separate cmdlet and are frequently missed entirely.
    if (Test-CmdletAvailable -Name 'Get-AppRetentionCompliancePolicy') {
        $appPolicies = Invoke-Safely -Label 'Get-AppRetentionCompliancePolicy' -Script {
            Get-AppRetentionCompliancePolicy -ErrorAction Stop
        }

        if ($null -eq $appPolicies) {
            Add-Result -Product $Product -Category 'Data lifecycle' -Setting 'Retention for newer locations' `
                -Status 'Gray' -Current 'Could not read app retention policies' `
                -Expected 'Coverage for Teams private channels, Viva Engage and Copilot/AI interactions' `
                -Recommendation 'Verify retention read permissions.'
        }
        else {
            $appTotal = @($appPolicies).Count

            $appState = 'Yellow'
            $appRec   = 'No app retention policies exist. Teams private channel messages, Viva Engage messages and Copilot/AI app interactions are retained by separate policies and are otherwise uncovered.'
            if ($appTotal -gt 0) {
                $appState = 'Green'
                $appRec   = 'Confirm the covered locations match where your users actually work.'
            }

            Add-Result -Product $Product -Category 'Data lifecycle' -Setting 'Retention for newer locations' `
                -Status $appState -Current ('{0} app retention policy(ies)' -f $appTotal) `
                -Expected 'Coverage for Teams private channels, Viva Engage and Copilot/AI interactions' `
                -Recommendation $appRec
        }
    }
}

function Test-PurviewRetentionLabels {
    <# Retention label storage, label inventory and publication. #>
    param([string] $Product)

    if (Test-CmdletAvailable -Name 'Get-ComplianceTagStorage') {
        $storage = Invoke-Safely -Label 'Get-ComplianceTagStorage' -Script { Get-ComplianceTagStorage -ErrorAction Stop }

        $storageState   = 'Red'
        $storageCurrent = 'Label storage not created'
        if ($storage) {
            $storageState   = 'Green'
            $storageCurrent = 'Label storage present'
        }

        Add-Result -Product $Product -Category 'Retention labels' -Setting 'Retention label storage created' `
            -Status $storageState `
            -Current $storageCurrent `
            -Expected 'Label storage created' `
            -Recommendation 'Run Enable-ComplianceTagStorage once. Retention labels cannot be used until this one-time storage exists.'
    }

    if (-not (Test-CmdletAvailable -Name 'Get-ComplianceTag')) {
        Add-Result -Product $Product -Category 'Retention labels' -Setting 'Retention label inventory' `
            -Status 'Gray' -Current 'Get-ComplianceTag not available in this session' `
            -Expected 'Retention labels defined and published' `
            -Recommendation 'Reconnect with Connect-IPPSSession using an account holding retention management rights.'
        return
    }

    $labels = Invoke-Safely -Label 'Get-ComplianceTag' -Script { Get-ComplianceTag -ErrorAction Stop }

    if ($null -eq $labels) {
        Add-Result -Product $Product -Category 'Retention labels' -Setting 'Retention label inventory' `
            -Status 'Gray' -Current 'Could not read retention labels' -Expected 'Retention labels defined and published' `
            -Recommendation 'Verify retention read permissions.'
        return
    }

    $total = @($labels).Count

    $labelState = 'Red'
    if ($total -gt 0) { $labelState = 'Green' }

    Add-Result -Product $Product -Category 'Retention labels' -Setting 'Retention label inventory' `
        -Status $labelState -Current ('{0} retention label(s) defined' -f $total) `
        -Expected 'Retention labels defined for your record classes' `
        -Recommendation 'Define retention labels for the record types your regulators care about, then publish or auto-apply them.'

    if ($total -gt 0) {
        # Regulatory / record labels cannot be removed by users - worth calling out.
        $recordLabels = @($labels | Where-Object {
            (Get-PropertyValue $_ 'IsRecordLabel') -eq $true -or (Get-PropertyValue $_ 'RetentionAction') -eq 'KeepAndDelete'
        }).Count

        $recordState = 'Yellow'
        if ($recordLabels -gt 0) { $recordState = 'Green' }

        Add-Result -Product $Product -Category 'Retention labels' -Setting 'Record / immutable labels' `
            -Status $recordState -Current ('{0} of {1} labels are record or keep-and-delete labels' -f $recordLabels, $total) `
            -Expected 'Record labels defined for regulated content' `
            -Recommendation 'Use record labels for content that must not be edited or deleted by users during its retention period.'
    }

    if (Test-CmdletAvailable -Name 'Get-RetentionComplianceRule') {
        $rules = Invoke-Safely -Label 'Get-RetentionComplianceRule' -Script { Get-RetentionComplianceRule -ErrorAction Stop }

        if ($null -eq $rules) {
            Add-Result -Product $Product -Category 'Retention labels' -Setting 'Retention rules defined' `
                -Status 'Gray' -Current 'Could not read retention rules' -Expected 'Every policy backed by a rule' `
                -Recommendation 'Verify retention read permissions.'
        }
        else {
            $ruleCount = @($rules).Count

            $ruleState = 'Red'
            if ($ruleCount -gt 0) { $ruleState = 'Green' }

            Add-Result -Product $Product -Category 'Retention labels' -Setting 'Retention rules defined' `
                -Status $ruleState -Current ('{0} retention rule(s)' -f $ruleCount) `
                -Expected 'Every retention policy backed by a rule' `
                -Recommendation 'A retention policy needs a rule to define the actual retain/delete settings. A policy with no rule is incomplete.'
        }
    }
}

function Test-PurviewSensitivityLabels {
    <# Sensitivity label inventory, protection settings and publication. #>
    param([string] $Product)

    if (-not (Test-CmdletAvailable -Name 'Get-Label')) {
        Add-Result -Product $Product -Category 'Information protection' -Setting 'Sensitivity label inventory' `
            -Status 'Gray' -Current 'Get-Label not available in this session' `
            -Expected 'Sensitivity labels defined and published' `
            -Recommendation 'Reconnect with Connect-IPPSSession using an account holding information protection rights.'
        return
    }

    $labels = Invoke-Safely -Label 'Get-Label' -Script { Get-Label -ErrorAction Stop }

    if ($null -eq $labels) {
        Add-Result -Product $Product -Category 'Information protection' -Setting 'Sensitivity label inventory' `
            -Status 'Gray' -Current 'Could not read sensitivity labels' -Expected 'Sensitivity labels defined and published' `
            -Recommendation 'Verify information protection read permissions.'
        return
    }

    $total = @($labels).Count

    if ($total -eq 0) {
        Add-Result -Product $Product -Category 'Information protection' -Setting 'Sensitivity label inventory' `
            -Status 'Red' -Current 'No sensitivity labels defined' -Expected 'Sensitivity labels defined and published' `
            -Recommendation 'Create a sensitivity label taxonomy in Purview > Information protection. Labels underpin encryption, marking and DLP conditions.'
        return
    }

    Write-Step -Message ('Found {0} sensitivity labels' -f $total) -State 'Info'

    $enabled = @($labels | Where-Object { (Get-PropertyValue $_ 'Disabled') -ne $true }).Count
    Add-Result -Product $Product -Category 'Information protection' -Setting 'Sensitivity label inventory' `
        -Status (Get-CoverageState -Compliant $enabled -Total $total) `
        -Current ('{0} of {1} labels enabled' -f $enabled, $total) -Expected 'Labels defined and enabled' `
        -Recommendation 'Remove or re-enable disabled labels so the taxonomy users see matches what you intend.'

    # Encryption is what actually protects the file once it leaves your tenant.
    $encrypting = @($labels | Where-Object {
        (Get-PropertyValue $_ 'EncryptionEnabled') -eq $true -or
        "$(Get-PropertyValue $_ 'EncryptionProtectionType')" -match '(?i)template|userdefined|donotforward'
    }).Count

    $encryptionState = 'Yellow'
    if ($encrypting -gt 0) { $encryptionState = 'Green' }

    Add-Result -Product $Product -Category 'Information protection' -Setting 'Labels applying encryption' `
        -Status $encryptionState -Current ('{0} of {1} labels apply encryption' -f $encrypting, $total) `
        -Expected 'Confidential tiers apply encryption' `
        -Recommendation 'Labels that only apply a visual marking do not protect content outside your tenant. Add encryption to your confidential and highly-confidential tiers.'

    # Content marking is the visible cue that drives user behaviour.
    $marking = @($labels | Where-Object {
        (Get-PropertyValue $_ 'ApplyContentMarkingHeaderEnabled') -eq $true -or
        (Get-PropertyValue $_ 'ApplyContentMarkingFooterEnabled') -eq $true -or
        (Get-PropertyValue $_ 'ApplyWaterMarkingEnabled') -eq $true
    }).Count

    $markingState = 'Yellow'
    if ($marking -gt 0) { $markingState = 'Green' }

    Add-Result -Product $Product -Category 'Information protection' -Setting 'Labels applying content marking' `
        -Status $markingState -Current ('{0} of {1} labels apply header, footer or watermark' -f $marking, $total) `
        -Expected 'Sensitive tiers apply visible marking' `
        -Recommendation 'Visible markings are a cheap behavioural control and make mishandled documents obvious in screenshots and printouts.'

    # Auto-labelling removes the dependency on users choosing correctly.
    $autoLabel = @($labels | Where-Object {
        (Get-PropertyValue $_ 'AutoLabelingEnabled') -eq $true -or
        (Get-PropertyValue $_ 'ApplyAutoLabelingEnabled') -eq $true
    }).Count

    $autoState = 'Yellow'
    if ($autoLabel -gt 0) { $autoState = 'Green' }

    Add-Result -Product $Product -Category 'Information protection' -Setting 'Automatic / recommended labelling' `
        -Status $autoState -Current ('{0} of {1} labels use automatic or recommended labelling' -f $autoLabel, $total) `
        -Expected 'Auto-labelling configured for known sensitive info types' `
        -Recommendation 'Manual-only labelling depends entirely on user diligence. Add auto-labelling conditions for your key sensitive info types.'

    # Label policies are what actually publish labels to users.
    if (Test-CmdletAvailable -Name 'Get-LabelPolicy') {
        $labelPolicies = Invoke-Safely -Label 'Get-LabelPolicy' -Script { Get-LabelPolicy -ErrorAction Stop }

        if ($null -eq $labelPolicies) {
            Add-Result -Product $Product -Category 'Information protection' -Setting 'Sensitivity label publication' `
                -Status 'Gray' -Current 'Could not read label policies' -Expected 'At least one label policy published' `
                -Recommendation 'Verify information protection read permissions.'
            return
        }

        $policyTotal = @($labelPolicies).Count

        $publishState = 'Red'
        if ($policyTotal -gt 0) { $publishState = 'Green' }

        Add-Result -Product $Product -Category 'Information protection' -Setting 'Sensitivity label publication' `
            -Status $publishState -Current ('{0} label policy(ies) published' -f $policyTotal) `
            -Expected 'At least one label policy published to users' `
            -Recommendation 'Labels that are never published are invisible to users. Publish them to the relevant groups.'

        if ($policyTotal -gt 0) {
            # Mandatory labelling and a default label sharply raise coverage.
            $mandatory = @($labelPolicies | Where-Object {
                "$(Get-PropertyValue $_ 'Settings')" -match '(?i)mandatory.*true'
            }).Count

            $mandatoryState = 'Yellow'
            if ($mandatory -gt 0) { $mandatoryState = 'Green' }

            Add-Result -Product $Product -Category 'Information protection' -Setting 'Mandatory labelling' `
                -Status $mandatoryState -Current ('Mandatory labelling detected in {0} of {1} policies' -f $mandatory, $policyTotal) `
                -Expected 'Mandatory labelling enabled' `
                -Recommendation 'Requiring a label on save or send is the single biggest driver of labelling coverage. Enable it once your taxonomy is stable.'

            $defaultLabel = @($labelPolicies | Where-Object {
                "$(Get-PropertyValue $_ 'Settings')" -match '(?i)defaultlabelid'
            }).Count

            $defaultState = 'Yellow'
            if ($defaultLabel -gt 0) { $defaultState = 'Green' }

            Add-Result -Product $Product -Category 'Information protection' -Setting 'Default label configured' `
                -Status $defaultState -Current ('Default label set in {0} of {1} policies' -f $defaultLabel, $policyTotal) `
                -Expected 'Default label configured' `
                -Recommendation 'A default label ensures new content starts classified rather than unlabelled.'
        }
    }
}

function Test-PurviewInsiderRisk {
    <#
        Insider Risk Management and Communication Compliance. Both are E5 / add-on
        features and their cmdlets are frequently absent, so each is gated on cmdlet
        availability and reports Gray rather than a misleading Red when unavailable.
    #>
    param([string] $Product)

    # ---- Insider Risk Management ----
    if (Test-CmdletAvailable -Name 'Get-InsiderRiskPolicy') {
        $irmPolicies = Invoke-Safely -Label 'Get-InsiderRiskPolicy' -Script { Get-InsiderRiskPolicy -ErrorAction Stop }

        if ($null -eq $irmPolicies) {
            Add-Result -Product $Product -Category 'Insider risk' -Setting 'Insider risk policies' `
                -Status 'Gray' -Current 'Could not read insider risk policies' -Expected 'At least one enabled policy' `
                -Recommendation 'Confirm the account holds an Insider Risk Management role.'
        }
        else {
            $irmTotal = @($irmPolicies).Count

            $irmState = 'Red'
            if ($irmTotal -gt 0) { $irmState = 'Green' }

            Add-Result -Product $Product -Category 'Insider risk' -Setting 'Insider risk policies' `
                -Status $irmState -Current ('{0} insider risk policy(ies)' -f $irmTotal) `
                -Expected 'At least one enabled policy' `
                -Recommendation 'Create insider risk policies for departing-employee data theft and sensitive data leak scenarios - the two highest-value starting templates.'
        }
    }
    else {
        Add-Result -Product $Product -Category 'Insider risk' -Setting 'Insider risk policies' `
            -Status 'Gray' -Current 'Insider risk cmdlets not available in this session' `
            -Expected 'At least one enabled policy' `
            -Recommendation 'Insider Risk Management requires E5 or the Compliance add-on plus an Insider Risk Management role. Review in the Purview portal.'
    }

    # ---- Communication Compliance ----
    $ccCmdlet = @('Get-SupervisoryReviewPolicyV2', 'Get-SupervisoryReviewPolicy') |
                    Where-Object { Test-CmdletAvailable -Name $_ } |
                    Select-Object -First 1

    if ($ccCmdlet) {
        $ccPolicies = Invoke-Safely -Label $ccCmdlet -Script {
            & $ccCmdlet -ErrorAction Stop
        }

        if ($null -eq $ccPolicies) {
            Add-Result -Product $Product -Category 'Communication compliance' -Setting 'Communication compliance policies' `
                -Status 'Gray' -Current 'Could not read communication compliance policies' `
                -Expected 'At least one active policy' `
                -Recommendation 'Confirm the account holds a Communication Compliance role.'
        }
        else {
            $ccTotal = @($ccPolicies).Count

            $ccState = 'Yellow'
            if ($ccTotal -gt 0) { $ccState = 'Green' }

            Add-Result -Product $Product -Category 'Communication compliance' -Setting 'Communication compliance policies' `
                -Status $ccState -Current ('{0} policy(ies) configured' -f $ccTotal) `
                -Expected 'At least one active policy' `
                -Recommendation 'Communication compliance policies detect harassment, regulatory breaches and sensitive info sharing in Teams and email.'
        }
    }
    else {
        Add-Result -Product $Product -Category 'Communication compliance' -Setting 'Communication compliance policies' `
            -Status 'Gray' -Current 'Communication compliance cmdlets not available in this session' `
            -Expected 'At least one active policy' `
            -Recommendation 'Communication Compliance requires E5 or the Compliance add-on plus the relevant role. Review in the Purview portal.'
    }
}

#endregion

# =====================================================================================
# REGION: HTML report generation
# =====================================================================================
#region Reporting

function New-HtmlReport {
    <#
        Renders a fully self-contained HTML report - no external CSS, fonts or scripts,
        so it can be emailed or archived as a single file.

        THEMING: every colour is a CSS variable defined on :root and overridden wholesale
        by [data-theme="dark"]. A small inline script in <head> applies the saved (or
        system-preferred) theme BEFORE the body paints, so the report never flashes
        white and then snaps to dark. The choice persists in localStorage, and printing
        always forces the light palette regardless of the on-screen theme.
    #>
    param(
        [Parameter(Mandatory)][object[]] $Data,
        [Parameter(Mandatory)][string]   $Path
    )

    $green  = @($Data | Where-Object Status -eq 'Green').Count
    $yellow = @($Data | Where-Object Status -eq 'Yellow').Count
    $red    = @($Data | Where-Object Status -eq 'Red').Count
    $gray   = @($Data | Where-Object Status -eq 'Gray').Count
    $scored = $green + $yellow + $red

    $scorePercent = 0
    if ($scored -gt 0) {
        $scorePercent = [math]::Round(((($green * $script:StateWeight.Green) + ($yellow * $script:StateWeight.Yellow)) / ($scored * $script:StateWeight.Green)) * 100, 1)
    }

    $scoreClass = 'bad'
    if ($scorePercent -ge 80)     { $scoreClass = 'ok' }
    elseif ($scorePercent -ge 55) { $scoreClass = 'warn' }

    $generated = $script:StartTime.ToString('yyyy-MM-dd HH:mm:ss')
    $duration  = [math]::Round(((Get-Date) - $script:StartTime).TotalSeconds, 0)

    $sb = [System.Text.StringBuilder]::new()

    $head = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Microsoft Entra, Defender &amp; Purview Best Practice Report</title>
<style>
  :root {
    --green:#107c10; --green-bg:#dff6dd;
    --yellow:#9d5d00; --yellow-bg:#fff4ce;
    --red:#a80000;   --red-bg:#fde7e9;
    --gray:#5c5c5c;  --gray-bg:#f0f0f0;
    --ink:#1b1b1b;   --muted:#616161;
    --line:#e1e1e1;  --card:#ffffff;  --page:#f5f6f8;
    --th-bg:#fafafa; --td-line:#f0f0f0; --cur-ink:#333333;
    --hdr-a:#0f2a4a; --hdr-b:#12457a;
    --accent:#12457a;
  }
  [data-theme="dark"] {
    --green:#6ccb70; --green-bg:#12321a;
    --yellow:#ffcf4d; --yellow-bg:#3a2f0b;
    --red:#ff8a8a;   --red-bg:#3d1519;
    --gray:#b8b8b8;  --gray-bg:#2c2c2e;
    --ink:#e8e8ea;   --muted:#a2a2a8;
    --line:#3a3a3d;  --card:#252528;  --page:#1a1a1c;
    --th-bg:#2b2b2e; --td-line:#333336; --cur-ink:#d6d6da;
    --hdr-a:#0a1c33; --hdr-b:#0e3159;
    --accent:#4a9eff;
  }
  * { box-sizing:border-box; }
  body { margin:0; padding:0 0 48px; background:var(--page); color:var(--ink);
         font-family:'Segoe UI',-apple-system,BlinkMacSystemFont,Roboto,Helvetica,Arial,sans-serif;
         font-size:14px; line-height:1.5;
         transition:background-color .2s ease, color .2s ease; }
  header { background:linear-gradient(135deg,var(--hdr-a) 0%,var(--hdr-b) 100%); color:#fff; padding:28px 32px; }
  header h1 { margin:0 0 6px; font-size:24px; font-weight:600; }
  header .meta { font-size:13px; opacity:.85; }
  .wrap { max-width:1500px; margin:0 auto; padding:0 32px; }
  .cards { display:flex; flex-wrap:wrap; gap:16px; margin:24px 0; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:8px;
          padding:18px 22px; min-width:160px; flex:1; box-shadow:0 1px 3px rgba(0,0,0,.05); }
  .card .n { font-size:30px; font-weight:600; line-height:1.1; }
  .card .l { font-size:12px; text-transform:uppercase; letter-spacing:.6px; color:var(--muted); margin-top:4px; }
  .card.g .n { color:var(--green); } .card.y .n { color:var(--yellow); }
  .card.r .n { color:var(--red); }   .card.x .n { color:var(--gray); }
  .card.score .n.ok { color:var(--green); }
  .card.score .n.warn { color:var(--yellow); }
  .card.score .n.bad { color:var(--red); }
  .bar { display:flex; height:12px; border-radius:6px; overflow:hidden; margin:4px 0 24px; border:1px solid var(--line); }
  .bar span { display:block; height:100%; }
  .bar .g { background:var(--green); } .bar .y { background:#ffb900; }
  .bar .r { background:var(--red); }   .bar .x { background:var(--gray); }
  .controls { display:flex; flex-wrap:wrap; gap:10px; align-items:center; margin-bottom:20px; }
  .controls input { padding:8px 12px; border:1px solid var(--line); border-radius:6px;
                    min-width:280px; font-size:14px; background:var(--card); color:var(--ink); }
  .btn { cursor:pointer; border:1px solid var(--line); background:var(--card); border-radius:16px;
         padding:6px 14px; font-size:13px; color:var(--ink); }
  .btn.active { background:var(--accent); color:#fff; border-color:var(--accent); }
  .theme-toggle { margin-left:auto; display:inline-flex; align-items:center; gap:7px; }
  h2 { font-size:18px; margin:30px 0 4px; padding-bottom:8px; border-bottom:2px solid var(--line); }
  h2 .pill { font-size:12px; font-weight:400; color:var(--muted); margin-left:10px; }
  table { width:100%; border-collapse:collapse; background:var(--card);
          border:1px solid var(--line); border-radius:8px; overflow:hidden; margin-bottom:8px; }
  th { text-align:left; background:var(--th-bg); font-size:12px; text-transform:uppercase;
       letter-spacing:.5px; color:var(--muted); padding:10px 12px; border-bottom:1px solid var(--line); }
  td { padding:10px 12px; border-bottom:1px solid var(--td-line); vertical-align:top; }
  tr:last-child td { border-bottom:none; }
  tr.Green  td:first-child { border-left:4px solid var(--green); }
  tr.Yellow td:first-child { border-left:4px solid var(--yellow); }
  tr.Red    td:first-child { border-left:4px solid var(--red); }
  tr.Gray   td:first-child { border-left:4px solid var(--gray); }
  .st { display:inline-block; padding:3px 10px; border-radius:12px; font-size:12px; font-weight:600; white-space:nowrap; }
  .st.Green  { background:var(--green-bg);  color:var(--green); }
  .st.Yellow { background:var(--yellow-bg); color:var(--yellow); }
  .st.Red    { background:var(--red-bg);    color:var(--red); }
  .st.Gray   { background:var(--gray-bg);   color:var(--gray); }
  .cat { font-weight:600; color:var(--accent); }
  .cur { font-family:Consolas,'Courier New',monospace; font-size:12.5px; color:var(--cur-ink); word-break:break-word; }
  .rec { color:var(--muted); font-size:13px; }
  .scope { font-size:11px; color:var(--muted); }
  footer { text-align:center; color:var(--muted); font-size:12px; margin-top:36px; }
  .legend { display:flex; gap:18px; flex-wrap:wrap; font-size:12.5px; color:var(--muted); margin-bottom:18px; }
  @media print {
    .controls { display:none; }
    /* Always print on white, whatever the on-screen theme is. */
    html, body, [data-theme="dark"] {
      --ink:#1b1b1b; --muted:#616161; --line:#e1e1e1; --card:#ffffff; --page:#ffffff;
      --th-bg:#fafafa; --td-line:#f0f0f0; --cur-ink:#333333; --accent:#12457a;
      --green:#107c10; --green-bg:#dff6dd; --yellow:#9d5d00; --yellow-bg:#fff4ce;
      --red:#a80000; --red-bg:#fde7e9; --gray:#5c5c5c; --gray-bg:#f0f0f0;
      background:#fff;
    }
  }
</style>
<script>
// Apply the saved (or system-preferred) theme BEFORE the body renders, so the
// page never flashes light then snaps to dark.
(function () {
  try {
    var saved = localStorage.getItem('dbpr-theme');
    if (!saved) {
      saved = (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) ? 'dark' : 'light';
    }
    document.documentElement.setAttribute('data-theme', saved);
  } catch (e) {
    document.documentElement.setAttribute('data-theme', 'light');
  }
})();
</script>
</head>
<body>
'@
    [void]$sb.Append($head)

    # ---- Header and summary ----
    $tenantSafe = ConvertTo-HtmlSafe $script:TenantLabel

    [void]$sb.Append(@"
<header>
  <h1>Microsoft Entra, Defender &amp; Purview Best Practice Report</h1>
  <div class="meta">Tenant: $tenantSafe &nbsp;|&nbsp; Generated: $generated &nbsp;|&nbsp; Runtime: ${duration}s &nbsp;|&nbsp; Cloud: $Cloud</div>
</header>
<div class="wrap">
  <div class="cards">
    <div class="card score"><div class="n $scoreClass">$scorePercent%</div><div class="l">Weighted score</div></div>
    <div class="card g"><div class="n">$green</div><div class="l">Green - compliant</div></div>
    <div class="card y"><div class="n">$yellow</div><div class="l">Yellow - partial</div></div>
    <div class="card r"><div class="n">$red</div><div class="l">Red - not configured</div></div>
    <div class="card x"><div class="n">$gray</div><div class="l">Gray - not evaluated</div></div>
  </div>
"@)

    $totalAll = $green + $yellow + $red + $gray
    if ($totalAll -gt 0) {
        $gw = [math]::Round(($green / $totalAll) * 100, 2)
        $yw = [math]::Round(($yellow / $totalAll) * 100, 2)
        $rw = [math]::Round(($red / $totalAll) * 100, 2)
        $xw = [math]::Round(($gray / $totalAll) * 100, 2)
        [void]$sb.Append("<div class=`"bar`"><span class=`"g`" style=`"width:$gw%`"></span><span class=`"y`" style=`"width:$yw%`"></span><span class=`"r`" style=`"width:$rw%`"></span><span class=`"x`" style=`"width:$xw%`"></span></div>")
    }

    [void]$sb.Append(@'
  <div class="legend">
    <span><strong>Green</strong> - enabled / enforced / blocking</span>
    <span><strong>Yellow</strong> - partial: audit or warn mode, simulation, report-only, lower tier, or only some objects compliant</span>
    <span><strong>Red</strong> - off, missing, or not configured</span>
    <span><strong>Gray</strong> - could not be evaluated (permissions, module, licensing, or workload skipped)</span>
  </div>
  <div class="controls">
    <input type="text" id="q" placeholder="Filter by setting, category or recommendation..." oninput="applyFilters()" />
    <button class="btn active" data-f="All" onclick="setFilter(this)">All</button>
    <button class="btn" data-f="Green" onclick="setFilter(this)">Green</button>
    <button class="btn" data-f="Yellow" onclick="setFilter(this)">Yellow</button>
    <button class="btn" data-f="Red" onclick="setFilter(this)">Red</button>
    <button class="btn" data-f="Gray" onclick="setFilter(this)">Gray</button>
    <button class="btn theme-toggle" id="themeBtn" onclick="toggleTheme()" title="Switch between light and dark">
      <span id="themeIcon">&#9789;</span><span id="themeLabel">Dark</span>
    </button>
  </div>
'@)

    # ---- Per-product tables ----
    $productOrder = @(
        'Microsoft Entra ID', 'Defender for Cloud', 'Defender for Endpoint',
        'Defender for Identity', 'Defender for Office 365', 'Defender for Cloud Apps',
        'Microsoft Purview'
    )
    $present = $Data | Select-Object -ExpandProperty Product -Unique
    $ordered = @($productOrder | Where-Object { $present -contains $_ }) +
               @($present | Where-Object { $productOrder -notcontains $_ })

    foreach ($product in $ordered) {
        $rows = @($Data | Where-Object Product -eq $product)
        $pg = @($rows | Where-Object Status -eq 'Green').Count
        $py = @($rows | Where-Object Status -eq 'Yellow').Count
        $pr = @($rows | Where-Object Status -eq 'Red').Count
        $px = @($rows | Where-Object Status -eq 'Gray').Count

        $productSafe = ConvertTo-HtmlSafe $product

        [void]$sb.Append("<h2>$productSafe<span class=`"pill`">$($rows.Count) checks &middot; $pg green &middot; $py yellow &middot; $pr red &middot; $px gray</span></h2>")
        [void]$sb.Append('<table><thead><tr><th style="width:22%">Setting</th><th style="width:12%">Category</th><th style="width:9%">Status</th><th style="width:19%">Current value</th><th style="width:13%">Expected</th><th style="width:25%">Recommendation</th></tr></thead><tbody>')

        $sortRank = @{ Red = 0; Yellow = 1; Gray = 2; Green = 3 }
        $sorted = $rows | Sort-Object @{ Expression = { $sortRank[$_.Status] } }, Category, Setting

        foreach ($row in $sorted) {
            $setting = ConvertTo-HtmlSafe $row.Setting
            if ($row.Scope) {
                $scopeSafe = ConvertTo-HtmlSafe $row.Scope
                $setting += "<div class=`"scope`">$scopeSafe</div>"
            }

            $catText = ConvertTo-HtmlSafe $row.Category
            $curText = ConvertTo-HtmlSafe $row.Current
            $expText = ConvertTo-HtmlSafe $row.Expected
            $recText = ConvertTo-HtmlSafe $row.Recommendation

            $template = "<tr class=`"{0}`" data-status=`"{0}`"><td>{1}</td><td class=`"cat`">{2}</td><td><span class=`"st {0}`">{0}</span></td><td class=`"cur`">{3}</td><td class=`"cur`">{4}</td><td class=`"rec`">{5}</td></tr>"
            [void]$sb.Append(($template -f $row.Status, $setting, $catText, $curText, $expText, $recText))
        }
        [void]$sb.Append('</tbody></table>')
    }

    [void]$sb.Append(@"
  <footer>Generated by Invoke-DefenderBestPracticeReport.ps1 &middot; $generated &middot; Read-only assessment - no tenant changes were made.</footer>
</div>
<script>
var currentFilter = 'All';

function setFilter(btn) {
  currentFilter = btn.getAttribute('data-f');
  // Scope to status buttons only, so the theme toggle keeps its own styling.
  document.querySelectorAll('.btn[data-f]').forEach(function (b) { b.classList.remove('active'); });
  btn.classList.add('active');
  applyFilters();
}

function applyFilters() {
  var term = document.getElementById('q').value.toLowerCase();
  document.querySelectorAll('tbody tr').forEach(function (tr) {
    var statusOk = (currentFilter === 'All') || (tr.getAttribute('data-status') === currentFilter);
    var textOk = (term === '') || (tr.innerText.toLowerCase().indexOf(term) !== -1);
    tr.style.display = (statusOk && textOk) ? '' : 'none';
  });
}

function applyThemeLabel(theme) {
  var icon = document.getElementById('themeIcon');
  var label = document.getElementById('themeLabel');
  if (theme === 'dark') {
    icon.innerHTML = '&#9788;';   // sun - click to go back to light
    label.textContent = 'Light';
  } else {
    icon.innerHTML = '&#9789;';   // moon - click to go dark
    label.textContent = 'Dark';
  }
}

function toggleTheme() {
  var current = document.documentElement.getAttribute('data-theme') || 'light';
  var next = (current === 'dark') ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  try { localStorage.setItem('dbpr-theme', next); } catch (e) { }
  applyThemeLabel(next);
}

applyThemeLabel(document.documentElement.getAttribute('data-theme') || 'light');
</script>
</body>
</html>
"@)

    $sb.ToString() | Out-File -FilePath $Path -Encoding utf8 -Force
}

#endregion

# =====================================================================================
# REGION: MAIN
# =====================================================================================
#region Main

Write-Host ''
Write-Host '============================================================' -ForegroundColor DarkCyan
Write-Host ' Microsoft Entra, Defender & Purview Best Practice Assessment' -ForegroundColor White
Write-Host '============================================================' -ForegroundColor DarkCyan
Write-Host ''

# Default the output folder to wherever this script lives. $PSScriptRoot is empty when
# the code is pasted straight into a console or dot-sourced from elsewhere, so fall back
# to the current working directory in that case.
if ([string]::IsNullOrWhiteSpace($OutputFolder)) {
    $OutputFolder = $PSScriptRoot
    if ([string]::IsNullOrWhiteSpace($OutputFolder)) {
        $OutputFolder = (Get-Location).Path
    }
}

if (-not (Test-Path -LiteralPath $OutputFolder)) {
    New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null
}

Write-Host (' Output folder: {0}' -f $OutputFolder) -ForegroundColor DarkGray
Write-Host ''

if ($TenantId) { $script:TenantLabel = $TenantId }

if (-not $SkipModuleCheck) {
    Test-ModulePrerequisites -Requested $Modules | Out-Null
}

Connect-Workloads -Requested $Modules

if ($Modules -contains 'Entra')                { Invoke-EntraChecks }
if ($Modules -contains 'DefenderForCloud')     { Invoke-DefenderForCloudChecks }
if ($Modules -contains 'DefenderForEndpoint')  { Invoke-DefenderForEndpointChecks }
if ($Modules -contains 'DefenderForIdentity')  { Invoke-DefenderForIdentityChecks }
if ($Modules -contains 'DefenderForOffice')    { Invoke-DefenderForOfficeChecks }
if ($Modules -contains 'DefenderForCloudApps') { Invoke-DefenderForCloudAppsChecks }
if ($Modules -contains 'Purview')              { Invoke-PurviewChecks }

$data = $script:Results.ToArray()

if ($data.Count -eq 0) {
    Write-Step -Message 'No results were produced. Check connectivity and permissions.' -State 'Fail'
    return
}

$stamp    = $script:StartTime.ToString('yyyyMMdd-HHmmss')
$htmlPath = Join-Path $OutputFolder "DefenderBestPractice-$stamp.html"
$csvPath  = Join-Path $OutputFolder "DefenderBestPractice-$stamp.csv"
$jsonPath = Join-Path $OutputFolder "DefenderBestPractice-$stamp.json"

New-HtmlReport -Data $data -Path $htmlPath
$data | Export-Csv -Path $csvPath -NoTypeInformation -Encoding utf8
$data | ConvertTo-Json -Depth 5 | Out-File -FilePath $jsonPath -Encoding utf8

Write-Host ''
Write-Host '------------------------------------------------------------' -ForegroundColor DarkCyan
Write-Host (' Green : {0}' -f @($data | Where-Object Status -eq 'Green').Count)  -ForegroundColor Green
Write-Host (' Yellow: {0}' -f @($data | Where-Object Status -eq 'Yellow').Count) -ForegroundColor Yellow
Write-Host (' Red   : {0}' -f @($data | Where-Object Status -eq 'Red').Count)    -ForegroundColor Red
Write-Host (' Gray  : {0}' -f @($data | Where-Object Status -eq 'Gray').Count)   -ForegroundColor DarkGray
Write-Host '------------------------------------------------------------' -ForegroundColor DarkCyan
Write-Host ''
Write-Host (' HTML : {0}' -f $htmlPath) -ForegroundColor White
Write-Host (' CSV  : {0}' -f $csvPath)  -ForegroundColor White
Write-Host (' JSON : {0}' -f $jsonPath) -ForegroundColor White
Write-Host ''

Invoke-Safely -Label 'Open report' -Script { Start-Process $htmlPath } | Out-Null

#endregion
