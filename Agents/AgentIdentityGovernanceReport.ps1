<#
.SYNOPSIS
    Agent Identity Governance Report for Microsoft Entra Agent ID / Agent 365.

.DESCRIPTION
    Discovers Agent Identities as service principals where:
        servicePrincipalType eq 'ServiceIdentity'

    Reports:
      - Agent identity inventory
      - Best-effort assigned agent/package match
      - Owners
      - Sponsors
      - Application permissions
      - Delegated permission grants
      - Entra role assignments
      - Directory audit activity

    Sign-in log collection has been intentionally removed from this version.

    Output: four CSV files plus an on-screen summary table.

.NOTES
    Recommended delegated Graph scopes:
      Application.Read.All
      Directory.Read.All
      AuditLog.Read.All
      RoleManagement.Read.Directory

    Optional package lookup scope:
      CopilotPackages.Read.All

    IMPORTANT:
      All identity properties are read through Get-ObjectPropertyValue instead of
      direct dot notation. Agent Identity objects do not always return every
      property (for example createdDateTime), and Set-StrictMode throws on a
      missing property when accessed directly.
#>

[CmdletBinding()]
param(
    [string]$OutputFolder = "C:\Tools\Agents\Reports",

    [int]$UsageLookbackDays = 30,

    [switch]$SkipPackageLookup,

    [switch]$NoDisconnect
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# =====================================================================
# REGION: Logging helpers
# =====================================================================

function Write-LogStart {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [string]$Detail = ""
    )

    if ([string]::IsNullOrWhiteSpace($Detail)) {
        Write-Host "[START] $Name" -ForegroundColor Cyan
    }
    else {
        Write-Host "[START] $Name - $Detail" -ForegroundColor Cyan
    }
}

function Write-LogStop {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [string]$Detail = ""
    )

    if ([string]::IsNullOrWhiteSpace($Detail)) {
        Write-Host "[STOP ] $Name" -ForegroundColor Green
    }
    else {
        Write-Host "[STOP ] $Name - $Detail" -ForegroundColor Green
    }
}

function Write-LogInfo {
    param(
        [Parameter(Mandatory)]
        [string]$Message
    )

    Write-Host "[INFO ] $Message" -ForegroundColor Gray
}

function Write-LogWarn {
    param(
        [Parameter(Mandatory)]
        [string]$Message
    )

    Write-Warning $Message
}

# =====================================================================
# REGION: Generic helpers
#
# Get-ObjectPropertyValue is the safe way to read any property from a
# Graph object or hashtable. It returns $null when the property is not
# present instead of throwing under Set-StrictMode.
# =====================================================================

function Get-ObjectPropertyValue {
    param(
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$PropertyName
    )

    if ($null -eq $InputObject) {
        return $null
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.ContainsKey($PropertyName)) {
            return $InputObject[$PropertyName]
        }

        return $null
    }

    $property = $InputObject.PSObject.Properties[$PropertyName]

    if ($property) {
        return $property.Value
    }

    return $null
}

function Get-ObjectPropertyText {
    param(
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$PropertyName
    )

    $value = Get-ObjectPropertyValue -InputObject $InputObject -PropertyName $PropertyName

    if ($null -eq $value) {
        return ""
    }

    return [string]$value
}

function Join-UniqueText {
    param(
        [object[]]$Values
    )

    if (-not $Values) {
        return ""
    }

    $cleanValues = foreach ($value in $Values) {
        if (-not [string]::IsNullOrWhiteSpace([string]$value)) {
            [string]$value
        }
    }

    if (-not $cleanValues) {
        return ""
    }

    return (($cleanValues | Sort-Object -Unique) -join "; ")
}

function ConvertTo-UrlEncodedText {
    param(
        [Parameter(Mandatory)]
        [string]$Value
    )

    return [System.Net.WebUtility]::UrlEncode($Value)
}

# =====================================================================
# REGION: Graph request wrappers
# =====================================================================

function Invoke-GraphGetAll {
    param(
        [Parameter(Mandatory)]
        [string]$Uri
    )

    $items = @()
    $nextUri = $Uri

    while (-not [string]::IsNullOrWhiteSpace($nextUri)) {
        $response = Invoke-MgGraphRequest -Method GET -Uri $nextUri

        $value = Get-ObjectPropertyValue -InputObject $response -PropertyName "value"

        if ($value) {
            $items += @($value)
        }
        else {
            if ($response) {
                $items += $response
            }

            break
        }

        $nextUri = Get-ObjectPropertyValue -InputObject $response -PropertyName "@odata.nextLink"
    }

    return $items
}

function Invoke-GraphGetAllSafe {
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [string]$FailureMessage = "Graph request failed."
    )

    try {
        return Invoke-GraphGetAll -Uri $Uri
    }
    catch {
        Write-LogWarn "$FailureMessage Error: $($_.Exception.Message)"
        return @()
    }
}

function Invoke-GraphGetOneSafe {
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [string]$FailureMessage = "Graph request failed."
    )

    try {
        return Invoke-MgGraphRequest -Method GET -Uri $Uri
    }
    catch {
        Write-LogWarn "$FailureMessage Error: $($_.Exception.Message)"
        return $null
    }
}

# =====================================================================
# REGION: Graph connection
# =====================================================================

function Connect-GraphForReport {
    param(
        [switch]$IncludePackageScope
    )

    Write-LogStart -Name "Connect-GraphForReport"

    $scopes = @(
        "Application.Read.All",
        "Directory.Read.All",
        "AuditLog.Read.All",
        "RoleManagement.Read.Directory"
    )

    if ($IncludePackageScope) {
        $scopes += "CopilotPackages.Read.All"
    }

    $context = Get-MgContext -ErrorAction SilentlyContinue

    if (-not $context) {
        Write-LogInfo "No active Graph context. Connecting."
        Connect-MgGraph -Scopes $scopes -NoWelcome
        Write-LogStop -Name "Connect-GraphForReport" -Detail "Connected"
        return
    }

    $missingScopes = $scopes | Where-Object { $_ -notin $context.Scopes }

    if ($missingScopes) {
        Write-LogInfo "Missing scope(s): $($missingScopes -join ', ')"
        Connect-MgGraph -Scopes $scopes -NoWelcome
        Write-LogStop -Name "Connect-GraphForReport" -Detail "Reconnected"
        return
    }

    Write-LogStop -Name "Connect-GraphForReport" -Detail "Existing context is sufficient"
}

# =====================================================================
# REGION: Agent identity discovery
#
# Uses a raw Graph call rather than Get-MgServicePrincipal so the
# returned objects are plain hashtables. Every property is then read
# safely, which avoids missing-property failures such as createdDateTime.
# =====================================================================

function Get-AgentIdentityServicePrincipal {
    Write-LogStart -Name "Get-AgentIdentityServicePrincipal"

    $filterText = "servicePrincipalType eq 'ServiceIdentity'"
    $filter = ConvertTo-UrlEncodedText -Value $filterText

    $uri = "https://graph.microsoft.com/v1.0/servicePrincipals?" + '$filter=' + $filter + '&$select=id,appId,displayName,servicePrincipalType,accountEnabled,createdDateTime&$top=999'

    $identities = Invoke-GraphGetAllSafe `
        -Uri $uri `
        -FailureMessage "Unable to enumerate Agent Identity service principals."

    Write-LogStop -Name "Get-AgentIdentityServicePrincipal" -Detail "Found $(@($identities).Count) object(s)"
    return $identities
}

function Get-RelationshipDisplayText {
    param(
        [Parameter(Mandatory)]
        [string]$ServicePrincipalId,

        [Parameter(Mandatory)]
        [ValidateSet("owners", "sponsors")]
        [string]$RelationshipName
    )

    Write-LogStart -Name "Get-RelationshipDisplayText" -Detail "Relationship=$($RelationshipName); Sp=$($ServicePrincipalId)"

    $uri = "https://graph.microsoft.com/v1.0/servicePrincipals/$ServicePrincipalId/$RelationshipName" + '?$select=id,displayName,userPrincipalName,mail'

    $objects = Invoke-GraphGetAllSafe `
        -Uri $uri `
        -FailureMessage "Unable to read relationship [$($RelationshipName)] for service principal [$($ServicePrincipalId)]."

    $names = foreach ($object in $objects) {
        $displayName = Get-ObjectPropertyText -InputObject $object -PropertyName "displayName"
        $upn = Get-ObjectPropertyText -InputObject $object -PropertyName "userPrincipalName"
        $mail = Get-ObjectPropertyText -InputObject $object -PropertyName "mail"
        $id = Get-ObjectPropertyText -InputObject $object -PropertyName "id"

        if ($displayName -and $upn) {
            "$displayName <$upn>"
        }
        elseif ($displayName -and $mail) {
            "$displayName <$mail>"
        }
        elseif ($displayName) {
            $displayName
        }
        elseif ($upn) {
            $upn
        }
        elseif ($mail) {
            $mail
        }
        elseif ($id) {
            $id
        }
    }

    $result = Join-UniqueText -Values $names

    Write-LogStop -Name "Get-RelationshipDisplayText" -Detail "Relationship=$($RelationshipName); Count=$(@($objects).Count)"
    return $result
}

# =====================================================================
# REGION: Permissions
# =====================================================================

function Get-AgentApplicationPermission {
    param(
        [Parameter(Mandatory)]
        [string]$ServicePrincipalId
    )

    Write-LogStart -Name "Get-AgentApplicationPermission" -Detail "Sp=$($ServicePrincipalId)"

    $uri = "https://graph.microsoft.com/v1.0/servicePrincipals/$ServicePrincipalId/appRoleAssignments"

    $assignments = Invoke-GraphGetAllSafe `
        -Uri $uri `
        -FailureMessage "Unable to read application permissions for service principal [$($ServicePrincipalId)]."

    if (-not $assignments -or @($assignments).Count -eq 0) {
        Write-LogStop -Name "Get-AgentApplicationPermission" -Detail "None found"
        return @()
    }

    $resourceCache = @{}
    $rows = @()

    foreach ($assignment in $assignments) {
        $resourceId = Get-ObjectPropertyText -InputObject $assignment -PropertyName "resourceId"
        $appRoleId = Get-ObjectPropertyText -InputObject $assignment -PropertyName "appRoleId"

        $resource = $null

        if (-not [string]::IsNullOrWhiteSpace($resourceId)) {
            if (-not $resourceCache.ContainsKey($resourceId)) {
                $resourceUri = "https://graph.microsoft.com/v1.0/servicePrincipals/$resourceId" + '?$select=id,appId,displayName,appRoles'

                $resourceCache[$resourceId] = Invoke-GraphGetOneSafe `
                    -Uri $resourceUri `
                    -FailureMessage "Unable to resolve resource service principal [$($resourceId)]."
            }

            $resource = $resourceCache[$resourceId]
        }

        $resourceDisplayName = Get-ObjectPropertyText -InputObject $assignment -PropertyName "resourceDisplayName"
        $resourceAppId = ""
        $permissionValue = ""
        $permissionDisplayName = ""

        if ($resource) {
            $resourceDisplayNameFromSp = Get-ObjectPropertyText -InputObject $resource -PropertyName "displayName"
            $resourceAppId = Get-ObjectPropertyText -InputObject $resource -PropertyName "appId"

            if ($resourceDisplayNameFromSp) {
                $resourceDisplayName = $resourceDisplayNameFromSp
            }

            $appRoles = Get-ObjectPropertyValue -InputObject $resource -PropertyName "appRoles"

            if ($appRoles) {
                foreach ($role in $appRoles) {
                    $roleId = Get-ObjectPropertyText -InputObject $role -PropertyName "id"

                    if ($roleId -eq $appRoleId) {
                        $permissionValue = Get-ObjectPropertyText -InputObject $role -PropertyName "value"
                        $permissionDisplayName = Get-ObjectPropertyText -InputObject $role -PropertyName "displayName"
                        break
                    }
                }
            }
        }

        $rows += [pscustomobject]@{
            PermissionType        = "Application"
            ResourceDisplayName   = $resourceDisplayName
            ResourceId            = $resourceId
            ResourceAppId         = $resourceAppId
            PermissionValue       = $permissionValue
            PermissionDisplayName = $permissionDisplayName
            AppRoleId             = $appRoleId
            PrincipalId           = Get-ObjectPropertyText -InputObject $assignment -PropertyName "principalId"
            PrincipalDisplayName  = Get-ObjectPropertyText -InputObject $assignment -PropertyName "principalDisplayName"
            CreatedDateTime       = Get-ObjectPropertyText -InputObject $assignment -PropertyName "createdDateTime"
        }
    }

    Write-LogStop -Name "Get-AgentApplicationPermission" -Detail "Found=$(@($rows).Count)"
    return $rows
}

function Get-AgentDelegatedPermission {
    param(
        [Parameter(Mandatory)]
        [string]$ServicePrincipalId
    )

    Write-LogStart -Name "Get-AgentDelegatedPermission" -Detail "Sp=$($ServicePrincipalId)"

    $filterText = "clientId eq '$ServicePrincipalId'"
    $filter = ConvertTo-UrlEncodedText -Value $filterText
    $uri = "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?" + '$filter=' + $filter

    $grants = Invoke-GraphGetAllSafe `
        -Uri $uri `
        -FailureMessage "Unable to read delegated permission grants for service principal [$($ServicePrincipalId)]."

    if (-not $grants -or @($grants).Count -eq 0) {
        Write-LogStop -Name "Get-AgentDelegatedPermission" -Detail "None found"
        return @()
    }

    $resourceCache = @{}
    $rows = @()

    foreach ($grant in $grants) {
        $resourceId = Get-ObjectPropertyText -InputObject $grant -PropertyName "resourceId"
        $resource = $null

        if (-not [string]::IsNullOrWhiteSpace($resourceId)) {
            if (-not $resourceCache.ContainsKey($resourceId)) {
                $resourceUri = "https://graph.microsoft.com/v1.0/servicePrincipals/$resourceId" + '?$select=id,appId,displayName'

                $resourceCache[$resourceId] = Invoke-GraphGetOneSafe `
                    -Uri $resourceUri `
                    -FailureMessage "Unable to resolve delegated permission resource service principal [$($resourceId)]."
            }

            $resource = $resourceCache[$resourceId]
        }

        $resourceDisplayName = ""
        $resourceAppId = ""

        if ($resource) {
            $resourceDisplayName = Get-ObjectPropertyText -InputObject $resource -PropertyName "displayName"
            $resourceAppId = Get-ObjectPropertyText -InputObject $resource -PropertyName "appId"
        }

        $rows += [pscustomobject]@{
            PermissionType      = "Delegated"
            ResourceDisplayName = $resourceDisplayName
            ResourceId          = $resourceId
            ResourceAppId       = $resourceAppId
            Scope               = Get-ObjectPropertyText -InputObject $grant -PropertyName "scope"
            ConsentType         = Get-ObjectPropertyText -InputObject $grant -PropertyName "consentType"
            ClientId            = Get-ObjectPropertyText -InputObject $grant -PropertyName "clientId"
            PrincipalId         = Get-ObjectPropertyText -InputObject $grant -PropertyName "principalId"
            GrantId             = Get-ObjectPropertyText -InputObject $grant -PropertyName "id"
        }
    }

    Write-LogStop -Name "Get-AgentDelegatedPermission" -Detail "Found=$(@($rows).Count)"
    return $rows
}

# =====================================================================
# REGION: Entra directory roles
# =====================================================================

function Get-AgentDirectoryRole {
    param(
        [Parameter(Mandatory)]
        [string]$PrincipalId
    )

    Write-LogStart -Name "Get-AgentDirectoryRole" -Detail "Principal=$($PrincipalId)"

    $filterText = "principalId eq '$PrincipalId'"
    $filter = ConvertTo-UrlEncodedText -Value $filterText
    $uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?" + '$filter=' + $filter + '&$expand=roleDefinition'

    $assignments = Invoke-GraphGetAllSafe `
        -Uri $uri `
        -FailureMessage "Unable to read Entra role assignments for principal [$($PrincipalId)]."

    if (-not $assignments -or @($assignments).Count -eq 0) {
        Write-LogStop -Name "Get-AgentDirectoryRole" -Detail "None found"
        return @()
    }

    $rows = @()

    foreach ($assignment in $assignments) {
        $roleDefinition = Get-ObjectPropertyValue -InputObject $assignment -PropertyName "roleDefinition"

        $roleDisplayName = ""

        if ($roleDefinition) {
            $roleDisplayName = Get-ObjectPropertyText -InputObject $roleDefinition -PropertyName "displayName"
        }

        $rows += [pscustomobject]@{
            RoleAssignmentId = Get-ObjectPropertyText -InputObject $assignment -PropertyName "id"
            RoleDefinitionId = Get-ObjectPropertyText -InputObject $assignment -PropertyName "roleDefinitionId"
            RoleDisplayName  = $roleDisplayName
            DirectoryScopeId = Get-ObjectPropertyText -InputObject $assignment -PropertyName "directoryScopeId"
            PrincipalId      = Get-ObjectPropertyText -InputObject $assignment -PropertyName "principalId"
        }
    }

    Write-LogStop -Name "Get-AgentDirectoryRole" -Detail "Found=$(@($rows).Count)"
    return $rows
}

# =====================================================================
# REGION: Usage - directory audit activity only
#         (sign-in log collection removed by design)
# =====================================================================

function Get-AgentAuditUsage {
    param(
        [Parameter(Mandatory)]
        [string]$ServicePrincipalId,

        [Parameter(Mandatory)]
        [int]$LookbackDays
    )

    Write-LogStart -Name "Get-AgentAuditUsage" -Detail "Sp=$($ServicePrincipalId); Days=$($LookbackDays)"

    $startUtc = (Get-Date).ToUniversalTime().AddDays(-1 * $LookbackDays).ToString("yyyy-MM-ddTHH:mm:ssZ")
    $filterText = "activityDateTime ge $startUtc and targetResources/any(t:t/id eq '$ServicePrincipalId')"
    $filter = ConvertTo-UrlEncodedText -Value $filterText
    $uri = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?" + '$filter=' + $filter + '&$top=100'

    $audits = Invoke-GraphGetAllSafe `
        -Uri $uri `
        -FailureMessage "Unable to read directory audit logs for service principal [$($ServicePrincipalId)]."

    $last = $null

    if ($audits -and @($audits).Count -gt 0) {
        $last = $audits |
            Sort-Object { Get-ObjectPropertyText -InputObject $_ -PropertyName "activityDateTime" } -Descending |
            Select-Object -First 1
    }

    $lastDateTime = ""
    $lastActivity = ""
    $lastCategory = ""
    $initiatedByText = ""

    if ($last) {
        $lastDateTime = Get-ObjectPropertyText -InputObject $last -PropertyName "activityDateTime"
        $lastActivity = Get-ObjectPropertyText -InputObject $last -PropertyName "activityDisplayName"
        $lastCategory = Get-ObjectPropertyText -InputObject $last -PropertyName "category"

        $initiatedBy = Get-ObjectPropertyValue -InputObject $last -PropertyName "initiatedBy"

        if ($initiatedBy) {
            $initiatedByUser = Get-ObjectPropertyValue -InputObject $initiatedBy -PropertyName "user"
            $initiatedByApp = Get-ObjectPropertyValue -InputObject $initiatedBy -PropertyName "app"

            if ($initiatedByUser) {
                $initiatedByText = Get-ObjectPropertyText -InputObject $initiatedByUser -PropertyName "userPrincipalName"
            }
            elseif ($initiatedByApp) {
                $initiatedByText = Get-ObjectPropertyText -InputObject $initiatedByApp -PropertyName "displayName"
            }
        }
    }

    $result = [pscustomobject]@{
        AuditEventCount      = @($audits).Count
        LastAuditDateTime    = $lastDateTime
        LastAuditActivity    = $lastActivity
        LastAuditCategory    = $lastCategory
        LastAuditInitiatedBy = $initiatedByText
    }

    Write-LogStop -Name "Get-AgentAuditUsage" -Detail "AuditEvents=$($result.AuditEventCount)"
    return $result
}

# =====================================================================
# REGION: Optional agent package correlation
# =====================================================================

function Get-AgentPackage {
    param(
        [switch]$Skip
    )

    Write-LogStart -Name "Get-AgentPackage"

    if ($Skip) {
        Write-LogInfo "Package lookup skipped by parameter."
        Write-LogStop -Name "Get-AgentPackage" -Detail "Skipped"
        return @()
    }

    $uri = "https://graph.microsoft.com/v1.0/copilot/admin/catalog/packages"

    $packages = Invoke-GraphGetAllSafe `
        -Uri $uri `
        -FailureMessage "Unable to read Copilot or Agent 365 package catalog. Use -SkipPackageLookup if unavailable."

    Write-LogStop -Name "Get-AgentPackage" -Detail "Packages=$(@($packages).Count)"
    return $packages
}

function Find-AgentPackageMatch {
    param(
        [string]$IdentityDisplayName,

        [string]$IdentityAppId,

        [string]$IdentityObjectId,

        [object[]]$Packages
    )

    Write-LogStart -Name "Find-AgentPackageMatch" -Detail "Identity=$($IdentityDisplayName)"

    if (-not $Packages -or @($Packages).Count -eq 0) {
        $result = [pscustomobject]@{
            AgentAssigned     = "Unknown"
            AgentPackageName  = ""
            AgentPackageId    = ""
            AgentPackageAppId = ""
            MatchReason       = "Package lookup unavailable or skipped"
        }

        Write-LogStop -Name "Find-AgentPackageMatch" -Detail $result.MatchReason
        return $result
    }

    $matchedPackage = $null
    $matchReason = ""

    foreach ($package in $Packages) {
        $packageId = Get-ObjectPropertyText -InputObject $package -PropertyName "id"
        $packageAppId = Get-ObjectPropertyText -InputObject $package -PropertyName "appId"
        $packageName = Get-ObjectPropertyText -InputObject $package -PropertyName "displayName"

        if (-not $packageName) {
            $packageName = Get-ObjectPropertyText -InputObject $package -PropertyName "name"
        }

        if ($IdentityAppId -and $packageAppId -and $IdentityAppId -eq $packageAppId) {
            $matchedPackage = $package
            $matchReason = "Matched by AppId"
            break
        }

        if ($IdentityDisplayName -and $packageName -and $IdentityDisplayName -eq $packageName) {
            $matchedPackage = $package
            $matchReason = "Matched by displayName"
            break
        }

        if ($IdentityObjectId -and $packageId -and $IdentityObjectId -eq $packageId) {
            $matchedPackage = $package
            $matchReason = "Matched by object id or package id"
            break
        }
    }

    if (-not $matchedPackage) {
        $result = [pscustomobject]@{
            AgentAssigned     = "Not found"
            AgentPackageName  = ""
            AgentPackageId    = ""
            AgentPackageAppId = ""
            MatchReason       = "No package match by AppId, displayName, or id"
        }

        Write-LogStop -Name "Find-AgentPackageMatch" -Detail $result.MatchReason
        return $result
    }

    $matchedName = Get-ObjectPropertyText -InputObject $matchedPackage -PropertyName "displayName"

    if (-not $matchedName) {
        $matchedName = Get-ObjectPropertyText -InputObject $matchedPackage -PropertyName "name"
    }

    $result = [pscustomobject]@{
        AgentAssigned     = "Matched"
        AgentPackageName  = $matchedName
        AgentPackageId    = Get-ObjectPropertyText -InputObject $matchedPackage -PropertyName "id"
        AgentPackageAppId = Get-ObjectPropertyText -InputObject $matchedPackage -PropertyName "appId"
        MatchReason       = $matchReason
    }

    Write-LogStop -Name "Find-AgentPackageMatch" -Detail $result.MatchReason
    return $result
}

# =====================================================================
# REGION: Main
# =====================================================================

try {
    Write-LogStart -Name "Main"

    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        throw "Microsoft Graph PowerShell SDK is not installed. Install with: Install-Module Microsoft.Graph -Scope CurrentUser"
    }

    if (-not (Test-Path -Path $OutputFolder)) {
        Write-LogInfo "Creating output folder: $OutputFolder"
        New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null
    }

    if ($SkipPackageLookup) {
        Connect-GraphForReport
    }
    else {
        Connect-GraphForReport -IncludePackageScope
    }

    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

    $summaryPath     = Join-Path $OutputFolder "AgentIdentity-Governance-Summary-$timestamp.csv"
    $permissionsPath = Join-Path $OutputFolder "AgentIdentity-Governance-Permissions-$timestamp.csv"
    $rolesPath       = Join-Path $OutputFolder "AgentIdentity-Governance-EntraRoles-$timestamp.csv"
    $usagePath       = Join-Path $OutputFolder "AgentIdentity-Governance-Usage-$timestamp.csv"

    $agentIdentities = Get-AgentIdentityServicePrincipal
    $packages = Get-AgentPackage -Skip:$SkipPackageLookup

    $summaryRows    = @()
    $permissionRows = @()
    $roleRows       = @()
    $usageRows      = @()

    foreach ($identity in $agentIdentities) {

        # Read every identity property safely. Agent Identity objects do not
        # always return createdDateTime or accountEnabled.
        $identityId          = Get-ObjectPropertyText -InputObject $identity -PropertyName "id"
        $identityAppId       = Get-ObjectPropertyText -InputObject $identity -PropertyName "appId"
        $identityDisplayName = Get-ObjectPropertyText -InputObject $identity -PropertyName "displayName"
        $identitySpType      = Get-ObjectPropertyText -InputObject $identity -PropertyName "servicePrincipalType"
        $identityEnabled     = Get-ObjectPropertyText -InputObject $identity -PropertyName "accountEnabled"
        $identityCreated     = Get-ObjectPropertyText -InputObject $identity -PropertyName "createdDateTime"

        if ([string]::IsNullOrWhiteSpace($identityId)) {
            Write-LogWarn "Skipping an object with no id value."
            continue
        }

        Write-LogStart -Name "Process Agent Identity" -Detail "$($identityDisplayName) [$($identityId)]"

        $owners   = Get-RelationshipDisplayText -ServicePrincipalId $identityId -RelationshipName "owners"
        $sponsors = Get-RelationshipDisplayText -ServicePrincipalId $identityId -RelationshipName "sponsors"

        $applicationPermissions = Get-AgentApplicationPermission -ServicePrincipalId $identityId
        $delegatedPermissions   = Get-AgentDelegatedPermission -ServicePrincipalId $identityId
        $roles                  = Get-AgentDirectoryRole -PrincipalId $identityId
        $auditUsage             = Get-AgentAuditUsage -ServicePrincipalId $identityId -LookbackDays $UsageLookbackDays

        $agentMatch = Find-AgentPackageMatch `
            -IdentityDisplayName $identityDisplayName `
            -IdentityAppId $identityAppId `
            -IdentityObjectId $identityId `
            -Packages $packages

        $permissionSummaryItems = @()

        foreach ($permission in $applicationPermissions) {
            if ($permission.PermissionValue) {
                $permissionSummaryItems += "$($permission.ResourceDisplayName):$($permission.PermissionValue)"
            }
            elseif ($permission.PermissionDisplayName) {
                $permissionSummaryItems += "$($permission.ResourceDisplayName):$($permission.PermissionDisplayName)"
            }
            elseif ($permission.AppRoleId) {
                $permissionSummaryItems += "$($permission.ResourceDisplayName):$($permission.AppRoleId)"
            }
        }

        foreach ($permission in $delegatedPermissions) {
            if ($permission.Scope) {
                $permissionSummaryItems += "$($permission.ResourceDisplayName):$($permission.Scope)"
            }
        }

        $roleSummaryItems = @()

        foreach ($role in $roles) {
            $roleSummaryItems += $role.RoleDisplayName
        }

        $summaryRows += [pscustomobject]@{
            AgentIdentityName       = $identityDisplayName
            AgentIdentityObjectId   = $identityId
            AgentIdentityAppId      = $identityAppId
            ServicePrincipalType    = $identitySpType
            AccountEnabled          = $identityEnabled
            CreatedDateTime         = $identityCreated
            Owners                  = $owners
            Sponsors                = $sponsors
            AgentAssigned           = $agentMatch.AgentAssigned
            AgentPackageName        = $agentMatch.AgentPackageName
            AgentPackageId          = $agentMatch.AgentPackageId
            AgentPackageAppId       = $agentMatch.AgentPackageAppId
            AgentPackageMatchReason = $agentMatch.MatchReason
            ApplicationGrantCount   = @($applicationPermissions).Count
            DelegatedGrantCount     = @($delegatedPermissions).Count
            PermissionSummary       = Join-UniqueText -Values $permissionSummaryItems
            EntraRoleCount          = @($roles).Count
            EntraRoles              = Join-UniqueText -Values $roleSummaryItems
            UsageLookbackDays       = $UsageLookbackDays
            AuditEventCount         = $auditUsage.AuditEventCount
            LastAuditDateTime       = $auditUsage.LastAuditDateTime
            LastAuditActivity       = $auditUsage.LastAuditActivity
            LastAuditCategory       = $auditUsage.LastAuditCategory
            LastAuditInitiatedBy    = $auditUsage.LastAuditInitiatedBy
        }

        foreach ($permission in $applicationPermissions) {
            $permissionRows += [pscustomobject]@{
                AgentIdentityName     = $identityDisplayName
                AgentIdentityObjectId = $identityId
                AgentIdentityAppId    = $identityAppId
                PermissionType        = $permission.PermissionType
                ResourceDisplayName   = $permission.ResourceDisplayName
                ResourceId            = $permission.ResourceId
                ResourceAppId         = $permission.ResourceAppId
                PermissionValue       = $permission.PermissionValue
                PermissionDisplayName = $permission.PermissionDisplayName
                Scope                 = ""
                ConsentType           = ""
                AppRoleId             = $permission.AppRoleId
                CreatedDateTime       = $permission.CreatedDateTime
            }
        }

        foreach ($permission in $delegatedPermissions) {
            $permissionRows += [pscustomobject]@{
                AgentIdentityName     = $identityDisplayName
                AgentIdentityObjectId = $identityId
                AgentIdentityAppId    = $identityAppId
                PermissionType        = $permission.PermissionType
                ResourceDisplayName   = $permission.ResourceDisplayName
                ResourceId            = $permission.ResourceId
                ResourceAppId         = $permission.ResourceAppId
                PermissionValue       = ""
                PermissionDisplayName = ""
                Scope                 = $permission.Scope
                ConsentType           = $permission.ConsentType
                AppRoleId             = ""
                CreatedDateTime       = ""
            }
        }

        foreach ($role in $roles) {
            $roleRows += [pscustomobject]@{
                AgentIdentityName     = $identityDisplayName
                AgentIdentityObjectId = $identityId
                AgentIdentityAppId    = $identityAppId
                RoleDisplayName       = $role.RoleDisplayName
                RoleDefinitionId      = $role.RoleDefinitionId
                RoleAssignmentId      = $role.RoleAssignmentId
                DirectoryScopeId      = $role.DirectoryScopeId
            }
        }

        $usageRows += [pscustomobject]@{
            AgentIdentityName     = $identityDisplayName
            AgentIdentityObjectId = $identityId
            AgentIdentityAppId    = $identityAppId
            UsageLookbackDays     = $UsageLookbackDays
            AuditEventCount       = $auditUsage.AuditEventCount
            LastAuditDateTime     = $auditUsage.LastAuditDateTime
            LastAuditActivity     = $auditUsage.LastAuditActivity
            LastAuditCategory     = $auditUsage.LastAuditCategory
            LastAuditInitiatedBy  = $auditUsage.LastAuditInitiatedBy
        }

        Write-LogStop -Name "Process Agent Identity" -Detail "$($identityDisplayName)"
    }

    Write-LogStart -Name "Export CSV files"

    $summaryRows |
        Sort-Object AgentIdentityName |
        Export-Csv -Path $summaryPath -NoTypeInformation -Encoding UTF8

    $permissionRows |
        Sort-Object AgentIdentityName, PermissionType, ResourceDisplayName |
        Export-Csv -Path $permissionsPath -NoTypeInformation -Encoding UTF8

    $roleRows |
        Sort-Object AgentIdentityName, RoleDisplayName |
        Export-Csv -Path $rolesPath -NoTypeInformation -Encoding UTF8

    $usageRows |
        Sort-Object AgentIdentityName |
        Export-Csv -Path $usagePath -NoTypeInformation -Encoding UTF8

    Write-LogStop -Name "Export CSV files"

    Write-Host ""
    Write-Host "Report complete." -ForegroundColor Green
    Write-Host "Summary:     $summaryPath"
    Write-Host "Permissions: $permissionsPath"
    Write-Host "Entra roles: $rolesPath"
    Write-Host "Usage:       $usagePath"
    Write-Host ""

    $summaryRows |
        Sort-Object AgentIdentityName |
        Format-Table AgentIdentityName, ServicePrincipalType, AgentAssigned, ApplicationGrantCount, DelegatedGrantCount, EntraRoleCount, AuditEventCount, LastAuditDateTime -AutoSize

    Write-LogStop -Name "Main" -Detail "Completed successfully"
}
finally {
    if (-not $NoDisconnect) {
        try {
            Disconnect-MgGraph | Out-Null
        }
        catch {
            Write-LogWarn "Disconnect-MgGraph failed. $($_.Exception.Message)"
        }
    }
}
