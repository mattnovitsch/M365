# ==============================
# CONFIG
# ==============================
$TenantId     = "<tenantid>"
$ClientId     = "<clientid>"
$ClientSecret = "<clientsecret>"
$Thumbprint = "<certificateThumbprint>"
$Organization = "<Tenantname>.onmicrosoft.com"

# ==============================
# GRAPH AUTH
# ==============================
$body = @{
    grant_type    = "client_credentials"
    scope         = "https://graph.microsoft.com/.default"
    client_id     = $ClientId
    client_secret = $ClientSecret
}

$tokenResponse = Invoke-RestMethod -Method Post `
    -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
    -Body $body

$graphToken = $tokenResponse.access_token

$graphHeaders = @{
    Authorization = "Bearer $graphToken"
    "Content-Type" = "application/json"
}

# ==============================
# PRELOAD GROUPS
# ==============================
Write-Host "Preloading Entra groups from Graph..."

$allGroups = @()
$uri = "https://graph.microsoft.com/v1.0/groups?`$select=id,displayName&`$top=999"

do {
    $response = Invoke-RestMethod -Headers $graphHeaders -Uri $uri
    $allGroups += $response.value
    $uri = $response.'@odata.nextLink'
} while ($uri)

Write-Host "Total groups loaded:" $allGroups.Count

# Build lookup
$groupLookup = @{}

foreach ($group in $allGroups) {

    if (-not $group.displayName -or -not $group.id) { continue }

    $name = $group.displayName.ToLower().Trim()

    if (-not $groupLookup.ContainsKey($name)) {
        $groupLookup[$name] = @()
    }

    $groupLookup[$name] += $group.id
}

# ==============================
# CONNECT TO PURVIEW
# ==============================
Write-Host "Connecting to Purview..."
Import-Module ExchangeOnlineManagement

Write-Host "Connecting to Purview (App-only with certificate)..."

Connect-IPPSSession `
    -AppId $ClientId `
    -CertificateThumbprint $Thumbprint `
    -Organization $Organization `
    -CommandName * `
    -ShowBanner:$false

# ==============================
# STEP 1: GET DLP POLICIES
# ==============================
Write-Host "Pulling DLP policies from Purview..."

$policyGroupMap = @()
$dlpPolicies = Get-DlpCompliancePolicy

$locationProperties = @(
    "ExchangeLocation",
    "ExchangeLocationException",
    "SharePointLocation",
    "SharePointLocationException",
    "OneDriveLocation",
    "OneDriveLocationException",
    "TeamsLocation",
    "TeamsLocationException",
    "EndpointDlpLocation",
    "EndpointDlpLocationException"
)

foreach ($policy in $dlpPolicies) {

    foreach ($prop in $locationProperties) {

        $values = $policy.$prop
        if (-not $values) { continue }

        foreach ($loc in $values) {

            if ($loc -is [string]) {
	    $raw = $loc
	}
	elseif ($loc.PSObject.Properties["DisplayName"]) {
	    $raw = $loc.DisplayName
	}
	elseif ($loc.PSObject.Properties["Name"]) {
	    $raw = $loc.Name
	}
	else {
	    $raw = $loc.ToString()
	}

            $scopeType = if ($prop -like "*Exception") { "Exclude" } else { "Include" }

            if ($raw -match "^[0-9a-fA-F-]{36}$") {

                $policyGroupMap += [PSCustomObject]@{
                    PolicyName = $policy.Name
                    PolicyType = "DLP"
                    ScopeType  = $scopeType
                    GroupId    = $raw
                }
            }
            else {
                $normalized = $raw.ToLower().Trim()

                if ($groupLookup.ContainsKey($normalized)) {

                    foreach ($gid in $groupLookup[$normalized]) {

                        $policyGroupMap += [PSCustomObject]@{
                            PolicyName = $policy.Name
                            PolicyType = "DLP"
                            ScopeType  = $scopeType
                            GroupId    = $gid
                        }
                    }
                }
                else {
                    Write-Warning "Group not found in preload: $raw"
                }
            }
        }
    }
}

Write-Host "Total policy group entries:" $policyGroupMap.Count

# ==============================
# STEP 2: RUN KQL
# ==============================
Write-Host "Running KQL query via Graph..."

$kqlQuery = @"
CloudAppEvents
| where ActionType in ("Add member to group.", "Remove member from group.")
| extend raw = parse_json(RawEventData)
| extend UserImpacted = tostring(raw.ObjectId)
| extend mp = parse_json(raw.ModifiedProperties)
| mv-expand mp
| extend Name = tostring(mp.Name),
         OldValue = tostring(mp.OldValue),
         NewValue = tostring(mp.NewValue)
| extend Value = iff(isempty(NewValue), OldValue, NewValue)
| summarize
    GroupDisplayName = maxif(Value, Name == "Group.DisplayName"),
    GroupObjectId   = maxif(Value, Name == "Group.ObjectID")
    by Timestamp, ActionType, AccountDisplayName, UserImpacted
| project Timestamp,
          ActionType,
          Actor = AccountDisplayName,
          Group = GroupDisplayName,
          GroupId = GroupObjectId,
          UserImpacted
"@

$kqlBody = @{
    query = $kqlQuery
} | ConvertTo-Json -Depth 5

$kqlResults = Invoke-RestMethod -Method Post `
    -Uri "https://graph.microsoft.com/v1.0/security/runHuntingQuery" `
    -Headers $graphHeaders `
    -Body $kqlBody

$events = $kqlResults.results

# ==============================
# STEP 3: CORRELATE IMPACT
# ==============================
Write-Host "Correlating impact..."

$impactResults = @()

foreach ($event in $events) {

    $eventGroupId = [string]$event.GroupId
    if (-not $eventGroupId) { continue }

    $action = $event.ActionType

    foreach ($policy in $policyGroupMap) {

        if ($policy.GroupId -eq $eventGroupId) {

            $impact = "Unknown"

            if ($policy.ScopeType -eq "Exclude" -and $action -eq "Remove member from group.") {
                $impact = "User NOW subject to policy"
            }
            elseif ($policy.ScopeType -eq "Exclude" -and $action -eq "Add member to group.") {
                $impact = "User EXCLUDED from policy"
            }
            elseif ($policy.ScopeType -eq "Include" -and $action -eq "Add member to group.") {
                $impact = "User NOW subject to policy"
            }
            elseif ($policy.ScopeType -eq "Include" -and $action -eq "Remove member from group.") {
                $impact = "User REMOVED from policy scope"
            }

            $impactResults += [PSCustomObject]@{
                Timestamp      = $event.Timestamp
                Actor          = $event.Actor
                ActionType     = $action
                Group          = $event.Group
                GroupId        = $eventGroupId
                UserImpacted   = $event.UserImpacted
                PolicyName     = $policy.PolicyName
                PolicyType     = $policy.PolicyType
                ScopeType      = $policy.ScopeType
                Impact         = $impact
            }
        }
    }
}

# ==============================
# STEP 4: EXPORT
# ==============================
$impactResults | Export-Csv "PurviewPolicyImpact.csv" -NoTypeInformation

Write-Host "✅ Done. Results exported to PurviewPolicyImpact.csv"