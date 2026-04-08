# ==============================
# CONFIG
# ==============================
#$TenantId = "<TENANT_ID>"
#$ClientId = "<APP_ID>"
#$ClientSecret = "<CLIENT_SECRET>"

# ==============================
# GRAPH AUTH (for group lookups)
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
# DEFENDER AUTH (for KQL)
# ==============================
$defenderBody = @{
    grant_type    = "client_credentials"
    scope         = "https://api.security.microsoft.com/.default"
    client_id     = $ClientId
    client_secret = $ClientSecret
}

$defenderTokenResponse = Invoke-RestMethod -Method Post `
    -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
    -Body $defenderBody

$defenderToken = $defenderTokenResponse.access_token

$defenderHeaders = @{
    Authorization = "Bearer $defenderToken"
    "Content-Type" = "application/json"
}

# ==============================
# STEP 1: CONNECT TO PURVIEW
# ==============================
Write-Host "Connecting to Purview..."

Import-Module ExchangeOnlineManagement
Connect-IPPSSession

# ==============================
# STEP 2: GET DLP POLICIES
# ==============================
Write-Host "Pulling DLP policies from Purview..."

$policyGroupMap = @()
$dlpPolicies = Get-DlpCompliancePolicy

foreach ($policy in $dlpPolicies) {

    # Exchange locations (often groups)
foreach ($loc in $policy.ExchangeLocation) {

    $locString = $loc.ToString()

    if ($locString -ne "All") {
        $policyGroupMap += [PSCustomObject]@{
            PolicyName = $policy.Name
            PolicyType = "DLP"
            GroupName  = $locString
        }
    }
}

    # SharePoint / OneDrive locations
    foreach ($loc in $policy.SharePointLocation) {

    $locString = $loc.ToString()

    if ($locString -ne "All") {
        $policyGroupMap += [PSCustomObject]@{
            PolicyName = $policy.Name
            PolicyType = "DLP"
            GroupName  = $locString
        }
    }
}
}

# ==============================
# STEP 3: NORMALIZE GROUP NAMES
# ==============================
Write-Host "Normalizing group names..."

$normalizedPolicyMap = @()

foreach ($item in $policyGroupMap) {

    # Attempt to resolve via Graph (optional but helpful)
    try {
        $group = Invoke-RestMethod -Headers $graphHeaders -Uri `
            "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$($item.GroupName)'"

        if ($group.value.Count -gt 0) {
            $normalizedPolicyMap += [PSCustomObject]@{
                PolicyName = $item.PolicyName
                PolicyType = $item.PolicyType
                GroupName  = $group.value[0].displayName
            }
        }
    }
    catch {
        # fallback to raw name
        $normalizedPolicyMap += $item
    }
}

# ==============================
# STEP 4: RUN YOUR KQL (GRAPH API)
# ==============================
Write-Host "Running KQL query via Graph..."

$kqlQuery = @"
CloudAppEvents | where ActionType contains "Group" | extend raw = parse_json(RawEventData) | extend UserImpacted = raw.ObjectId, Operation = raw.Operation | extend mp = parse_json(RawEventData.ModifiedProperties) | mv-expand mp | where tostring(mp.Name) == "Group.DisplayName" | extend Group = iff(ActionType contains "remove", tostring(mp.OldValue), tostring(mp.NewValue)) | project Timestamp, ActionType, Actor=AccountDisplayName, Operation, Group, UserImpacted
"@

$kqlBody = @{
    query = $kqlQuery
} | ConvertTo-Json -Depth 5

$kqlResults = Invoke-RestMethod -Method Post `
    -Uri "https://graph.microsoft.com/v1.0/security/runHuntingQuery" `
    -Headers $graphHeaders `
    -Body $kqlBody

# Normalize results (Graph uses lowercase 'results')
$events = $kqlResults.results

# ==============================
# STEP 5: CORRELATE IMPACT
# ==============================
Write-Host "Correlating impact..."

$impactResults = @()

foreach ($event in $kqlResults.Results) {

    $matchedPolicies = $normalizedPolicyMap | Where-Object {
        $_.GroupName -and $_.GroupName.ToLower() -eq $event.Group.ToLower()
    }

    foreach ($policy in $matchedPolicies) {
        $impactResults += [PSCustomObject]@{
            Timestamp      = $event.Timestamp
            Actor          = $event.Actor
            Operation      = $event.Operation
            Group          = $event.Group
            UserImpacted   = $event.UserImpacted
            PolicyName     = $policy.PolicyName
            PolicyType     = $policy.PolicyType
            ImpactDetected = $true
        }
    }
}

# ==============================
# STEP 6: EXPORT
# ==============================
$impactResults | Export-Csv "PurviewPolicyImpact.csv" -NoTypeInformation

Write-Host "✅ Done. Results exported to PurviewPolicyImpact.csv"