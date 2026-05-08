# ================================
# CONFIG
# ================================
$tenantId     = "TenatID"
$clientId     = "AppID"
$clientSecret = "ClientSecret"

# ================================
# AUTH - Get Graph Token
# ================================
$body = @{
    client_id     = $clientId
    scope         = "https://graph.microsoft.com/.default"
    client_secret = $clientSecret
    grant_type    = "client_credentials"
}

$tokenResponse = Invoke-RestMethod -Method POST `
    -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" `
    -Body $body

$accessToken = $tokenResponse.access_token

$headers = @{
    Authorization = "Bearer $accessToken"
}

# ================================
# STEP 1: Get Uploaded Streams
# ================================
$streamsUrl = "https://graph.microsoft.com/beta/security/dataDiscovery/cloudAppDiscovery/uploadedStreams"

$response = Invoke-RestMethod -Method GET -Uri $streamsUrl -Headers $headers

if (-not $response.value) {
    Write-Error "No streams found."
    return
}

# ================================
# STEP 2: Display Streams
# ================================
Write-Host "`nAvailable Streams:`n"

$index = 1
$streamTable = @()

foreach ($stream in $response.value) {
    $obj = [PSCustomObject]@{
        Index       = $index
        StreamId    = $stream.id
        Name        = $stream.displayName
        Source      = $stream.source
        Status      = $stream.status
    }

    $streamTable += $obj
    $index++
}

$streamTable | Format-Table -AutoSize

# ================================
# STEP 3: Prompt for selection
# ================================
$selection = Read-Host "`nEnter the Index of the stream you want to use"

$selectedStream = $streamTable | Where-Object { $_.Index -eq [int]$selection }

if (-not $selectedStream) {
    Write-Error "Invalid selection."
    return
}

$streamId = $selectedStream.StreamId
Write-Host "`nSelected Stream: $($selectedStream.Name) ($streamId)`n"

# ================================
# STEP 4: Get Apps for selected stream
# ================================
$appsUrl = "https://graph.microsoft.com/beta/security/dataDiscovery/cloudAppDiscovery/uploadedStreams/$streamId/aggregatedAppsDetails(period=duration'P90D')"

$allApps = @()

while ($appsUrl) {
    $appsResponse = Invoke-RestMethod -Method GET -Uri $appsUrl -Headers $headers

    foreach ($app in $appsResponse.value) {
        $allApps += [PSCustomObject]@{
    AppId           = $app.id   # <-- REQUIRED
    AppName         = $app.displayName
    Category        = $app.category
    RiskScore       = $app.riskScore
    RiskLevel       = $app.riskLevel
    Domain          = ($app.domains -join ",")
    UsersCount      = $app.usersCount
    IPsCount        = $app.ipAddressesCount
    Transactions    = $app.transactionCount
    UploadedDataMB  = $app.uploadedData
    DownloadedDataMB= $app.downloadedData
}
    }

    $appsUrl = $appsResponse.'@odata.nextLink'
}

# ================================
# STEP 5: Export to CSV
# ================================
$outputFile = ".\DiscoveredApps_$($selectedStream.Name).csv"

$allApps | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8

Write-Host "`nExport complete: $outputFile"

# ================================
# STEP 6: Get Users Per App
# ================================
Write-Host "`nCollecting users per application...`n"

$appUserResults = @()

foreach ($app in $allApps) {

    # IMPORTANT: We need the original app ID
    # Modify earlier section to store it if you haven't already
    $appId = $app.AppId

    if (-not $appId) {
        continue
    }

    Write-Host "Processing users for app: $($app.AppName)"

    $usersUrl = "https://graph.microsoft.com/beta/security/dataDiscovery/cloudAppDiscovery/uploadedStreams/$streamId/microsoft.graph.security.aggregatedAppsDetails(period=duration'P90D')/$appId/users"

    while ($usersUrl) {
        $usersResponse = Invoke-RestMethod -Method GET -Uri $usersUrl -Headers $headers

        foreach ($user in $usersResponse.value) {
            $appUserResults += [PSCustomObject]@{
                AppName        = $app.AppName
                AppId          = $appId
                UserIdentifier = $user.userIdentifier
            }
        }

        $usersUrl = $usersResponse.'@odata.nextLink'
    }
}

# ================================
# STEP 7: Export Users CSV
# ================================
$userOutputFile = ".\DiscoveredAppUsers_$($selectedStream.Name).csv"

$appUserResults | Export-Csv -Path $userOutputFile -NoTypeInformation -Encoding UTF8

Write-Host "`nUser export complete: $userOutputFile"