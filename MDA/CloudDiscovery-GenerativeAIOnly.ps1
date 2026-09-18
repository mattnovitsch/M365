# ============================================================
# Microsoft Defender for Cloud Apps
# Cloud Discovery - Generative AI Application Report
#
# Authentication: Delegated user authentication
# No client secrets required
# ============================================================

# ============================================================
# CONFIG
# ============================================================

$tenantId = "TenantID"

# Cloud App Discovery category to retrieve
$categoryFilter = "generativeAi"


# ============================================================
# STEP 0: Prerequisites
# ============================================================

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {

    Write-Host "Microsoft Graph PowerShell module not found." -ForegroundColor Yellow
    Write-Host "Installing Microsoft.Graph.Authentication..." -ForegroundColor Yellow

    Install-Module Microsoft.Graph.Authentication `
        -Scope CurrentUser `
        -Force `
        -AllowClobber
}

Import-Module Microsoft.Graph.Authentication


# ============================================================
# STEP 1: Authenticate to Microsoft Graph
# ============================================================

Write-Host "`nConnecting to Microsoft Graph..." -ForegroundColor Cyan

try {

    Connect-MgGraph `
        -TenantId $tenantId `
        -Scopes "CloudApp-Discovery.Read.All" `
        -NoWelcome

}
catch {

    Write-Error "Unable to authenticate to Microsoft Graph."
    Write-Error $_.Exception.Message
    return
}


# ============================================================
# Verify authentication context
# ============================================================

$context = Get-MgContext

if (-not $context) {

    Write-Error "Microsoft Graph authentication context was not created."
    return
}

Write-Host "`nAuthenticated successfully." -ForegroundColor Green
Write-Host "Account : $($context.Account)"
Write-Host "Tenant  : $($context.TenantId)"
Write-Host "AuthType: $($context.AuthType)"
Write-Host "Scopes  : $($context.Scopes -join ', ')"


# ============================================================
# STEP 2: Get Uploaded Streams
# ============================================================

$streamsUrl = "https://graph.microsoft.com/beta/security/dataDiscovery/cloudAppDiscovery/uploadedStreams"

try {

    $response = Invoke-MgGraphRequest `
        -Method GET `
        -Uri $streamsUrl

}
catch {

    Write-Error "Unable to retrieve Cloud Discovery streams."
    Write-Error $_.Exception.Message
    return
}

if (-not $response.value) {

    Write-Error "No Cloud Discovery streams were found."
    return
}


# ============================================================
# STEP 3: Display Streams
# ============================================================

Write-Host "`nAvailable Streams:`n" -ForegroundColor Cyan

$index = 1
$streamTable = @()

foreach ($stream in $response.value) {

    $obj = [PSCustomObject]@{

        Index    = $index
        StreamId = $stream.id
        Name     = $stream.displayName
        Source   = $stream.source
        Status   = $stream.status
    }

    $streamTable += $obj
    $index++
}

$streamTable | Format-Table -AutoSize


# ============================================================
# STEP 4: Prompt for Stream Selection
# ============================================================

$selection = Read-Host "`nEnter the Index of the stream to use"

$selectedStream = $streamTable |
    Where-Object { $_.Index -eq [int]$selection }

if (-not $selectedStream) {

    Write-Error "Invalid stream selection."
    return
}

$streamId = $selectedStream.StreamId

Write-Host "`nSelected Stream : $($selectedStream.Name)" -ForegroundColor Cyan
Write-Host "Stream ID       : $streamId"
Write-Host "Category Filter : $categoryFilter"


# ============================================================
# STEP 5: Get Discovered Applications
# Last 90 Days
# ============================================================

$appsUrl = "https://graph.microsoft.com/beta/security/dataDiscovery/cloudAppDiscovery/uploadedStreams/$streamId/microsoft.graph.security.aggregatedAppsDetails(period=duration'P90D')"

$allApps = @()

Write-Host "`nRetrieving discovered applications..." -ForegroundColor Cyan

while ($appsUrl) {

    try {

        $appsResponse = Invoke-MgGraphRequest `
            -Method GET `
            -Uri $appsUrl

    }
    catch {

        Write-Error "Unable to retrieve discovered applications."
        Write-Error $_.Exception.Message
        return
    }

    foreach ($app in $appsResponse.value) {

        $allApps += [PSCustomObject]@{

            AppId            = $app.id
            AppName          = $app.displayName
            Category         = $app.category
            RiskScore        = $app.riskScore
            RiskLevel        = $app.riskLevel
            Domain           = ($app.domains -join ", ")
            UsersCount       = $app.usersCount
            IPsCount         = $app.ipAddressesCount
            Transactions     = $app.transactionCount
            UploadedDataMB   = $app.uploadedData
            DownloadedDataMB = $app.downloadedData
        }
    }

    $appsUrl = $appsResponse.'@odata.nextLink'
}

Write-Host "Total discovered applications: $($allApps.Count)" `
    -ForegroundColor Cyan


# ============================================================
# STEP 6: Filter for Generative AI
# ============================================================

$filteredApps = $allApps |
    Where-Object {
        $_.Category -eq $categoryFilter
    }

Write-Host "`nGenerative AI applications found: $($filteredApps.Count)" `
    -ForegroundColor Green


# ============================================================
# Troubleshooting - Display Returned Categories
# ============================================================

if (-not $filteredApps) {

    Write-Warning "No applications were found with category '$categoryFilter'."

    Write-Host "`nCategories returned by Cloud Discovery:`n" `
        -ForegroundColor Yellow

    $allApps |
        Group-Object Category |
        Sort-Object Count -Descending |
        Select-Object Count, Name |
        Format-Table -AutoSize

    Disconnect-MgGraph
    return
}


# ============================================================
# Display Generative AI Apps
# ============================================================

Write-Host "`nGenerative AI Applications:`n" `
    -ForegroundColor Green

$filteredApps |
    Sort-Object AppName |
    Select-Object `
        AppName,
        Category,
        RiskScore,
        UsersCount,
        Transactions |
    Format-Table -AutoSize


# ============================================================
# STEP 7: Export Generative AI Applications
# ============================================================

$safeStreamName = $selectedStream.Name -replace '[\\/:*?"<>|]', '_'

$outputFile = ".\GenerativeAI_DiscoveredApps_$safeStreamName.csv"

$filteredApps |
    Sort-Object AppName |
    Export-Csv `
        -Path $outputFile `
        -NoTypeInformation `
        -Encoding UTF8

Write-Host "`nGenerative AI application export complete:" `
    -ForegroundColor Green

Write-Host $outputFile


# ============================================================
# STEP 8: Get Users Per Generative AI Application
# ============================================================

Write-Host "`nCollecting users for Generative AI applications...`n" `
    -ForegroundColor Cyan

$appUserResults = @()

foreach ($app in $filteredApps) {

    $appId = $app.AppId

    if (-not $appId) {

        Write-Warning "Skipping $($app.AppName): no AppId returned."
        continue
    }

    Write-Host "Processing: $($app.AppName)" `
        -ForegroundColor Yellow

    $usersUrl = "https://graph.microsoft.com/beta/security/dataDiscovery/cloudAppDiscovery/uploadedStreams/$streamId/microsoft.graph.security.aggregatedAppsDetails(period=duration'P90D')/$appId/users"

    while ($usersUrl) {

        try {

            $usersResponse = Invoke-MgGraphRequest `
                -Method GET `
                -Uri $usersUrl

            foreach ($user in $usersResponse.value) {

                $appUserResults += [PSCustomObject]@{

                    AppName        = $app.AppName
                    AppId          = $appId
                    Category       = $app.Category
                    RiskScore      = $app.RiskScore
                    UserIdentifier = $user.userIdentifier
                }
            }

            $usersUrl = $usersResponse.'@odata.nextLink'

        }
        catch {

            Write-Warning "Unable to retrieve users for $($app.AppName): $($_.Exception.Message)"
            break
        }
    }
}


# ============================================================
# STEP 9: Export User Report
# ============================================================

$userOutputFile = ".\GenerativeAI_DiscoveredAppUsers_$safeStreamName.csv"

$appUserResults |
    Sort-Object AppName, UserIdentifier |
    Export-Csv `
        -Path $userOutputFile `
        -NoTypeInformation `
        -Encoding UTF8

Write-Host "`nUser export complete:" `
    -ForegroundColor Green

Write-Host $userOutputFile


# ============================================================
# SUMMARY
# ============================================================

Write-Host "`n============================================" `
    -ForegroundColor Cyan

Write-Host "GENERATIVE AI CLOUD DISCOVERY SUMMARY" `
    -ForegroundColor Cyan

Write-Host "============================================" `
    -ForegroundColor Cyan

Write-Host "Stream                : $($selectedStream.Name)"
Write-Host "Total discovered apps : $($allApps.Count)"
Write-Host "Generative AI apps    : $($filteredApps.Count)"
Write-Host "User/app records      : $($appUserResults.Count)"

Write-Host "`nApplication Report:"
Write-Host $outputFile

Write-Host "`nUser Report:"
Write-Host $userOutputFile


# ============================================================
# Disconnect Graph Session
# ============================================================

Disconnect-MgGraph

Write-Host "`nMicrosoft Graph session disconnected." `
    -ForegroundColor Green