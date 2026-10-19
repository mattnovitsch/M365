#requires -Version 5.1
<#
.SYNOPSIS
Exports discovered cloud applications from the legacy Defender for Cloud Apps API.

.DESCRIPTION
Uses the same tenant, region, and API-token authentication pattern as
MDA-SanctionedApps-Template.ps1. It retrieves continuous Cloud Discovery reports,
then exports discovered apps for each report to CSV and JSON.
#>

[CmdletBinding()]
param(
    [string]$MDCATenant,
    [string]$MDCARegion,
    [string]$MDCAToken = '',
    [ValidateRange(1,365)]
    [int]$TimeFrameDays = 90,
    [ValidateRange(1,100)]
    [int]$PageSize = 100,
    [string]$OutputFolder = (Join-Path $PWD ("MDA-CloudDiscovery-{0}" -f (Get-Date -Format 'yyyyMMdd-HHmmss')))
)

$MDCATenant = ''
$MDCARegion = ''
$TimeFrameDays = '90'
$MDCAToken = ''

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function ConvertFrom-SecureToken {
    param([Parameter(Mandatory)][SecureString]$SecureToken)
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureToken)
    try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
}

function Invoke-MDCARequest {
    param(
        [Parameter(Mandatory)][ValidateSet('GET','POST')][string]$Method,
        [Parameter(Mandatory)][string]$Uri,
        [object]$Body
    )

    $parameters = @{
        Method      = $Method
        Uri         = $Uri
        Headers     = $script:Headers
        ErrorAction = 'Stop'
    }
    if ($PSBoundParameters.ContainsKey('Body')) {
        $parameters.ContentType = 'application/json'
        $parameters.Body = $Body | ConvertTo-Json -Depth 20 -Compress
    }

    try {
        Invoke-RestMethod @parameters
    }
    catch {
        $status = $null
        if ($_.Exception.Response) {
            try { $status = [int]$_.Exception.Response.StatusCode } catch { }
        }
        $detail = $_.ErrorDetails.Message
        if ([string]::IsNullOrWhiteSpace($detail)) { $detail = $_.Exception.Message }
        throw "MDCA request failed: $Method $Uri`nHTTP status: $status`n$detail"
    }
}

function Get-ItemsFromResponse {
    param([Parameter(Mandatory)]$Response)

    if ($null -eq $Response) { return @() }
    if ($Response -is [System.Array]) { return @($Response) }

    foreach ($name in @('streams','data','results','items','apps','services')) {
        if ($Response.PSObject.Properties.Name -contains $name) {
            return @($Response.$name)
        }
    }
    @($Response)
}

function Get-StreamIdentifier {
    param([Parameter(Mandatory)]$Stream)
    foreach ($name in @('_id','id','streamId')) {
        if ($Stream.PSObject.Properties.Name -contains $name) {
            return [string]$Stream.$name
        }
    }
    return $null
}

function ConvertTo-FlatAppRecord {
    param(
        [Parameter(Mandatory)]$App,
        [Parameter(Mandatory)][string]$StreamId,
        [Parameter(Mandatory)][string]$StreamName
    )

    $record = [ordered]@{
        StreamId   = $StreamId
        StreamName = $StreamName
    }

    foreach ($property in $App.PSObject.Properties) {
        $value = $property.Value

        if ($null -eq $value) {
            $record[$property.Name] = $null
            continue
        }

        # Strip the SAASDB_CATEGORY_ / SAASDB_SUBCATEGORY_ prefix
        if ($property.Name -eq 'category' -and $value -is [string]) {
            $value = $value -replace '^SAASDB_(SUB)?CATEGORY_', ''
        }
        # allDomains comes back space-separated; normalize to "; "
        elseif ($property.Name -eq 'allDomains' -and $value -is [string]) {
            $value = ($value -split '\s+' | Where-Object { $_ }) -join '; '
        }
        # Arrays: join simple values, JSON-encode complex ones (no unrolling)
        elseif ($value -is [System.Array]) {
            $isSimple = -not ($value | Where-Object { $_ -isnot [string] -and $_ -isnot [ValueType] })
            if ($isSimple) {
                $value = $value -join '; '
            }
            else {
                $value = ConvertTo-Json -InputObject $value -Depth 10 -Compress
            }
        }
        # Nested objects (timeFrames, riskFactors, revised_score, etc.)
        elseif ($value -isnot [string] -and $value -isnot [ValueType]) {
            $value = ConvertTo-Json -InputObject $value -Depth 10 -Compress
        }

        $record[$property.Name] = $value
    }

    [pscustomobject]$record
}

if ([string]::IsNullOrWhiteSpace($MDCATenant)) {
    $MDCATenant = Read-Host 'Enter the MDCA tenant name (example: mngenvmcap386787)'
}
if ([string]::IsNullOrWhiteSpace($MDCARegion)) {
    $MDCARegion = Read-Host 'Enter the MDCA region (example: us2)'
}

if ($MDCATenant -notmatch '^[A-Za-z0-9-]+$') { throw 'MDCATenant contains invalid characters.' }
if ($MDCARegion -notmatch '^[A-Za-z0-9-]+$') { throw 'MDCARegion contains invalid characters.' }

$baseUrl = "https://${MDCATenant}.${MDCARegion}.portal.cloudappsecurity.com"
$script:Headers = @{
    Authorization = "Token $($MDCAToken.Trim())"
    Accept        = 'application/json'
}

New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null
Write-Host "MDCA API host: $baseUrl" -ForegroundColor Cyan

# 1. Retrieve continuous Cloud Discovery reports.
$streamsUri = "$baseUrl/api/discovery/streams/"
Write-Host 'Retrieving continuous Cloud Discovery reports...' -ForegroundColor Cyan
$streamsResponse = Invoke-MDCARequest -Method GET -Uri $streamsUri
$streamsResponse | ConvertTo-Json -Depth 30 | Set-Content (Join-Path $OutputFolder 'ContinuousReports-Raw.json') -Encoding UTF8

# The API wraps reports in a 'streams' property
if ($streamsResponse.PSObject.Properties.Name -contains 'streams') {
    $streams = @($streamsResponse.streams)
}
else {
    $streams = @(Get-ItemsFromResponse -Response $streamsResponse)
}

# streamType 1 = Defender-managed endpoints (input). Skip the Global view (3) to avoid duplicate rows.
$streams = @($streams | Where-Object { $_ -and $_.streamType -eq 1 })

if ($streams.Count -eq 0) {
    throw "No continuous reports were returned. Review $(Join-Path $OutputFolder 'ContinuousReports-Raw.json')."
}

$streams | Export-Csv (Join-Path $OutputFolder 'ContinuousReports.csv') -NoTypeInformation -Encoding UTF8
$streams | ConvertTo-Json -Depth 30 | Set-Content (Join-Path $OutputFolder 'ContinuousReports.json') -Encoding UTF8
Write-Host "Continuous reports found: $($streams.Count)" -ForegroundColor Green

# 2. Retrieve discovered apps for every report.
$allApps = [System.Collections.Generic.List[object]]::new()

foreach ($stream in $streams) {
    $streamId = Get-StreamIdentifier -Stream $stream
    $streamName = [string]$stream.displayName

    if ([string]::IsNullOrWhiteSpace($streamId)) {
        Write-Warning "Skipping '$streamName' because the API response did not include id, _id, or streamId."
        continue
    }

    Write-Host "Retrieving apps from '$streamName' [$streamId]..." -ForegroundColor Cyan
    $skip = 0
    $page = 0
    $previousPageJson = $null

    do {
        $page++
        $requestBody = @{
            streamId  = $streamId
            timeFrame = $TimeFrameDays
            skip      = $skip
            limit     = $PageSize
        }

        $appsUri = "$baseUrl/api/v1/discovery/discovered_apps/"
        $response = Invoke-MDCARequest -Method POST -Uri $appsUri -Body $requestBody
        $response | ConvertTo-Json -Depth 30 | Set-Content (Join-Path $OutputFolder ("Apps-{0}-Page-{1}.json" -f $streamId,$page)) -Encoding UTF8

        $items = @(Get-ItemsFromResponse -Response $response)
        $pageJson = $items | ConvertTo-Json -Depth 10 -Compress
        if ($page -gt 1 -and $pageJson -eq $previousPageJson) {
            Write-Warning 'The API repeated the prior page. Pagination was stopped.'
            break
        }
        $previousPageJson = $pageJson

        foreach ($app in $items) {
            $allApps.Add((ConvertTo-FlatAppRecord -App $app -StreamId $streamId -StreamName $streamName))
        }

        Write-Host "  Page ${page}: $($items.Count) apps" -ForegroundColor DarkGray
        $skip += $items.Count

        $hasNext = $false
        if ($response.PSObject.Properties.Name -contains 'hasNext') {
            $hasNext = [bool]$response.hasNext
        }
        elseif ($items.Count -eq $PageSize) {
            $hasNext = $true
        }

        if ($items.Count -eq 0) { $hasNext = $false }
        if ($page -ge 10000) { throw 'Pagination exceeded 10,000 pages and was stopped.' }
    } while ($hasNext)
}

$csvPath = Join-Path $OutputFolder 'CloudDiscoveryApps.csv'
$jsonPath = Join-Path $OutputFolder 'CloudDiscoveryApps.json'

if ($allApps.Count -gt 0) {
    # Fixed column order for the CSV; the full data stays in CloudDiscoveryApps.json
	$csvColumns = @(
	    'streamId','StreamName','category','domainList','firstUsed','hqLocation',
	    'lastModified','lastUsed','name','revised_score_total',
	    'validTimeFrames','allDomains','name_l','tags','trafficTotalBytes',
	    'trafficUploadedBytes','trafficTotalEvents','usersCount','ipAddressesCount',
	    'machineNamesCount','trafficTotalBlockedEvents','description','organization'
)

$allApps | Select-Object -Property $csvColumns |
    Export-Csv $csvPath -NoTypeInformation -Encoding UTF8
    $allApps | ConvertTo-Json -Depth 30 | Set-Content $jsonPath -Encoding UTF8
}
else {
    'No discovered applications were returned.' | Set-Content (Join-Path $OutputFolder 'NoAppsReturned.txt') -Encoding UTF8
}

Write-Host ''
Write-Host 'Export complete.' -ForegroundColor Green
Write-Host "Continuous reports: $($streams.Count)"
Write-Host "Discovered apps:    $($allApps.Count)"
Write-Host "Output folder:      $((Resolve-Path $OutputFolder).Path)"

$script:Headers = $null
