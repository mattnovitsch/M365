# ===========================
# Export Sanctioned + Protected Domains
# Defender for Cloud Apps
# ===========================

# ===========================
# CONFIG
# ===========================
$MDCATenant = "TenantName"
$MDCARegion = "Regin"
$MDCAToken  = "CloudAppsToken"

# Output CSV
$OutputCsv = "MDCA-SanctionedAndProtectedDomains.csv"

# ===========================
# Build Base URL
# ===========================
$baseUrl = "https://${MDCATenant}.${MDCARegion}.portal.cloudappsecurity.com"

# ===========================
# Normalize Domain Function
# ===========================
function Normalize-Domain {
    param (
        [string]$Domain
    )

    if ([string]::IsNullOrWhiteSpace($Domain)) {
        return $null
    }

    $Domain = $Domain.ToLower().Trim()

    # Remove protocol
    $Domain = $Domain -replace '^https?:\/\/', ''

    # Remove anything after first slash
    if ($Domain -match '^[^\/]+') {
        $Domain = $matches[0]
    }

    # Convert ".domain.com" → "*.domain.com"
    if ($Domain -match '^\.(.+)') {
        $Domain = "*.$($matches[1])"
    }

    return $Domain
}

# ===========================
# FETCH SANCTIONED DOMAINS
# ===========================
Write-Host ""
Write-Host "========================================="
Write-Host "Fetching sanctioned domains..."
Write-Host "========================================="

$formatCode = 120

$SanctionedUrl = "${baseUrl}/api/discovery_block_scripts/?format=${formatCode}&type=sanctioned"

try {

    $SanctionedResponse = Invoke-RestMethod `
        -Method Get `
        -Uri $SanctionedUrl `
        -Headers @{
            "Authorization" = "Token $MDCAToken"
            "Accept"        = "text/plain"
        }

}
catch {

    Write-Error "Failed to retrieve sanctioned domains"
    Write-Error $_
    exit 1
}

# Process sanctioned domains
$SanctionedDomains = @()

if ($SanctionedResponse) {

    $SanctionedDomains = $SanctionedResponse -split "`n" | ForEach-Object {

        $CleanDomain = Normalize-Domain $_

        if (-not [string]::IsNullOrWhiteSpace($CleanDomain)) {

            [PSCustomObject]@{
                Domain = $CleanDomain
                Type   = "Sanctioned"
            }
        }

    } | Sort-Object Domain -Unique
}

Write-Host "✅ Sanctioned domains collected: $($SanctionedDomains.Count)"

# ===========================
# FETCH PROTECTED DOMAINS
# ===========================
Write-Host ""
Write-Host "========================================="
Write-Host "Fetching protected domains..."
Write-Host "========================================="

$ProtectedUrl = "${baseUrl}/api/discovery_block_scripts/?format=${formatCode}&type=protected"

try {

    $ProtectedResponse = Invoke-RestMethod `
        -Method Get `
        -Uri $ProtectedUrl `
        -Headers @{
            "Authorization" = "Token $MDCAToken"
            "Accept"        = "text/plain"
        }

}
catch {

    Write-Warning "Failed to retrieve protected domains"
    $ProtectedResponse = $null
}

# Process protected domains
$ProtectedDomains = @()

if ($ProtectedResponse) {

    $ProtectedDomains = $ProtectedResponse -split "`n" | ForEach-Object {

        $CleanDomain = Normalize-Domain $_

        if (-not [string]::IsNullOrWhiteSpace($CleanDomain)) {

            [PSCustomObject]@{
                Domain = $CleanDomain
                Type   = "Protected"
            }
        }

    } | Sort-Object Domain -Unique
}

Write-Host "✅ Protected domains collected: $($ProtectedDomains.Count)"

# ===========================
# COMBINE RESULTS
# ===========================
Write-Host ""
Write-Host "========================================="
Write-Host "Combining results..."
Write-Host "========================================="

$Export = @()
$Export += $SanctionedDomains
$Export += $ProtectedDomains

$Export = $Export |
    Sort-Object Domain, Type -Unique

$SanctionedCount = ($Export | Where-Object { $_.Type -eq "Sanctioned" }).Count
$ProtectedCount  = ($Export | Where-Object { $_.Type -eq "Protected" }).Count

Write-Host "✅ Total sanctioned entries: $SanctionedCount"
Write-Host "✅ Total protected entries : $ProtectedCount"
Write-Host "✅ Total combined entries  : $($Export.Count)"

# ===========================
# EXPORT CSV
# ===========================
Write-Host ""
Write-Host "========================================="
Write-Host "Exporting CSV..."
Write-Host "========================================="

$Export |
    Sort-Object Type, Domain |
    Export-Csv `
        -Path $OutputCsv `
        -NoTypeInformation `
        -Encoding UTF8

# ===========================
# SUMMARY
# ===========================
Write-Host ""
Write-Host "========================================="
Write-Host "EXPORT COMPLETE"
Write-Host "========================================="

Write-Host "Sanctioned Entries : $SanctionedCount"
Write-Host "Protected Entries  : $ProtectedCount"
Write-Host "Total Export Rows  : $($Export.Count)"

Write-Host ""
Write-Host "CSV File:"
Write-Host "   $OutputCsv"

Write-Host ""
Write-Host "✅ Completed successfully"