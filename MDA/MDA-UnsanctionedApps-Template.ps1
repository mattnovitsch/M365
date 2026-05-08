# ===========================
# CONFIG
# ===========================
$MDCATenant = "TenantName"
$MDCARegion = "Regin"
$MDCAToken  = "CloudAppsToken"

$savePath = "MDCA-UnsanctionedDomains.csv"   # Path to save the block script
$formatCode = 120   # Zscaler block script format
$typeFilter = "banned"  # Unsanctioned apps

# ===========================
# Build the API URL
# ===========================
$baseUrl = "https://${MDCATenant}.${MDCARegion}.portal.cloudappsecurity.com"
$apiEndpoint = "/api/discovery_block_scripts/"
$requestUrl  = "${baseUrl}${apiEndpoint}?format=${formatCode}&type=${typeFilter}"

# ===========================
# Fetch the block script
# ===========================
Write-Host "Fetching Zscaler block script from MDCA..."
$response = Invoke-RestMethod -Method Get -Uri $requestUrl -Headers @{
    "Authorization" = "Token $MDCAToken"
    "Accept"        = "text/plain"
}

# ===========================
# Save the script
# ===========================
if ($response) {
    Write-Host "Saving block script to $savePath ..."
    $response | Out-File -FilePath $savePath -Encoding ASCII
    Write-Host "Done! Block script ready for Zscaler import."
} else {
    Write-Warning "No script returned from the API."
}