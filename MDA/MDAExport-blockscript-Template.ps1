# ==============================
# MDCA → GSA Filtering Policy
# ==============================

# --- CONFIGURATION ---
$TenantId     = "<TenantID>" #Acquire from Entra Registered Application
$ClientId     = "<ClientID>" #Acquire from Entra Registered Application
$ClientSecret = "<Generate Client Secret>" #Generate Client Secret from Entra Registered Application
$PolicyName   = "MDCA Block Script - Per Domain Rules"

# ===========================
# CONFIG
# ===========================
# You can find these settings here: https://security.microsoft.com/cloudapps/settings
$MDCATenant = "<Tenant Name>" #name of your tenant when created
$MDCARegion = "<Tenant Region>" #Like us, us2, usmod
$MDCAToken  = "<Generate this from Defender XDR>"
$formatCode = 120
$typeFilter = "banned"

# ===========================
# HELPER: Normalize Domain
# ===========================
function Normalize-Domain {
    param ($d)

    $d = $d.ToLower().Trim()

    # If domain starts with ".", convert to wildcard
    if ($d -match '^\.(.+)') {
        return "*.$($matches[1])"
    }

    return $d
}

# ===========================
# Build API URL
# ===========================
$baseUrl = "https://${MDCATenant}.${MDCARegion}.portal.cloudappsecurity.com"
$apiEndpoint = "/api/discovery_block_scripts/"
$requestUrl  = "${baseUrl}${apiEndpoint}?format=${formatCode}&type=${typeFilter}"

# ===========================
# FETCH + PROCESS DOMAINS (IN-MEMORY)
# ===========================
Write-Host "Fetching Zscaler block script from MDCA..."

$response = Invoke-RestMethod -Method Get -Uri $requestUrl -Headers @{
    "Authorization" = "Token $MDCAToken"
    "Accept"        = "text/plain"
}

if (-not $response) {
    Write-Warning "No script returned from the API."
    exit 1
}

# ===========================
# HELPER: Normalize Domain
# ===========================
function Normalize-Domain {
    param ($d)

    $d = $d.ToLower().Trim()

    # Convert ".domain.com" → "*.domain.com"
    if ($d -match '^\.(.+)') {
        return "*.$($matches[1])"
    }

    return $d
}

# ===========================
# PARSE DOMAINS DIRECTLY
# ===========================
$AllDomains = $response -split "`n" | ForEach-Object {
    $_ = Normalize-Domain $_

    # Remove anything after first slash
    if ($_ -match '^[^/]+') {
        $matches[0]
    }
} | Where-Object { $_ -ne "" } | Sort-Object -Unique

Write-Host "✅ Total cleaned domains: $($AllDomains.Count)"

# ==============================
# GET MICROSOFT GRAPH TOKEN
# ==============================
$GraphBody = @{
    grant_type    = "client_credentials"
    scope         = "https://graph.microsoft.com/.default"
    client_id     = $ClientId
    client_secret = $ClientSecret
}

$GraphTokenResponse = Invoke-RestMethod -Method Post `
    -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
    -Body $GraphBody

$GraphAccessToken = $GraphTokenResponse.access_token
if (-not $GraphAccessToken) {
    Write-Error "❌ Failed to obtain Graph token"
    exit 1
}

$GraphHeaders = @{
    Authorization  = "Bearer $GraphAccessToken"
    "Content-Type" = "application/json"
}

# ==============================
# GET OR CREATE POLICY
# ==============================
$PoliciesUri = "https://graph.microsoft.com/beta/networkaccess/filteringPolicies"
$ExistingPolicies = Invoke-RestMethod -Method Get -Uri $PoliciesUri -Headers $GraphHeaders
$Policy = $ExistingPolicies.value | Where-Object { $_.name -eq $PolicyName }

if (-not $Policy) {
    Write-Host "⚠️ Policy not found. Creating..."

    $firstDomain = $AllDomains[0]

    $PolicyBody = @{
        name         = $PolicyName
        "@odata.type" = "#microsoft.graph.networkaccess.filteringPolicy"
        action       = "block"
        policyRules  = @(
            @{
                "@odata.type" = "#microsoft.graph.networkaccess.fqdnFilteringRule"
                name          = "Block $firstDomain"
                ruleType      = "fqdn"
                destinations  = @(@{
                    "@odata.type" = "#microsoft.graph.networkaccess.fqdn"
                    value         = $firstDomain
                })
            }
        )
    } | ConvertTo-Json -Depth 10

    $Policy = Invoke-RestMethod -Method Post `
        -Uri $PoliciesUri `
        -Headers $GraphHeaders `
        -Body $PolicyBody

    Write-Host "✅ Created policy with initial domain: $firstDomain"

    $AllDomains = $AllDomains | Where-Object { $_ -ne $firstDomain }
} else {
    Write-Host "✅ Using existing policy: $($Policy.id)"
}

# ==============================
# GET EXISTING RULES
# ==============================
$ExistingRulesUri = "https://graph.microsoft.com/beta/networkaccess/filteringPolicies/$($Policy.id)/policyRules"
$ExistingRules = (Invoke-RestMethod -Method Get -Uri $ExistingRulesUri -Headers $GraphHeaders).value

$ExistingDomainsMap = @{}

foreach ($rule in $ExistingRules) {
    foreach ($dest in $rule.destinations) {
        $normalized = Normalize-Domain $dest.value
        $ExistingDomainsMap[$normalized] = $rule.id
    }
}

# ==============================
# BUILD SETS
# ==============================
# Create empty sets
$DesiredSet  = New-Object 'System.Collections.Generic.HashSet[string]'
$ExistingSet = New-Object 'System.Collections.Generic.HashSet[string]'

# Populate DesiredSet
foreach ($d in $AllDomains) {
    [void]$DesiredSet.Add($d)
}

# Populate ExistingSet
foreach ($d in $ExistingDomainsMap.Keys) {
    [void]$ExistingSet.Add($d)
}

# ==============================
# CALCULATE DIFFERENCES
# ==============================
$ToAdd    = $DesiredSet.Where({ -not $ExistingSet.Contains($_) })
$ToRemove = $ExistingSet.Where({ -not $DesiredSet.Contains($_) })

# ==============================
# ADD MISSING DOMAINS
# ==============================
foreach ($domain in $ToAdd) {

    $RuleBody = @{
        "@odata.type" = "#microsoft.graph.networkaccess.fqdnFilteringRule"
        name          = "Block $domain"
        ruleType      = "fqdn"
        destinations  = @(@{
            "@odata.type" = "#microsoft.graph.networkaccess.fqdn"
            value         = $domain
        })
    } | ConvertTo-Json -Depth 5

    try {
        Invoke-RestMethod -Method Post `
            -Uri $ExistingRulesUri `
            -Headers $GraphHeaders `
            -Body $RuleBody

        Write-Host "✅ Added: $domain"
    } catch {
        Write-Error "❌ Failed to add $domain"
    }
}

# ==============================
# REMOVE STALE DOMAINS
# ==============================
foreach ($domain in $ToRemove) {

    $ruleId = $ExistingDomainsMap[$domain]
    $Uri = "$ExistingRulesUri/$ruleId"

    try {
        Invoke-RestMethod -Method Delete -Uri $Uri -Headers $GraphHeaders
        Write-Host "🗑 Removed: $domain"
    } catch {
        Write-Error "❌ Failed to remove $domain"
    }
}

# ==============================
# SUMMARY
# ==============================
Write-Host "----- SUMMARY -----"
Write-Host "Desired Domains : $($DesiredSet.Count)"
Write-Host "Existing Rules  : $($ExistingSet.Count)"
Write-Host "Added           : $($ToAdd.Count)"
Write-Host "Removed         : $($ToRemove.Count)"