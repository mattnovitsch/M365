# ==============================
# CONFIG
# ==============================
$inputCsv  = "C:\Tools\MDE\sites.csv"
$outputCsv = "C:\Tools\MDE\Defender_WCF_Test_Results.csv"
$ThrottleLimit = 20

# Force TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ==============================
# IMPORT CSV
# ==============================
Write-Host "Loading CSV..." -ForegroundColor Cyan
$csvData = Import-Csv $inputCsv
$columnName = "URL"

# ==============================
# NORMALIZATION
# ==============================
function Normalize-Domain {
    param([string]$Domain)

    if ([string]::IsNullOrWhiteSpace($Domain)) { return $null }

    $Domain = $Domain.Trim()
    $Domain = $Domain -replace '^https?://',''
    $Domain = $Domain -replace '^\*\.',''
    $Domain = $Domain -replace '^\.+',''
    $Domain = $Domain -replace '^/+',''
    $Domain = $Domain.Split('/')[0]
    $Domain = $Domain.Split(':')[0]
    $Domain = $Domain.Trim().TrimStart('.','/','\')

    if ([string]::IsNullOrWhiteSpace($Domain)) { return $null }

    return $Domain.ToLower()
}

function Get-UrlVariants {
    param([string]$Domain)

    $Domain = Normalize-Domain $Domain
    if (!$Domain) { return @() }

    $root = if ($Domain.StartsWith("www.")) { $Domain.Substring(4) } else { $Domain }

    return @(
        "http://$root"
        "https://$root"
        "http://www.$root"
        "https://www.$root"
    )
}

# ==============================
# BUILD URL LIST
# ==============================
$testUrls = foreach ($row in $csvData) {
    $val = $row.$columnName
    if ($val) { Get-UrlVariants $val }
}

$testUrls = $testUrls | Where-Object { $_ } | Sort-Object -Unique

Write-Host ""
Write-Host "Generated $($testUrls.Count) URLs" -ForegroundColor Green

if ($testUrls.Count -eq 0) {
    Write-Host "No URLs found." -ForegroundColor Red
    exit
}

# ==============================
# PARALLEL ENGINE
# ==============================
$results = $testUrls | ForEach-Object -Parallel {

    $url = $_

    function Classify-Url($Url) {

try {

    $r = Invoke-WebRequest `
        -Uri $Url `
        -UseBasicParsing `
        -TimeoutSec 8 `
        -MaximumRedirection 5 `
        -ErrorAction Stop

    $content = ""
    if ($r.Content) { $content = $r.Content.ToLower() }

    $finalUrl = ""
    if ($r.BaseResponse.ResponseUri) {
        $finalUrl = $r.BaseResponse.ResponseUri.AbsoluteUri.ToLower()
    }

    $headers = $r.Headers.Keys -join " "
    $headersLower = $headers.ToLower()

    # ==============================
    # 🔥 DEFENDER / WCF DETECTION (ROBUST)
    # ==============================

    $isBlock =
        # Block page text (when available)
        ($content -match "blocked by your organization") -or
        ($content -match "contact your administrator") -or
        ($content -match "web content filtering") -or

        # Redirect hints (VERY IMPORTANT)
        ($finalUrl -match "secure.*?site" -or
         $finalUrl -match "edge.*?block" -or
         $finalUrl -match "microsoft.*?family") -or

        # Proxy / Defender headers / hints
        ($headersLower -match "proxy" -or
         $headersLower -match "arr" -or
         $headersLower -match "edge")

    if ($isBlock) {
        return [PSCustomObject]@{
            URL            = $Url
            Status         = "BLOCKED"
            HttpStatusCode = $r.StatusCode
            DetectionType  = "DEFENDER_WCF_EDGE_BLOCK"
        }
    }

    # ==============================
    # ALLOWED
    # ==============================
    return [PSCustomObject]@{
        URL            = $Url
        Status         = "ALLOWED"
        HttpStatusCode = $r.StatusCode
        DetectionType  = "NONE"
    }

}      catch {

    $msg = $_.Exception.Message
    $type = $_.Exception.GetType().FullName
    $code = "N/A"

    if ($_.Exception.Response) {
        try { $code = [int]$_.Exception.Response.StatusCode } catch {}
    }

    $msgLower = $msg.ToLower()
    $typeLower = $type.ToLower()

    # ==============================
    # 1. HTTP POLICY BLOCKS
    # ==============================
    if ($code -eq 403 -or $code -eq 451) {
        $status = "BLOCKED"
    }

    # ==============================
    # 2. DEFENDER / WCF / TLS RESET (CRITICAL FIX)
    # ==============================
    elseif (
        $typeLower -match "webexception" -and (
            $msgLower -match "closed" -or
            $msgLower -match "aborted" -or
            $msgLower -match "secure channel" -or
            $msgLower -match "ssl" -or
            $msgLower -match "tls" -or
            $msgLower -match "handshake"
        )
    ) {
        $status = "BLOCKED"
    }

    # ==============================
    # 3. DNS ISSUES
    # ==============================
    elseif ($msgLower -match "could not resolve|name does not exist|dns") {
        $status = "DNS_ERROR"
    }

    # ==============================
    # 4. TIMEOUTS
    # ==============================
    elseif ($msgLower -match "timeout|timed out") {
        $status = "TIMEOUT"
    }

    # ==============================
    # 5. TRUE SSL CERT ISSUES ONLY
    # ==============================
    elseif ($msgLower -match "certificate|certificate chain|trust relationship") {
        $status = "SSL_ERROR"
    }

    # ==============================
    # 6. EVERYTHING ELSE (LAST RESORT)
    # ==============================
    else {
        $status = "BLOCKED"
    }

    return [PSCustomObject]@{
        URL            = $Url
        Status         = $status
        HttpStatusCode = $code
        DetectionType  = "$type | $msg"
    }
}
    }

    $out = Classify-Url $url
    Write-Host "$($out.Status) -> $url"
    return $out

} -ThrottleLimit $ThrottleLimit

# ==============================
# EXPORT RESULTS
# ==============================
$results |
    Sort-Object URL |
    Export-Csv $outputCsv -NoTypeInformation -Encoding UTF8

# ==============================
# SUMMARY
# ==============================
$allowed = ($results | Where-Object Status -eq "ALLOWED").Count
$blocked = ($results | Where-Object Status -eq "BLOCKED").Count
$dns     = ($results | Where-Object Status -eq "DNS_ERROR").Count
$timeout = ($results | Where-Object Status -eq "TIMEOUT").Count
$ssl     = ($results | Where-Object Status -eq "SSL_ERROR").Count
$error   = ($results | Where-Object Status -eq "ERROR").Count

Write-Host ""
Write-Host "================ SUMMARY ================" -ForegroundColor Cyan
Write-Host "Allowed   : $allowed"
Write-Host "Blocked   : $blocked"
Write-Host "DNS Error : $dns"
Write-Host "Timeout   : $timeout"
Write-Host "SSL Error : $ssl"
Write-Host "Error     : $error"
Write-Host "Total     : $($results.Count)"

Write-Host ""
Write-Host "Saved to:"
Write-Host $outputCsv