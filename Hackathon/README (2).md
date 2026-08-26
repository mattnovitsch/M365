## Invoke-DefenderBestPracticeReport.ps1

Read-only best-practice assessment across **seven Microsoft security and compliance workloads**. Produces a colour-coded, self-contained HTML report (plus CSV and JSON) that you can email, archive, or attach to a customer follow-up.
**Nothing is written to the tenant.** Every call is a GET.

> **Running this against a customer tenant?** Send them [Prerequisites](#prerequisites) ahead of the engagement. Admin consent, Purview role groups, and subscription RBAC all need lead time — the Purview role groups alone can take 30 minutes to propagate.

### Contents

- [What it checks](#what-it-checks)
- [How results are graded](#how-results-are-graded)
- [Prerequisites](#prerequisites)
  - [At a glance](#at-a-glance)
  - [Authentication model](#authentication-model)
  - [Graph scopes and admin consent](#graph-scopes-and-admin-consent)
  - [Roles](#roles)
  - [PowerShell modules](#powershell-modules)
  - [Network access](#network-access)
  - [Pre-flight validation](#pre-flight-validation)
- [Parameters](#parameters)
- [Usage](#usage)
- [Output](#output)
- [Known caveats](#known-caveats)

### What it checks

<table>
<tr>
<th>  
Module
</th>
<th>  
Covers
</th>
</tr>
<tr>
<td>  
**Entra**
</td>
<td>  
Security defaults vs Conditional Access, CA policy patterns (admin MFA, all-user MFA, legacy auth block, device trust, sign-in/user risk, break-glass exclusions), authentication methods, privileged roles and PIM adoption, default user permissions, guest access, app consent
</td>
</tr>
<tr>
<td>  
**DefenderForCloud**
</td>
<td>  
Defender plan tiers per subscription, CSPM extensions, security contacts and alert severity, MDE/MDA/Sentinel integrations, auto-provisioning, secure score
</td>
</tr>
<tr>
<td>  
**DefenderForEndpoint**
</td>
<td>  
Defender AV settings and the full ASR rule set (from Intune settings-catalog policies), device onboarding, sensor health, risk and exposure levels
</td>
</tr>
<tr>
<td>  
**DefenderForIdentity**
</td>
<td>  
Sensor inventory, version currency, health status, service state, delayed updates, open health issues
</td>
</tr>
<tr>
<td>  
**DefenderForOffice**
</td>
<td>  
Preset security policies, anti-phishing, Safe Links, Safe Attachments, anti-malware, inbound/outbound spam, DKIM, mailbox auditing
</td>
</tr>
<tr>
<td>  
**DefenderForCloudApps**
</td>
<td>  
Cloud Discovery streams, MDE discovery integration, Conditional Access App Control
</td>
</tr>
<tr>
<td>  
**Purview**
</td>
<td>  
Unified audit log, DLP policies and rules, retention policies and labels, sensitivity labels, insider risk, communication compliance
</td>
</tr>
</table>


### How results are graded

<table>
<tr>
<th>  
State
</th>
<th>  
Meaning
</th>
</tr>
<tr>
<td>  
🟢 **Green**
</td>
<td>  
Enabled / enforced / blocking
</td>
</tr>
<tr>
<td>  
🟡 **Yellow**
</td>
<td>  
Partial — audit or warn mode, DLP simulation, CA report-only, lower plan tier, or only some objects compliant
</td>
</tr>
<tr>
<td>  
🔴 **Red**
</td>
<td>  
Off, missing, or not configured
</td>
</tr>
<tr>
<td>  
⚪ **Gray**
</td>
<td>  
Could not be evaluated — permissions, missing module, licensing, or workload skipped
</td>
</tr>
</table>

  
**Gray is deliberate.** A permissions failure never scores as a pass, and a missing E5 feature never scores as a misconfiguration.  
The header shows a weighted score: Green = 2 points, Yellow = 1, Red = 0. Gray is excluded from scoring.

### Prerequisites

Everything below is read-only. Give this section to the customer before the engagement so the tenant is ready on day one.

#### At a glance

<table>
<tr>
<th>  
#
</th>
<th>  
Item
</th>
<th>  
Who does it
</th>
<th>  
Lead time
</th>
</tr>
<tr>
<td>  
1
</td>
<td>  
Grant admin consent for the Graph delegated scopes
</td>
<td>  
Privileged Role Admin / Cloud App Admin
</td>
<td>  
5 min, once per tenant
</td>
</tr>
<tr>
<td>  
2
</td>
<td>  
Assign Entra roles to the operator account
</td>
<td>  
Global Admin / Priv. Role Admin
</td>
<td>  
5 min
</td>
</tr>
<tr>
<td>  
3
</td>
<td>  
Assign Azure RBAC on target subscriptions
</td>
<td>  
Subscription Owner
</td>
<td>  
10 min
</td>
</tr>
<tr>
<td>  
4
</td>
<td>  
Assign Exchange / Purview roles
</td>
<td>  
Compliance Admin
</td>
<td>  
10 min
</td>
</tr>
<tr>
<td>  
5
</td>
<td>  
Add operator to Purview role groups (IRM, Comm. Compliance)
</td>
<td>  
Compliance Admin
</td>
<td>  
**Up to 30 min to take effect**
</td>
</tr>
<tr>
<td>  
6
</td>
<td>  
Install PowerShell modules
</td>
<td>  
Operator
</td>
<td>  
10 min
</td>
</tr>
<tr>
<td>  
7
</td>
<td>  
Confirm firewall / proxy allows the endpoints
</td>
<td>  
Network team
</td>
<td>  
Varies
</td>
</tr>
</table>

  
**Plan around item 5.** Insider Risk and Communication Compliance role group membership can take up to 30 minutes to propagate. Until it applies, those checks report Gray — not Red.

#### Authentication model

The script authenticates as **the signed-in user (delegated)**. No app registration, no client secret, no certificate, and no application permissions are requested.

That distinction matters for a security review:

- Consent grants the **Microsoft Graph PowerShell client** permission to act *on behalf of a signed-in user*.
- The operator still cannot read anything their own role does not already permit.
- Consent alone grants no standing access. Both the consent **and** an appropriate role are required.

#### Graph scopes and admin consent

All nine scopes are read-only. None write.

<table>
<tr>
<th>  
Scope
</th>
<th>  
What it reads
</th>
<th>  
Needed by
</th>
</tr>
<tr>
<td>  
Policy.Read.All
</td>
<td>  
Security defaults, Conditional Access, authorization policy, admin consent request policy
</td>
<td>  
Entra, DefenderForCloudApps
</td>
</tr>
<tr>
<td>  
Policy.Read.AuthenticationMethod
</td>
<td>  
Authentication methods policy, registration campaign, migration state
</td>
<td>  
Entra
</td>
</tr>
<tr>
<td>  
RoleManagement.Read.Directory
</td>
<td>  
Role definitions, role assignments, PIM eligibility schedules
</td>
<td>  
Entra
</td>
</tr>
<tr>
<td>  
Directory.Read.All
</td>
<td>  
Directory objects backing the role and policy checks
</td>
<td>  
Entra
</td>
</tr>
<tr>
<td>  
DeviceManagementConfiguration.Read.All
</td>
<td>  
Intune settings-catalog policies (Defender AV, ASR rules)
</td>
<td>  
DefenderForEndpoint
</td>
</tr>
<tr>
<td>  
DeviceManagementManagedDevices.Read.All
</td>
<td>  
Managed device inventory
</td>
<td>  
DefenderForEndpoint
</td>
</tr>
<tr>
<td>  
SecurityIdentitiesSensors.Read.All
</td>
<td>  
MDI sensor inventory, version, health, service state
</td>
<td>  
DefenderForIdentity
</td>
</tr>
<tr>
<td>  
SecurityIdentitiesHealth.Read.All
</td>
<td>  
MDI open health issues
</td>
<td>  
DefenderForIdentity
</td>
</tr>
<tr>
<td>  
CloudApp-Discovery.Read.All
</td>
<td>  
Cloud Discovery uploaded streams
</td>
<td>  
DefenderForCloudApps
</td>
</tr>
</table>

  
Copy-paste list for a change request:
Policy.Read.All
Policy.Read.AuthenticationMethod
RoleManagement.Read.Directory
Directory.Read.All
DeviceManagementConfiguration.Read.All
DeviceManagementManagedDevices.Read.All
SecurityIdentitiesSensors.Read.All
SecurityIdentitiesHealth.Read.All
CloudApp-Discovery.Read.All

**Scoping consent to only what you need.** If the customer will not run all seven workloads, request only the matching scopes. `DefenderForCloud` needs no Graph scopes at all (Azure RBAC only), and `DefenderForOffice` / `Purview` need none either (Exchange and Purview roles only).

**Who can grant consent:** Privileged Role Administrator (any permission on any API), or Cloud Application Administrator / Application Administrator (any permission except Graph *application* permissions — which this script never requests).

⚠️ **Granting tenant-wide admin consent to an app may revoke permissions already granted tenant-wide for that same app.** Permissions users granted on their own behalf are unaffected. If the tenant already uses Graph PowerShell for other automation, record the current scopes first:
Connect-MgGraph -Scopes 'Application.Read.All'
(Get-MgContext).Scopes | Sort-Object

**Option A — interactive consent on first run (recommended).** An admin with one of the roles above runs the script once. The sign-in prompt lists the requested scopes with a *Consent on behalf of your organization* checkbox. Tick it and consent applies tenant-wide, so later operators are never prompted. No URL construction, no portal navigation.

**Option B — Entra admin center (pre-stage).** Entra ID → Enterprise apps → All applications → search **Microsoft Graph Command Line Tools** (app ID `14d82eec-204b-4c2f-b7e8-296a70dab67e`, identical in every tenant) → Security → Permissions → Grant admin consent. If the app is not listed, it has never been used in that tenant — have an admin run `Connect-MgGraph` once, then retry.

**Option C — admin consent URL (fallback).** The documented format is `https://login.microsoftonline.com/{tenant}/v2.0/adminconsent?client_id=...&scope=...&redirect_uri=...&state=12345`, where `{tenant}` is the tenant GUID or a verified domain (not `common`). The catch: `redirect_uri` must exactly match a URI already registered for the client app, and the customer does not own that registration. Prefer A or B.

**Verify consent landed** with `(Get-MgContext).Scopes | Sort-Object` and compare against the list above. Anything missing surfaces as Gray rows, not a hard failure.

#### Roles

**Global Reader + Security Reader covers most of it.** Beyond that:

<table>
<tr>
<th>  
Area
</th>
<th>  
Requirement
</th>
</tr>
<tr>
<td>  
Defender for Cloud
</td>
<td>  
Reader or Security Reader **on each in-scope subscription**. The script enumerates every enabled subscription visible to the account unless -SubscriptionId is supplied; one it cannot read produces Gray rows, not silent omission.
</td>
</tr>
<tr>
<td>  
Defender for Endpoint API
</td>
<td>  
An MDE read role for the signed-in user, in addition to Azure sign-in
</td>
</tr>
<tr>
<td>  
Entra PIM checks
</td>
<td>  
Global Reader, Security Reader, or Privileged Role Administrator — **plus Entra ID P2**. Without P2 the eligibility read returns nothing and reports Gray.
</td>
</tr>
<tr>
<td>  
Unified audit log
</td>
<td>  
The **Audit Logs** role in Exchange Online
</td>
</tr>
<tr>
<td>  
DLP
</td>
<td>  
Global Reader, Compliance Administrator, or View-Only DLP Compliance Management
</td>
</tr>
<tr>
<td>  
Retention policies and labels
</td>
<td>  
Compliance Administrator or a retention management role — reader-flavoured roles are often **not** sufficient here
</td>
</tr>
<tr>
<td>  
Sensitivity labels
</td>
<td>  
An information protection read role
</td>
</tr>
<tr>
<td>  
Insider Risk Management
</td>
<td>  
E5 or Compliance add-on, **plus** the Insider Risk Management / Insider Risk Management Admins role group in Purview
</td>
</tr>
<tr>
<td>  
Communication Compliance
</td>
<td>  
E5 or Compliance add-on, **plus** the Communication Compliance role group in Purview
</td>
</tr>
</table>

  
Two things that catch people out every time:

- **Entra Compliance Administrator is not the same as the Purview role groups**, and does not populate them. Without membership the cmdlets are simply absent from the session and the checks report Gray — correctly, since that is a role/licensing state rather than a misconfiguration.
- **The unified audit log state is read from the Exchange Online session on purpose.** `Get-AdminAuditLogConfig` returns `UnifiedAuditLogIngestionEnabled` as `False` in Security & Compliance PowerShell regardless of the real setting. A Purview-only run still needs a working Exchange session.

#### PowerShell modules

**PowerShell 7+**
<table>
<tr>
<th>  
Module
</th>
<th>  
Minimum
</th>
<th>  
Needed by
</th>
</tr>
<tr>
<td>  
Microsoft.Graph.Authentication
</td>
<td>  
2.0.0
</td>
<td>  
Entra, MDE, MDI, MDA
</td>
</tr>
<tr>
<td>  
Az.Accounts
</td>
<td>  
2.12.0
</td>
<td>  
Defender for Cloud, MDE device posture
</td>
</tr>
<tr>
<td>  
ExchangeOnlineManagement
</td>
<td>  
3.0.0
</td>
<td>  
Defender for Office 365, Purview
</td>
</tr>
</table>

  
Only the modules required by the selected -Modules are checked. The script offers to install anything missing at startup.

The minimums are deliberate: `Get-ConnectionInformation` (used to detect an existing Exchange session) arrived in ExchangeOnlineManagement 3.0.0; `Get-AzAccessToken -ResourceUrl` needs Az.Accounts 2.12.0, and from Az.Accounts 5.0.0 the token comes back as a SecureString — the script handles both shapes. Only the Graph *Authentication* sub-module is needed, not the full meta-module.
Install-Module Az.Accounts, Microsoft.Graph.Authentication, ExchangeOnlineManagement -Scope CurrentUser -Force -AllowClobber

If a module is updated while already loaded, close the session and re-run so the new version loads cleanly.

#### Network access

Outbound HTTPS to the endpoints for the selected -Cloud, plus the sign-in authority for that cloud, the Exchange Online and Security & Compliance PowerShell endpoints, and `www.powershellgallery.com` if modules will be installed on the workstation.

Security & Compliance connection URIs for government clouds: **USGov (GCC High)** `https://ps.compliance.protection.office365.us/powershell-liveid/`, **USGovDoD** `https://l5.ps.compliance.protection.office365.us/powershell-liveid/`. Note that sign-in and consent endpoints in a sovereign cloud differ from the commercial `login.microsoftonline.com` shown above — confirm the correct authority before pre-staging a consent URL.

#### Pre-flight validation

Have the customer run this before the engagement and send back the output. It changes nothing.
\# --- PowerShell version ---
$PSVersionTable.PSVersion
\# --- Modules ---
'Az.Accounts','Microsoft.Graph.Authentication','ExchangeOnlineManagement' | ForEach-Object {
    $m = Get-Module $\_ -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
    \[pscustomobject\]@{ Module = $\_; Installed = if ($m) { $m.Version } else { 'NOT INSTALLED' } }
}
\# --- Graph consent ---
$required = @(
    'Policy.Read.All','Policy.Read.AuthenticationMethod','RoleManagement.Read.Directory',
    'Directory.Read.All','DeviceManagementConfiguration.Read.All',
    'DeviceManagementManagedDevices.Read.All','SecurityIdentitiesSensors.Read.All',
    'SecurityIdentitiesHealth.Read.All','CloudApp-Discovery.Read.All'
)
Connect-MgGraph -NoWelcome -Scopes $required
$granted = (Get-MgContext).Scopes
$required | ForEach-Object {
    \[pscustomobject\]@{ Scope = $\_; Granted = $granted -contains $\_ }
} | Format-Table -AutoSize
\# --- Azure subscriptions visible (Defender for Cloud runs) ---
Connect-AzAccount | Out-Null
Get-AzSubscription | Where-Object State -eq 'Enabled' | Select-Object Name, Id | Format-Table -AutoSize
\# --- Exchange / Purview cmdlet availability ---
Connect-ExchangeOnline -ShowBanner:$false
Connect-IPPSSession
'Get-AdminAuditLogConfig','Get-DlpCompliancePolicy','Get-RetentionCompliancePolicy',
'Get-ComplianceTag','Get-Label','Get-InsiderRiskPolicy','Get-SupervisoryReviewPolicyV2' |
ForEach-Object {
    \[pscustomobject\]@{ Cmdlet = $\_; Available = \[bool\](Get-Command $\_ -ErrorAction SilentlyContinue) }
} | Format-Table -AutoSize

Any cmdlet showing `Available = False`, or any scope showing `Granted = False`, means those checks will report Gray. That is expected behaviour rather than a script failure — but far better discovered a week before the readout than during it.

### Parameters

<table>
<tr>
<th>  
Parameter
</th>
<th>  
Type
</th>
<th>  
Default
</th>
<th>  
Purpose
</th>
</tr>
<tr>
<td>  
-OutputFolder
</td>
<td>  
string
</td>
<td>  
folder the script runs from
</td>
<td>  
Where HTML/CSV/JSON land. Created if missing.
</td>
</tr>
<tr>
<td>  
-Modules
</td>
<td>  
string\[\]
</td>
<td>  
all seven
</td>
<td>  
Which workloads to assess. Values: Entra, DefenderForCloud, DefenderForEndpoint, DefenderForIdentity, DefenderForOffice, DefenderForCloudApps, Purview
</td>
</tr>
<tr>
<td>  
-TenantId
</td>
<td>  
string
</td>
<td>  
—
</td>
<td>  
Entra tenant ID. Used for sign-in and stamped on the report.
</td>
</tr>
<tr>
<td>  
-SubscriptionId
</td>
<td>  
string\[\]
</td>
<td>  
all enabled subs
</td>
<td>  
Limits Defender for Cloud to specific subscriptions.
</td>
</tr>
<tr>
<td>  
-Cloud
</td>
<td>  
string
</td>
<td>  
Global
</td>
<td>  
Global, USGov, or USGovDoD. Switches Graph / ARM / MDE / Exchange endpoints.
</td>
</tr>
<tr>
<td>  
-SkipConnect
</td>
<td>  
switch
</td>
<td>  
off
</td>
<td>  
Reuse existing Az / Graph / Exchange sessions instead of prompting.
</td>
</tr>
<tr>
<td>  
-InstallMissingModules
</td>
<td>  
switch
</td>
<td>  
off
</td>
<td>  
Install missing or outdated modules without prompting.
</td>
</tr>
<tr>
<td>  
-ModuleScope
</td>
<td>  
string
</td>
<td>  
CurrentUser
</td>
<td>  
CurrentUser (no admin rights) or AllUsers (needs elevation; falls back automatically).
</td>
</tr>
<tr>
<td>  
-SkipModuleCheck
</td>
<td>  
switch
</td>
<td>  
off
</td>
<td>  
Bypass the prerequisite check entirely.
</td>
</tr>
<tr>
<td>  
-DisableWam
</td>
<td>  
switch
</td>
<td>  
off
</td>
<td>  
Skip the Exchange WAM broker and go straight to the fallback auth path.
</td>
</tr>
<tr>
<td>  
-ExchangeCredential
</td>
<td>  
PSCredential
</td>
<td>  
—
</td>
<td>  
Final auth fallback for Exchange / Purview. MFA-enforced accounts generally cannot use this path.
</td>
</tr>
<tr>
<td>  
-DumpSettingIds
</td>
<td>  
switch
</td>
<td>  
off
</td>
<td>  
Diagnostic. Writes every Intune setting definition ID your tenant returns, its value, interpreted state, and which map entry matched.
</td>
</tr>
<tr>
<td>  
-MdaPortalUrl
</td>
<td>  
string
</td>
<td>  
—
</td>
<td>  
Defender for Cloud Apps portal URL, for the legacy MDA REST checks.
</td>
</tr>
<tr>
<td>  
-MdaApiToken
</td>
<td>  
string
</td>
<td>  
—
</td>
<td>  
MDA API token. Without it, MDA REST-only checks report Gray.
</td>
</tr>
</table>


### Usage
\# Everything, reports land next to the script
.\\Invoke-DefenderBestPracticeReport.ps1
\# Identity baseline only - Graph sign-in only, no Azure or Exchange
.\\Invoke-DefenderBestPracticeReport.ps1 -Modules Entra
\# The two Exchange-backed workloads, skipping the WAM broker
.\\Invoke-DefenderBestPracticeReport.ps1 -Modules DefenderForOffice,Purview -DisableWam
\# Diagnose ASR / AV rule matching against your actual tenant
.\\Invoke-DefenderBestPracticeReport.ps1 -Modules DefenderForEndpoint -DumpSettingIds
\# Unattended, government cloud
.\\Invoke-DefenderBestPracticeReport.ps1 -InstallMissingModules -Cloud USGov -OutputFolder C:\\Reports

### Output
  
Three timestamped files per run:
- DefenderBestPractice-\<timestamp\>.html — the report
- DefenderBestPractice-\<timestamp\>.csv — flat table, good for FTOP notes and tracking
- DefenderBestPractice-\<timestamp\>.json — full result set for scripting  
The HTML report is fully self-contained (no external CSS, fonts, or scripts) and includes:
- **Light/dark toggle** at the right of the filter row. Follows your OS setting on first open, then remembers your choice per browser. Printing always forces the light palette.
- **Status filters** and a free-text search box
- Findings sorted worst-first within each workload  
The report enumerates security gaps and privileged role counts — **treat it as confidential.**

### Known caveats
- **Not yet validated end-to-end against a production tenant.** Structurally validated only. Two areas most likely to need tuning: Purview sensitivity-label property names, and Entra Conditional Access pattern matching (policies are detected structurally by grant controls and conditions, so an unconventionally built policy may read as missing).
- **ASR rules** are matched on friendly-name tokens first, GUID second. If a rule reports incorrectly, run -DumpSettingIds and compare against the map rather than guessing.
- **Exchange / Purview auth** can fail with a RuntimeBroker NullReferenceException on ExchangeOnlineManagement 3.7.0+. The script retries automatically (standard → -DisableWAM → credentials). The most common fix is simply running from a **non-elevated** console as the signed-in Windows user.
- **PIM checks** need Entra ID P2. Without it they report Gray, not Red.
