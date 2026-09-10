# AI Readiness Report - Microsoft Entra, Defender & Purview Baseline Assessment

## Overview

This PowerShell solution assesses the following Microsoft security workloads against recommended best-practice baselines and generates a color-coded HTML report with filtering, search, dark mode support, and Microsoft Learn documentation links.

### Supported Workloads

- Microsoft Entra ID
- Microsoft Defender for Cloud
- Microsoft Defender for Endpoint
- Microsoft Defender for Identity
- Microsoft Defender for Office 365
- Microsoft Defender for Cloud Apps
- Microsoft Purview

### Report Output

The assessment generates:

- Interactive HTML Report
- CSV Export
- JSON Export

Status values:

| Status | Meaning |
|----------|----------|
| 🟢 Green | Configured according to recommendation |
| 🟡 Yellow | Partially configured or operating in audit/report-only mode |
| 🔴 Red | Not configured or not meeting recommendation |
| ⚪ Gray | Unable to assess because of permissions, licensing, connectivity, or missing prerequisites |

---

# Features

## Microsoft Entra

- Security Defaults assessment
- Conditional Access review
- Authentication Methods analysis
- Privileged Role review
- PIM adoption analysis
- Application governance checks
- Guest access review

## Defender for Cloud

- Defender Plan validation
- Security Contact configuration
- Secure Score review
- Auto-Provisioning validation
- Microsoft Security integrations

## Defender for Endpoint

- Microsoft Defender Antivirus settings
- Attack Surface Reduction Rules
- Device onboarding validation
- Device health assessment
- Device risk review
- Exposure review

## Defender for Identity

- Sensor inventory
- Sensor health
- Sensor version validation
- Health issue analysis

## Defender for Office 365

- Preset Security Policies
- Anti-Phishing
- Safe Links
- Safe Attachments
- Anti-Malware
- Anti-Spam
- Outbound Spam Protection
- DKIM
- Mailbox Auditing

## Defender for Cloud Apps

- Cloud Discovery
- Conditional Access App Control
- Legacy API checks

## Microsoft Purview

- Unified Audit Logging
- DLP Policies
- Retention Policies
- Retention Labels
- Sensitivity Labels
- Insider Risk
- Communication Compliance

---

# Prerequisites

## PowerShell

PowerShell 7.0 or later is recommended.

Verify:

```powershell
$PSVersionTable.PSVersion
```

---

# Required PowerShell Modules

The script validates required modules at startup.

Required modules:

```powershell
Az.Accounts
Az.Security
Microsoft.Graph.Authentication
ExchangeOnlineManagement
```

Optional installation:

```powershell
.\Invoke-DefenderBestPracticeReport.ps1 -InstallMissingModules
```

---

# Microsoft Graph Authentication

The script supports two authentication models.

## Option 1 – Microsoft Graph Command Line Tools

Default behavior when `-GraphClientId` is not specified.

Advantages:

- No app registration required
- Quick setup

Considerations:

- May prompt for delegated consent
- Permissions cannot be pre-approved

---

## Option 2 – Customer-Owned App Registration (Recommended)

Specify:

```powershell
-GraphClientId "<Application Client ID>"
```

Advantages:

- One-time administrator consent
- Consistent customer experience
- Reduced deployment friction
- Better for recurring assessments

---

# App Registration Configuration

## Supported Account Type

```text
Accounts in this organizational directory only
(Single Tenant)
```

---

## Authentication Platform

Add:

```text
Mobile and desktop applications
```

Configure the following Redirect URIs:

```text
http://localhost
```

```text
https://login.microsoftonline.com/common/oauth2/nativeclient
```

```text
ms-appx-web://Microsoft.AAD.BrokerPlugin/<Application-Client-ID>
```

Example:

```text
ms-appx-web://Microsoft.AAD.BrokerPlugin/21468942-abfc-478b-8723-4020e2964636
```

---

## Public Client Flow

Authentication → Advanced Settings

```text
Allow public client flows = Yes
```

---

## Why Multiple Redirect URIs?

Microsoft Graph PowerShell may use different authentication methods depending on:

- Operating system
- Web Account Manager (WAM)
- Browser-based authentication
- Microsoft Graph SDK version

Providing all redirect URIs improves compatibility and reduces authentication failures across customer environments.

---

# Microsoft Defender for Cloud Apps (MDA) API Token

The Defender for Cloud Apps assessment requires an API token and portal URL to retrieve Microsoft Defender for Cloud Apps configuration and Cloud Discovery data.

## Create an API Token

1. Open Microsoft Defender XDR.
2. Navigate to:

```text
Settings
 └─ Cloud Apps
     └─ System
         └─ API Tokens
```

3. Select:

```text
+ Create token
```

4. Enter a descriptive name.

Example:

```text
AIReadinessReport
```

5. Select **Create**.

6. Copy the generated token and store it securely.

> **Important:** The token value is only displayed once. Store it in a password vault or other secure location before closing the window.

---

## Obtain the Portal URL

The portal URL is unique to each tenant.

Examples:

Commercial:

```text
https://contoso.portal.cloudappsecurity.com
```

GCC:

```text
https://contoso.us.portal.cloudappsecurity.com
```

You can obtain the portal URL from the browser address bar while connected to Microsoft Defender for Cloud Apps.

---

## Example Usage

```powershell
.\Invoke-DefenderBestPracticeReport.ps1 `
    -Modules DefenderForCloudApps `
    -MdaPortalUrl "https://contoso.portal.cloudappsecurity.com" `
    -MdaApiToken "<API Token>"
```

Combined example:

```powershell
.\Invoke-DefenderBestPracticeReport.ps1 `
    -Modules Entra,DefenderForOffice,Purview,DefenderForCloudApps `
    -GraphClientId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
    -MdaPortalUrl "https://contoso.portal.cloudappsecurity.com" `
    -MdaApiToken "<API Token>"
```

---

## Security Recommendations

- Treat the API token as a password.
- Do not commit tokens to GitHub or source control.
- Do not embed tokens in scripts that are shared with others.
- Store tokens in a secure vault whenever possible.
- Revoke and recreate tokens if they are suspected to be compromised.

If an invalid or missing token is supplied, Defender for Cloud Apps checks will be reported as **Gray** because the workload cannot be assessed.
---

## Obtain the MDA Portal URL

The portal URL is unique to each tenant.

Examples:

Commercial:

```text
https://contoso.portal.cloudappsecurity.com
```

US Government:

```text
https://contoso.us.portal.cloudappsecurity.com
```

You can obtain the URL from your browser address bar while logged into Microsoft Defender for Cloud Apps.

---

## Running Defender for Cloud Apps Assessments

Example:

```powershell
.\Invoke-DefenderBestPracticeReport.ps1 `
    -Modules DefenderForCloudApps `
    -MdaPortalUrl "https://contoso.portal.cloudappsecurity.com" `
    -MdaApiToken "<API Token>"
```

Example with additional workloads:

```powershell
.\Invoke-DefenderBestPracticeReport.ps1 `
    -Modules Entra,DefenderForOffice,Purview,DefenderForCloudApps `
    -MdaPortalUrl "https://contoso.portal.cloudappsecurity.com" `
    -MdaApiToken "<API Token>" `
    -GraphClientId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

---

## Security Considerations

- Treat the API token like a password.
- Do not store tokens in source control repositories.
- Do not embed tokens directly into scripts.
- Rotate tokens regularly according to your organization's security policies.
- Revoke unused or compromised tokens immediately.

If the token is invalid or missing, Microsoft Defender for Cloud Apps checks will be reported as **Gray** because the workload cannot be assessed.

---

# Required Microsoft Graph Permissions

Add the following Delegated Microsoft Graph permissions.

| Permission | Purpose |
|------------|----------|
| User.Read | Sign-in |
| Directory.Read.All | Directory configuration |
| Policy.Read.All | Conditional Access |
| Policy.Read.AuthenticationMethod | Authentication Methods |
| RoleManagement.Read.Directory | Roles and PIM |
| DeviceManagementConfiguration.Read.All | Intune Configuration |
| DeviceManagementManagedDevices.Read.All | Managed Devices |
| SecurityIdentitiesSensors.Read.All | Defender for Identity Sensors |
| SecurityIdentitiesHealth.Read.All | Defender for Identity Health |
| CloudApp-Discovery.Read.All | Defender for Cloud Apps |

---

# Grant Admin Consent

After permissions have been configured:

```text
Entra Admin Center
 └─ App registrations
     └─ Your Application
         └─ API Permissions
             └─ Grant Admin Consent
```

All permissions should display:

```text
Granted for <Tenant Name>
```

---

# Azure Permissions

Defender for Cloud assessments require:

```text
Reader
```

or

```text
Security Reader
```

on each subscription being assessed.

Required for:

- Defender Plans
- Security Contacts
- Secure Score
- Auto-Provisioning
- Defender Integrations

---

# Exchange Online and Purview Permissions

Recommended minimum roles:

```text
Global Reader
```

or

```text
Security Reader
```

For advanced Purview workloads:

```text
Compliance Administrator
```

---

# Additional Purview Role Requirements

Certain workloads require dedicated Purview role groups.

## Insider Risk

Requires:

```text
Insider Risk Management
```

or

```text
Insider Risk Management Admins
```

---

## Communication Compliance

Requires:

```text
Communication Compliance
```

role group membership.

---

## Retention Management

Advanced retention operations may require:

```text
Retention Management
```

role membership.

---

# Common Command Examples

## Run All Workloads

```powershell
.\Invoke-DefenderBestPracticeReport.ps1
```

---

## Entra Only

```powershell
.\Invoke-DefenderBestPracticeReport.ps1 `
    -Modules Entra
```

---

## Defender for Office and Purview

```powershell
.\Invoke-DefenderBestPracticeReport.ps1 `
    -Modules DefenderForOffice,Purview
```

---

## Using a Customer-Owned App Registration

```powershell
.\Invoke-DefenderBestPracticeReport.ps1 `
    -GraphClientId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

---

## Defender for Cloud Apps API

```powershell
.\Invoke-DefenderBestPracticeReport.ps1 `
    -Modules DefenderForCloudApps `
    -MdaPortalUrl "https://tenant.portal.cloudappsecurity.com" `
    -MdaApiToken "<token>"
```
## GCC / GCC High Customer

Specify the appropriate Microsoft Graph environment and tenant-specific application registration when connecting to Microsoft Government environments.

### GCC

```powershell
.\Invoke-DefenderBestPracticeReport.ps1 `
    -GraphEnvironment USGov `
    -GraphClientId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
    -Modules Entra,DefenderForOffice,Purview
```

### GCC High

```powershell
.\Invoke-DefenderBestPracticeReport.ps1 `
    -GraphEnvironment USGov `
    -GraphClientId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
    -Modules Entra,DefenderForOffice,Purview,DefenderForIdentity
```

> **Note:** A separate app registration must be created in the customer's GCC/GCC High tenant. Commercial tenant app registrations cannot be used to access Microsoft Government tenants. All required Microsoft Graph delegated permissions must be configured and granted admin consent within the government tenant.
---

# Output

Reports are saved to the same directory where the script is executed.

Generated files:

```text
DefenderBestPractice-<timestamp>.html
DefenderBestPractice-<timestamp>.csv
DefenderBestPractice-<timestamp>.json
```

The HTML report includes:

- Dark mode
- Status filtering
- Product filtering
- Search
- Microsoft Learn links
- Executive summary metrics

---

# Troubleshooting

## Graph Authentication Failed

Verify:

- Redirect URIs configured correctly
- Public Client Flow enabled
- Admin consent granted
- Correct Client ID supplied
- Required delegated permissions assigned

---

## Defender for Cloud Shows Gray

Verify:

- Reader or Security Reader access
- Azure subscription visibility
- Az.Accounts installed
- Az.Security installed

---

## Purview Checks Show Gray

Verify:

- Security & Compliance PowerShell connectivity
- Appropriate Purview role assignment
- Required licensing

---

## Defender for Identity Shows Gray

Verify:

```text
SecurityIdentitiesSensors.Read.All
SecurityIdentitiesHealth.Read.All
```

have been granted and consented.

---

# Security Notice

This script performs read-only assessments.

No settings are modified.

No tenant configuration changes are performed.

All data collection uses supported Microsoft APIs and administrative reporting interfaces.
