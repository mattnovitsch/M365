# Invoke-DefenderBestPracticeReport.ps1

Read-only best-practice assessment across **seven Microsoft security and compliance workloads**. Produces a colour-coded, self-contained HTML report (plus CSV and JSON) that you can email, archive, or attach to a customer follow-up.

**Nothing is written to the tenant.** Every call is a GET.

---

## What it checks

| Module | Covers |
|---|---|
| **Entra** | Security defaults vs Conditional Access, CA policy patterns (admin MFA, all-user MFA, legacy auth block, device trust, sign-in/user risk, break-glass exclusions), authentication methods, privileged roles and PIM adoption, default user permissions, guest access, app consent |
| **DefenderForCloud** | Defender plan tiers per subscription, CSPM extensions, security contacts and alert severity, MDE/MDA/Sentinel integrations, auto-provisioning, secure score |
| **DefenderForEndpoint** | Defender AV settings and the full ASR rule set (from Intune settings-catalog policies), device onboarding, sensor health, risk and exposure levels |
| **DefenderForIdentity** | Sensor inventory, version currency, health status, service state, delayed updates, open health issues |
| **DefenderForOffice** | Preset security policies, anti-phishing, Safe Links, Safe Attachments, anti-malware, inbound/outbound spam, DKIM, mailbox auditing |
| **DefenderForCloudApps** | Cloud Discovery streams, MDE discovery integration, Conditional Access App Control |
| **Purview** | Unified audit log, DLP policies and rules, retention policies and labels, sensitivity labels, insider risk, communication compliance |

---

## How results are graded

| State | Meaning |
|---|---|
| 🟢 **Green** | Enabled / enforced / blocking |
| 🟡 **Yellow** | Partial — audit or warn mode, DLP simulation, CA report-only, lower plan tier, or only some objects compliant |
| 🔴 **Red** | Off, missing, or not configured |
| ⚪ **Gray** | Could not be evaluated — permissions, missing module, licensing, or workload skipped |

**Gray is deliberate.** A permissions failure never scores as a pass, and a missing E5 feature never scores as a misconfiguration.

The header shows a weighted score: Green = 2 points, Yellow = 1, Red = 0. Gray is excluded from scoring.

---

## Parameters

| Parameter | Type | Default | Purpose |
|---|---|---|---|
| `-OutputFolder` | string | folder the script runs from | Where HTML/CSV/JSON land. Created if missing. |
| `-Modules` | string[] | all seven | Which workloads to assess. Values: `Entra`, `DefenderForCloud`, `DefenderForEndpoint`, `DefenderForIdentity`, `DefenderForOffice`, `DefenderForCloudApps`, `Purview` |
| `-TenantId` | string | — | Entra tenant ID. Used for sign-in and stamped on the report. |
| `-SubscriptionId` | string[] | all enabled subs | Limits Defender for Cloud to specific subscriptions. |
| `-Cloud` | string | `Global` | `Global`, `USGov`, or `USGovDoD`. Switches Graph / ARM / MDE / Exchange endpoints. |
| `-SkipConnect` | switch | off | Reuse existing Az / Graph / Exchange sessions instead of prompting. |
| `-InstallMissingModules` | switch | off | Install missing or outdated modules without prompting. |
| `-ModuleScope` | string | `CurrentUser` | `CurrentUser` (no admin rights) or `AllUsers` (needs elevation; falls back automatically). |
| `-SkipModuleCheck` | switch | off | Bypass the prerequisite check entirely. |
| `-DisableWam` | switch | off | Skip the Exchange WAM broker and go straight to the fallback auth path. |
| `-ExchangeCredential` | PSCredential | — | Final auth fallback for Exchange / Purview. MFA-enforced accounts generally cannot use this path. |
| `-DumpSettingIds` | switch | off | Diagnostic. Writes every Intune setting definition ID your tenant returns, its value, interpreted state, and which map entry matched. |
| `-MdaPortalUrl` | string | — | Defender for Cloud Apps portal URL, for the legacy MDA REST checks. |
| `-MdaApiToken` | string | — | MDA API token. Without it, MDA REST-only checks report Gray. |

---

## Usage

```powershell
# Everything, reports land next to the script
.\Invoke-DefenderBestPracticeReport.ps1

# Identity baseline only - Graph sign-in only, no Azure or Exchange
.\Invoke-DefenderBestPracticeReport.ps1 -Modules Entra

# The two Exchange-backed workloads, skipping the WAM broker
.\Invoke-DefenderBestPracticeReport.ps1 -Modules DefenderForOffice,Purview -DisableWam

# Diagnose ASR / AV rule matching against your actual tenant
.\Invoke-DefenderBestPracticeReport.ps1 -Modules DefenderForEndpoint -DumpSettingIds

# Unattended, government cloud
.\Invoke-DefenderBestPracticeReport.ps1 -InstallMissingModules -Cloud USGov -OutputFolder C:\Reports
```

---

## Requirements

**PowerShell 7+**

| Module | Minimum | Needed by |
|---|---|---|
| `Microsoft.Graph.Authentication` | 2.0.0 | Entra, MDE, MDI, MDA |
| `Az.Accounts` | 2.12.0 | Defender for Cloud, MDE device posture |
| `ExchangeOnlineManagement` | 3.0.0 | Defender for Office 365, Purview |

Only the modules required by the selected `-Modules` are checked. The script offers to install anything missing at startup.

**Roles:** Global Reader + Security Reader covers most of it. Defender for Cloud additionally needs Reader or Security Reader on each subscription. Purview needs a compliance read role. Insider Risk and Communication Compliance need E5 plus their own role assignments — where absent, those checks report Gray.

**Graph scopes requested:** `Policy.Read.All`, `Policy.Read.AuthenticationMethod`, `RoleManagement.Read.Directory`, `Directory.Read.All`, `DeviceManagementConfiguration.Read.All`, `DeviceManagementManagedDevices.Read.All`, `SecurityIdentitiesHealth.Read.All`, `SecurityIdentitiesSensors.Read.All`, `CloudApp-Discovery.Read.All`

---

## Output

Three timestamped files per run:

- `DefenderBestPractice-<timestamp>.html` — the report
- `DefenderBestPractice-<timestamp>.csv` — flat table, good for FTOP notes and tracking
- `DefenderBestPractice-<timestamp>.json` — full result set for scripting

The HTML report is fully self-contained (no external CSS, fonts, or scripts) and includes:

- **Light/dark toggle** at the right of the filter row. Follows your OS setting on first open, then remembers your choice per browser. Printing always forces the light palette.
- **Status filters** and a free-text search box
- Findings sorted worst-first within each workload

---

## Known caveats

- **Not yet validated end-to-end against a production tenant.** Structurally validated only. Two areas most likely to need tuning: Purview sensitivity-label property names, and Entra Conditional Access pattern matching (policies are detected structurally by grant controls and conditions, so an unconventionally built policy may read as missing).
- **ASR rules** are matched on friendly-name tokens first, GUID second. If a rule reports incorrectly, run `-DumpSettingIds` and compare against the map rather than guessing.
- **Exchange / Purview auth** can fail with a `RuntimeBroker` NullReferenceException on ExchangeOnlineManagement 3.7.0+. The script retries automatically (standard → `-DisableWAM` → credentials). The most common fix is simply running from a **non-elevated** console as the signed-in Windows user.
- **PIM checks** need Entra ID P2. Without it they report Gray, not Red.
