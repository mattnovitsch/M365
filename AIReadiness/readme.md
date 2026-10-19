# Securing Generative AI Usage with Microsoft Security

Generative AI introduces a new challenge for security teams: **you cannot secure what you cannot see**.

### AI usage can appear in several different forms across the enterprise:

* Users accessing public generative AI services from browsers
* Developers installing local AI coding agents and CLI tools
* AI agents connecting to Model Context Protocol (MCP) servers and tools
* AI agents processing files, websites, repositories, prompts, and tool output
* AI applications interacting with sensitive corporate information

The goal should not be to block AI. The goal is to establish **visibility, understand risk, and put appropriate guardrails around how AI is used**.

## What's New (October 2026 Update)

| Area | Update |
| --- | --- |
| **Local AI agent discovery (Defender for Endpoint)** | Discovery now covers **Windows and macOS**. **macOS discovery is still in preview.** Agents appear after Defender **observes agent activity**, so an installed but unused agent might not appear. Discovery isn't a full software inventory. Use Defender Vulnerability Management software inventory for that. |
| **Discovery licensing** | **Defender for Endpoint Plan 2** is the minimum license for discovery, the inventory, and Advanced Hunting (`AgentsInfo`). **Risk level, risk indicators, and security recommendations** require **Microsoft 365 E7** or **Microsoft Agent 365 + Defender for Endpoint Plan 2**. |
| **Where to find agents** | Defender portal: **Assets > AI agents > Local agents**. Agent pages include an **Attack surface map** and **Security recommendations** tab. |
| **Advanced Hunting** | Use `AgentsInfo` (`Platform == "LocalAgents"`) together with `ExposureGraphNodes` and `ExposureGraphEdges` to map agents to their devices, users, MCP servers, and reachable critical assets. |
| **AI agent runtime protection (Preview)** | Defender now uses two inspection methods. **Agent-native event inspection** works through vendor hooks, for example Claude Code, Codex CLI, and GitHub Copilot CLI. **Network inspection** covers agent-to-LLM traffic for agents without hooks. Network inspection doesn't support agents that use **certificate pinning or HTTP/3**. |
| **Runtime protection alerting** | Both **Audit** and **Block** raise a **Suspicious AI prompt injection** alert in Defender. Block also notifies the user and records the event in device protection history. The setting is protected by **tamper protection**. |
| **Secure Score: AI-Readiness (GA, Sept 2026)** | New device recommendations tagged **AI-Readiness**: TPM 2.0, VBS, HVCI, and Windows LAPS. Path: **Exposure Management > Recommendations > Devices > Misconfigurations**, then filter by the **AI-Readiness** tag. |
| **Purview DSPM** | **DSPM for AI (classic)** has been replaced by the new **Data Security Posture Management** experience. New AI capabilities aren't being added to the classic version. |
| **Shadow AI prerequisites** | Frontier opt-in, Defender for Endpoint, **Microsoft 365 E5**, and **Intune enrollment** for managed Windows devices. **Global Secure Access** is optional and adds usage metadata. |

## Government Cloud Availability

> [!IMPORTANT]
> Microsoft 365 Government environments don't always have feature parity with the Commercial cloud. Preview AI security capabilities can be especially limited. **Validate availability for GCC, GCC High, and DoD before designing a control around a feature.**

| Capability in this guide | Commercial | GCC | GCC High | DoD | Government tenant note |
| --- | --- | --- | --- | --- | --- |
| Microsoft Defender for Endpoint core service | Available | Available | Available | Available | Defender for Endpoint has dedicated US Government offerings, but Microsoft documents feature-parity gaps with Commercial. |
| **Local AI agent discovery in Defender for Endpoint** | Available on Windows; **Preview on macOS** | **Not supported** | **Not supported** | **Not supported** | Microsoft explicitly requires the Commercial cloud and states that sovereign and national clouds aren't supported. This also affects the `AgentsInfo`-based local-agent inventory described below. |
| **Local AI agent risk level, risk indicators, and recommendations** | Requires Microsoft 365 E7 or Agent 365 + MDE P2 | **Not supported** | **Not supported** | **Not supported** | Depends on local AI agent discovery, which is Commercial-only. |
| **Shadow AI in Microsoft 365 admin center** | Preview / Frontier | **Not currently documented as supported** | **Not currently documented as supported** | **Not currently documented as supported** | Shadow AI depends on Defender for Endpoint local AI agent discovery. Because that prerequisite is Commercial-only, don't position the current Shadow AI experience as available for Government tenants unless Microsoft updates the documentation. |
| **AI agent runtime protection in Defender for Endpoint** | Preview | **Verify before use** | **Verify before use** | **Verify before use** | Current runtime-protection documentation describes prerequisites and supported agents but doesn't explicitly document GCC/GCC High/DoD availability. Treat Government support as unconfirmed rather than assuming Commercial parity. |
| Microsoft Defender for Cloud Apps / Cloud Discovery | Available | Available with Government-specific service differences | Available with Government-specific service differences | Available with Government-specific service differences | Defender for US Government is available, but Microsoft documents that Government functionality can differ from Commercial. Validate the specific Cloud Discovery / Generative AI workflow you plan to use. |
| Microsoft Purview AI data-security capabilities / DSPM | Available according to licensing and prerequisites | **Verify individual capability** | **Verify individual capability** | **Verify individual capability** | Purview AI capabilities have their own licensing, workload, and cloud prerequisites. The referenced DSPM documentation doesn't provide a single GCC/GCC High/DoD parity statement for every AI feature in this guide. |
| Microsoft 365 Baseline Security Mode | Available | **Verify in tenant** | **Verify in tenant** | **Verify in tenant** | Microsoft states BSM can be configured on all Microsoft 365 subscriptions and plans, but the referenced page is the Worldwide service view and doesn't explicitly establish Government-cloud parity for every BSM setting. |

**Bottom line for Government customers:** The core Defender platform exists in US Government clouds, but the newer AI-specific capabilities in this guide shouldn't be assumed to have Commercial parity. The clearest documented gap today is **Defender for Endpoint local AI agent discovery**, which explicitly excludes sovereign and national clouds. Since the current **Shadow AI** experience depends on that capability, Government customers should also treat Shadow AI as unavailable/unconfirmed until Microsoft publishes Government-cloud support.

**Microsoft Learn references for Government availability:**

* [Microsoft Defender for Endpoint for US Government customers](https://learn.microsoft.com/en-us/defender-endpoint/gov)
* [Discover local AI agents with Microsoft Defender for Endpoint](https://learn.microsoft.com/en-us/defender-endpoint/discover-local-ai-agents)
* [Understand Shadow AI in Microsoft 365 admin center](https://learn.microsoft.com/en-us/microsoft-365/admin/manage/agent-shadow-ai?view=o365-worldwide)
* [Baseline security mode settings](https://learn.microsoft.com/en-us/microsoft-365/baseline-security-mode/baseline-security-mode-settings?view=o365-worldwide)

## Questions Microsoft Security Can Help Answer

| Security question | Microsoft capability |
| --- | --- |
| What local AI agents are installed and active? | Microsoft Defender for Endpoint |
| Which users and devices are running them? | Microsoft Defender for Endpoint |
| What MCP servers are configured? | Microsoft Defender for Endpoint |
| Which agents auto-approve their own actions or run in an untrusted host process? | Microsoft Defender for Endpoint (Advanced Hunting) |
| Which agents run on critical devices or reach sensitive assets? | Microsoft Defender for Endpoint + Exposure Management |
| Can local agents be investigated with Advanced Hunting? | Microsoft Defender for Endpoint |
| Can supported agent activity be inspected for prompt injection? | Microsoft Defender for Endpoint AI agent runtime protection |
| Are endpoints hardened against AI-accelerated attacks? | Microsoft Secure Score AI-Readiness recommendations |
| Which cloud AI services are users accessing? | Microsoft Defender for Cloud Apps |
| Which users are accessing those services? | Microsoft Defender for Cloud Apps |
| Can discovered AI services be assessed and sanctioned or unsanctioned? | Microsoft Defender for Cloud Apps |
| Can sensitive-data interactions with AI be investigated? | Microsoft Purview Data Security Posture Management |
| Where can unmanaged or unapproved AI agents be reviewed? | Shadow AI in the Microsoft 365 admin center |
| How can broader Microsoft 365 security defaults be established? | Microsoft 365 Baseline Security Mode |

## AI Security Layers at a Glance

| Layer | Security question | Microsoft capability |
| --- | --- | --- |
| Endpoint readiness | Are devices hardened for AI-era threats? | Secure Score AI-Readiness recommendations |
| Local AI discovery | What agents are active, and what can they reach? | Microsoft Defender for Endpoint |
| Shadow AI | What unmanaged agents are being used? | Shadow AI in the Microsoft 365 admin center |
| Cloud AI discovery | What AI sites, applications, and domains are being accessed? | Microsoft Defender for Cloud Apps |
| Data guardrails | What sensitive information can users share with AI? | Microsoft Purview |
| Runtime guardrails | Is a supported local agent encountering prompt injection or high-risk activity? | Microsoft Defender for Endpoint AI agent runtime protection |
| Microsoft 365 hardening | What foundational Microsoft 365 security controls should be reviewed? | Microsoft 365 Baseline Security Mode |

## Where Do I Start?

Do not start by blocking AI tools before understanding what is being used. Start with visibility, then move toward governance and enforcement.

### 1. Discover Local AI Agents

Use Microsoft Defender for Endpoint to identify supported local AI agents on managed **Windows and macOS** endpoints. Defender shows the agent, device, user or account, and configured MCP servers. You can also investigate local AI agents with Advanced Hunting.

**Prerequisites:**

* Commercial cloud
* Microsoft Defender for Endpoint Plan 2
* Devices onboarded to Defender for Endpoint
* Microsoft Defender Antivirus in **active mode** with **real-time protection** enabled and current monthly platform and engine updates

No extra deployment or scripts are required. Discovery starts automatically once the prerequisites are met.

**Portal path:** Microsoft Defender portal > **Assets** > **AI agents** > **Local agents**

> [!NOTE]
> Defender lists an agent **after it observes agent activity**. An installed agent that hasn't been used might not appear. Discovery provides security context. It isn't a complete software inventory.

> [!NOTE]
> **Licensing:** MDE Plan 2 covers discovery, the inventory, and Advanced Hunting. **Risk level, risk indicators, and security recommendations** require **Microsoft 365 E7** or **Microsoft Agent 365 + MDE Plan 2**.

> [!NOTE]
> **Government cloud:** Microsoft currently documents this capability as Commercial-cloud only. Sovereign and national clouds aren't supported, so this local AI agent inventory and its related Advanced Hunting workflow shouldn't be expected in GCC, GCC High, or DoD.

What AI agents are running on my endpoints, who is using them, and what are they connected to?

**Advanced Hunting starter query: current local AI agent inventory**

```kql
AgentsInfo
| where Platform == "LocalAgents"
| summarize arg_max(Timestamp, Name, Version, LifecycleStatus, RawAgentInfo) by AgentId
| where LifecycleStatus !in~ ("Deleted", "Uninstalled")
| extend AgentMetadata = RawAgentInfo.localAgentMetadata
| extend Vendor = tostring(AgentMetadata.vendor),
         Process = tostring(AgentMetadata.relatedProcess),
         Device = tostring(AgentMetadata.deviceName),
         Account = tostring(AgentMetadata.accountName)
| summarize Installations = count(),
            DeviceCount = dcount(Device),
            Devices = make_set(Device, 100),
            Versions = make_set(Version, 20),
            Accounts = make_set_if(Account, isnotempty(Account), 50)
    by Agent = Name, Vendor, Process
| sort by DeviceCount desc, Installations desc
```

**Advanced Hunting starter query: agents with risky configurations**

> [!TIP]
> `autoApprove` and `trustedProcess` are reported as **strings**. Compare them to `"true"` or `"false"`. Don't use `tobool()`.

```kql
AgentsInfo
| where Platform == "LocalAgents"
| summarize arg_max(Timestamp, Name, Version, LifecycleStatus, RawAgentInfo) by AgentId
| where LifecycleStatus !in~ ("Deleted", "Uninstalled")
| extend AgentMetadata = RawAgentInfo.localAgentMetadata
| extend AutoApprove = tostring(AgentMetadata.autoApprove),
         TrustedProcess = tostring(AgentMetadata.trustedProcess),
         Device = tostring(AgentMetadata.deviceName),
         Account = tostring(AgentMetadata.accountName)
| where AutoApprove =~ "true" or TrustedProcess =~ "false"
| project Agent = Name, Version, Device, Account, AutoApprove, TrustedProcess, LastSeen = Timestamp
| sort by Device asc, Agent asc
```

**Microsoft Learn:**

* [Local AI agent discovery with Microsoft Defender for Endpoint](https://learn.microsoft.com/en-us/defender-endpoint/local-agent-discovery-overview)
* [Discover local AI agents with Microsoft Defender for Endpoint](https://learn.microsoft.com/en-us/defender-endpoint/discover-local-ai-agents)

### 2. Understand Shadow AI

After agents are discovered, determine whether they are known and approved. The Shadow AI experience in the Microsoft 365 admin center is designed to help administrators discover, monitor, and govern unmanaged AI agents.

**Prerequisites:**

* Opt in to the **Frontier** preview in the Microsoft 365 admin center
* Defender for Endpoint enabled on devices for local agent detection
* **Microsoft 365 E5** license
* **Microsoft Intune enrollment** for managed Windows devices
* Optional: **Global Secure Access** for more usage metadata

> [!NOTE]
> **Government cloud:** The current Shadow AI preview requires Defender for Endpoint local AI agent discovery. Because Microsoft documents that discovery prerequisite as Commercial-cloud only, treat this Shadow AI experience as unavailable/unconfirmed for GCC, GCC High, and DoD until Government support is explicitly documented.

Which AI agents are being used without IT visibility or approval?

**Microsoft Learn:** [Understand Shadow AI in Microsoft 365 admin center](https://learn.microsoft.com/en-us/microsoft-365/admin/manage/agent-shadow-ai?view=o365-worldwide)

### 3. Discover Cloud Generative AI Usage

Not every AI tool is installed locally. Users might access generative AI services through browsers or cloud applications. Microsoft Defender for Cloud Apps provides Cloud Discovery visibility into cloud applications accessed across the organization.

Security teams can review discovered applications in the **Generative AI** category, identify associated domains and users, review available usage and risk information, and determine whether applications align with organizational policy.

> [!IMPORTANT]
> When an app is marked **Unsanctioned**, it's automatically blocked on devices onboarded to Defender for Endpoint. To warn and educate users instead of blocking, configure that option before unsanctioning apps.

> [!NOTE]
> **Government cloud:** Defender services are available in US Government environments, but Microsoft documents feature differences from Commercial. Validate the specific Generative AI Cloud Discovery experience in the target Government tenant before relying on it.

Which generative AI services and domains are users accessing?

**Microsoft Learn:**

* [View discovered apps with the Cloud Discovery dashboard](https://learn.microsoft.com/en-us/defender-cloud-apps/discovered-apps)
* [Manage generative AI apps for your organization](https://learn.microsoft.com/en-us/copilot/microsoft-365/manage-generative-ai-apps)

### 4. Protect Data Going to AI with Microsoft Purview

Microsoft Purview provides the data-security side of the AI guardrail strategy. Defender helps identify the AI applications and agents being used, while Purview addresses a separate question:

What corporate data are users sharing with AI?

### Relevant Microsoft Purview capabilities include:

* **Data Security Posture Management (DSPM):** Identifies and manages data-security risks associated with AI usage. **DSPM for AI (classic) has been replaced by the new DSPM experience.** New capabilities aren't being added to the classic version.
* **Information Protection:** Identifies and protects sensitive information used in supported AI interactions.
* **Data Loss Prevention (DLP):** Applies policies that control sensitive information shared with supported AI applications.
* **Endpoint DLP:** Can warn or block users when they attempt to share sensitive information with supported third-party generative AI sites.
* **Insider Risk Management:** The **Risky AI usage** policy template detects risky usage, including prompt injection attacks, and feeds these signals into Microsoft Defender XDR.
* **Audit and compliance capabilities:** Support investigation and governance of covered Copilot, agent, enterprise AI, and other generative AI interactions.

This creates an important guardrail: an AI application might be permitted, but sensitive organizational data still requires protection.

> [!NOTE]
> **Government cloud:** Don't assume every Purview AI or DSPM feature described here is present in GCC, GCC High, or DoD. Validate the individual capability, licensing, supported workload, and cloud before deployment.

**Microsoft Learn:**

* [Microsoft Purview data security and compliance protections for generative AI apps](https://learn.microsoft.com/en-us/purview/ai-microsoft-purview)
* [Considerations for deploying Microsoft Purview DSPM for AI (classic)](https://learn.microsoft.com/en-us/purview/dspm-for-ai-considerations)

### 5. Add Runtime Guardrails

Discovery tells you that an AI agent exists. Runtime protection addresses what happens when an agent processes malicious content or attempts a risky action.

Microsoft Defender for Endpoint AI agent runtime protection (Preview) inspects critical points in the agent loop for prompt injection and high-risk agent activity. It uses two inspection methods:

| Method | How it works | Example coverage |
| --- | --- | --- |
| **Agent-native event inspection** | Uses vendor-supported agent hooks to audit or block at points in the agent workflow | Claude Code, Codex CLI, GitHub Copilot CLI |
| **Network inspection** | Inspects covered agent-to-LLM network traffic for agents without hooks | Agents listed for network inspection in the support matrix |

> [!NOTE]
> Network inspection doesn't support agents that use **certificate pinning** or **HTTP/3**.

**Modes:**

| Mode | Behavior | Alert raised? |
| --- | --- | --- |
| **Audit** | Allows the action and records the detection | **Yes.** A Defender security alert is raised. |
| **Block** | Blocks the threat, notifies the user in the agent UI and with a Windows toast notification, and records the event in device protection history | **Yes.** A Defender security alert is raised and correlated into incidents. |
| **Disabled** | No inspection | No |

Detections raise a **Suspicious AI prompt injection** alert. Microsoft recommends starting in **Audit** mode before moving to **Block**. The setting is protected by **tamper protection**.

**Prerequisites:** MDE Plan 2, Microsoft 365 E5, Microsoft Agent 365, or Microsoft 365 E7; devices onboarded with Defender Antivirus in active mode with real-time protection on; supported Windows version with current platform, engine, and security intelligence updates; and a supported local AI agent installed.

> [!NOTE]
> **Government cloud:** Current Microsoft runtime-protection documentation doesn't explicitly confirm GCC, GCC High, or DoD availability. Treat Government support as **unconfirmed** and validate it before including runtime protection in a Government deployment plan.

**Microsoft Learn:**

* [AI agent runtime protection with Microsoft Defender for Endpoint (Preview)](https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-runtime-protection-overview)
* [Set up AI agent runtime protection with Microsoft Defender for Endpoint (Preview)](https://learn.microsoft.com/en-us/defender-endpoint/configure-ai-agent-runtime-protection)

### 6. Harden Endpoints with AI-Readiness Recommendations

Microsoft Secure Score includes **AI-Readiness** device recommendations (GA, September 2026) that help harden endpoints against AI-accelerated attacks:

* **TPM 2.0:** Hardware root of trust
* **VBS:** Isolates critical security functions
* **HVCI:** Enforces kernel code integrity
* **Windows LAPS:** Limits lateral movement through reused local admin credentials

**Portal path:**

1. Go to [https://security.microsoft.com](https://security.microsoft.com).
2. Go to **Exposure Management** > **Recommendations** > **Devices** > **Misconfigurations**.
3. Filter by the **AI-Readiness** tag.

**Microsoft Learn:** [What's new in Microsoft Defender for Endpoint](https://learn.microsoft.com/en-us/defender-endpoint/whats-new-in-microsoft-defender-endpoint)

### 7. Establish a Microsoft 365 Security Baseline

AI-specific controls should be part of a broader security strategy. Review Microsoft 365 Baseline Security Mode alongside AI security controls to understand the broader security configuration of the Microsoft 365 environment.

> [!NOTE]
> **Government cloud:** Microsoft states that BSM can be configured on all Microsoft 365 subscriptions and plans, but the current BSM page is published in the Worldwide service view. Validate the BSM experience and each setting in the target GCC, GCC High, or DoD tenant rather than assuming complete parity.

**Microsoft 365 admin center:** [Open Baseline Security Mode](https://admin.cloud.microsoft/?#/baselinesecuritymode)

## A Simple AI Security Strategy

```
Discover -> Understand -> Assess -> Audit -> Control -> Monitor
```

* **Discover:** Identify local AI agents, MCP configurations, cloud AI applications, domains, users, and devices.
* **Understand:** Determine how employees use AI and where unmanaged or Shadow AI exists.
* **Assess:** Determine whether discovered tools align with security, compliance, and data-handling requirements. Review agent risk, auto-approve settings, and reach to critical assets.
* **Audit:** Use audit capabilities where available to understand behavior before enforcement.
* **Control:** Apply appropriate data and runtime guardrails based on policy and risk.
* **Monitor:** Continue looking for new agents, applications, services, domains, and usage patterns.

## Key Takeaway

AI security is not one product or one control. Microsoft Defender for Endpoint, Microsoft Defender for Cloud Apps, Shadow AI, Microsoft Purview, and Microsoft 365 security controls provide different parts of the visibility and protection story.

Find out what AI is being used in your environment, understand the associated data and runtime risks, and then decide what should be allowed, monitored, audited, governed, restricted, or blocked.

For Government customers, add one more step: **validate cloud availability before selecting the control**. A capability available in Commercial or Preview shouldn't automatically be assumed to exist in GCC, GCC High, or DoD.

## Microsoft Learn References

* [Local AI agent discovery with Microsoft Defender for Endpoint](https://learn.microsoft.com/en-us/defender-endpoint/local-agent-discovery-overview)
* [Discover local AI agents with Microsoft Defender for Endpoint](https://learn.microsoft.com/en-us/defender-endpoint/discover-local-ai-agents)
* [AI agent runtime protection with Microsoft Defender for Endpoint (Preview)](https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-runtime-protection-overview)
* [Set up AI agent runtime protection with Microsoft Defender for Endpoint (Preview)](https://learn.microsoft.com/en-us/defender-endpoint/configure-ai-agent-runtime-protection)
* [What's new in Microsoft Defender for Endpoint](https://learn.microsoft.com/en-us/defender-endpoint/whats-new-in-microsoft-defender-endpoint)
* [Understand Shadow AI in Microsoft 365 admin center](https://learn.microsoft.com/en-us/microsoft-365/admin/manage/agent-shadow-ai?view=o365-worldwide)
* [View discovered apps with the Cloud Discovery dashboard](https://learn.microsoft.com/en-us/defender-cloud-apps/discovered-apps)
* [Manage generative AI apps for your organization](https://learn.microsoft.com/en-us/copilot/microsoft-365/manage-generative-ai-apps)
* [Microsoft Purview data security and compliance protections for generative AI apps](https://learn.microsoft.com/en-us/purview/ai-microsoft-purview)
* [Considerations for deploying Microsoft Purview DSPM for AI (classic)](https://learn.microsoft.com/en-us/purview/dspm-for-ai-considerations)
* [Microsoft Defender for Endpoint for US Government customers](https://learn.microsoft.com/en-us/defender-endpoint/gov)
* [Baseline security mode settings](https://learn.microsoft.com/en-us/microsoft-365/baseline-security-mode/baseline-security-mode-settings?view=o365-worldwide)
* [Microsoft 365 admin center: Baseline Security Mode](https://admin.cloud.microsoft/?#/baselinesecuritymode)
