# Securing Generative AI Usage with Microsoft Security

Generative AI introduces a new challenge for security teams: **you cannot secure what you cannot see**.

AI usage can appear in several different forms across the enterprise:

- Users accessing public generative AI services from browsers
- Developers installing local AI coding agents and CLI tools
- AI agents connecting to Model Context Protocol (MCP) servers and tools
- AI agents processing files, websites, repositories, prompts, and tool output
- AI applications interacting with sensitive corporate information

The goal should not be to block AI. The goal is to establish **visibility, understand risk, and put appropriate guardrails around how AI is used**.

Microsoft's security platform provides multiple layers that help answer different questions:

| Security question | Microsoft capability |
|---|---|
| What local AI agents are installed? | Microsoft Defender for Endpoint |
| Which users and devices are running them? | Microsoft Defender for Endpoint |
| What MCP servers are configured? | Microsoft Defender for Endpoint |
| Can local agents be investigated with Advanced Hunting? | Microsoft Defender for Endpoint |
| Can supported agent activity be inspected for prompt injection? | Microsoft Defender for Endpoint AI agent runtime protection |
| Which cloud AI services are users accessing? | Microsoft Defender for Cloud Apps |
| Which users are accessing those services? | Microsoft Defender for Cloud Apps |
| Can discovered AI services be assessed and sanctioned or unsanctioned? | Microsoft Defender for Cloud Apps |
| Can sensitive-data interactions with AI be investigated? | Microsoft Purview DSPM for AI |
| Where can unmanaged or unapproved AI agents be reviewed? | Shadow AI in the Microsoft 365 admin center |
| How can broader Microsoft 365 security defaults be established? | Microsoft 365 Baseline Security Mode |

## Where Do I Start?

Do not start by blocking AI tools before understanding what is being used in your environment. Start with visibility, then move toward governance and enforcement.

### 1. Discover Local AI Agents

Use Microsoft Defender for Endpoint to identify supported local AI agents running on managed endpoints. Defender can provide visibility into the agent, device, user or account, and configured MCP servers. Local AI agent information can also be investigated through Advanced Hunting.

This is a good starting point for answering:

> What AI agents are running on my endpoints, who is using them, and what are they connected to?

**Microsoft Learn:** [Discover local AI agents with Microsoft Defender for Endpoint (Preview)](https://learn.microsoft.com/en-us/defender-endpoint/discover-local-ai-agents)

### 2. Understand Shadow AI

Once AI agents are discovered, determine whether they are known and approved. The Shadow AI experience in the Microsoft 365 admin center is designed to help administrators discover, monitor, and govern unmanaged AI agents.

This moves the conversation from:

> Do we have AI agents?

To:

> Which AI agents are being used without IT visibility or approval?

**Microsoft Learn:** [Understand Shadow AI in Microsoft 365 admin center](https://learn.microsoft.com/en-us/microsoft-365/admin/manage/agent-shadow-ai?view=o365-worldwide)

### 3. Discover Cloud Generative AI Usage

Not every AI tool is installed locally. Users might access generative AI services directly through a browser or cloud application.

Microsoft Defender for Cloud Apps provides Cloud Discovery visibility into cloud applications accessed across the organization. Security teams can review discovered applications in the **Generative AI** category, identify associated domains and users, review available usage and risk information, and determine whether applications align with organizational policy.

This helps answer:

> Which generative AI services and domains are users accessing?

**Microsoft Learn:**

- [View discovered apps with the Cloud Discovery dashboard](https://learn.microsoft.com/en-us/defender-cloud-apps/discovered-apps)
- [Manage generative AI apps for your organization](https://learn.microsoft.com/en-us/microsoft-365/copilot/manage-generative-ai-apps)

### 4. Add Runtime Guardrails

Discovery tells you that an AI agent exists. Runtime protection addresses a different question:

> What happens when the agent processes malicious content or attempts a risky action?

Microsoft Defender for Endpoint AI agent runtime protection can inspect supported agent workflows for prompt injection and high-risk agent activity. Microsoft documents **Audit**, **Block**, and **Disabled** modes and recommends starting with Audit to observe detections and validate accuracy before moving to Block.

This is particularly important for local coding and agentic AI tools because agents can consume instructions from prompts, files, websites, repositories, and tool output.

**Microsoft Learn:** [AI agent runtime protection with Microsoft Defender for Endpoint (Preview)](https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-runtime-protection-overview)

### 5. Establish a Microsoft 365 Security Baseline

AI-specific controls should be part of a broader security strategy. Review Microsoft 365 Baseline Security Mode alongside AI security controls to understand the broader security configuration of the Microsoft 365 environment.

**Microsoft 365 admin center:** [Open Baseline Security Mode](https://admin.cloud.microsoft/?#/baselinesecuritymode)

## A Simple AI Security Strategy

You do not need to implement every available control on day one. A practical starting point is:

```text
Discover -> Understand -> Assess -> Audit -> Control -> Monitor
```

### Discover

Identify local AI agents, MCP configurations, cloud AI applications, domains, users, and devices.

### Understand

Determine how employees are using AI and where unmanaged or Shadow AI exists.

### Assess

Determine whether discovered AI tools align with organizational security, compliance, and data-handling requirements.

### Audit

Where available, begin with audit capabilities to understand behavior before enforcing controls.

### Control

Apply appropriate guardrails based on organizational policy and risk. Depending on the capability and scenario, an AI tool might be allowed, monitored, sanctioned, unsanctioned, restricted, or blocked.

### Monitor

Continue looking for new AI agents, applications, services, domains, and usage patterns. AI discovery should be an ongoing security process rather than a one-time assessment.

## Key Takeaway

AI security is not one product or one control. Microsoft Defender for Endpoint, Microsoft Defender for Cloud Apps, Shadow AI, Microsoft Purview, and Microsoft 365 security controls provide different parts of the visibility and protection story.

The most important first step is simple:

> Find out what AI is being used in your environment.

Once visibility is established, security teams can make informed decisions about what should be **allowed, monitored, audited, governed, restricted, or blocked**.

## Microsoft Learn References

- [Discover local AI agents with Microsoft Defender for Endpoint (Preview)](https://learn.microsoft.com/en-us/defender-endpoint/discover-local-ai-agents)
- [AI agent runtime protection with Microsoft Defender for Endpoint (Preview)](https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-runtime-protection-overview)
- [Understand Shadow AI in Microsoft 365 admin center](https://learn.microsoft.com/en-us/microsoft-365/admin/manage/agent-shadow-ai?view=o365-worldwide)
- [View discovered apps with the Cloud Discovery dashboard](https://learn.microsoft.com/en-us/defender-cloud-apps/discovered-apps)
- [Manage generative AI apps for your organization](https://learn.microsoft.com/en-us/microsoft-365/copilot/manage-generative-ai-apps)
- [Microsoft 365 admin center: Baseline Security Mode](https://admin.cloud.microsoft/?#/baselinesecuritymode)

> [!IMPORTANT]
> Several AI-agent security capabilities referenced on this page are currently Preview capabilities. Preview prerequisites, supported agents, licensing, availability, and functionality can change. Validate the latest Microsoft documentation before production deployment.
