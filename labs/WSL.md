# Microsoft Defender for Endpoint with WSL 2: Deployment and Alert Testing Lab

This lab demonstrates how to deploy Windows Subsystem for Linux (WSL 2), integrate it with Microsoft Defender for Endpoint using the Defender for Endpoint WSL plug\-in, validate onboarding, generate harmless Linux activity, investigate that activity in Advanced Hunting, and optionally create a custom Microsoft Defender XDR detection to generate a lab alert.

**Important:** Microsoft Defender for Endpoint's WSL integration should not be treated as identical to installing the full Microsoft Defender for Endpoint Linux agent on a standalone Linux system. The WSL plug\-in provides security\-event visibility for running WSL distributions. Some capabilities available with the full Linux agent are not available for the WSL logical device.

---

## Lab objectives

By the end of this lab, you will be able to:

1. Install WSL 2 on Windows.
2. Install a Linux distribution.
3. Install the Microsoft Defender for Endpoint plug\-in for WSL.
4. Validate Defender onboarding using healthcheck.exe.
5. Confirm that the WSL logical device appears in Microsoft Defender.
6. Generate harmless Linux activity inside WSL.
7. Search for WSL activity using Advanced Hunting.
8. Create a custom detection rule for repeatable lab testing.
9. Generate and investigate a Defender alert associated with the WSL test.

---

# 1\. Prerequisites

The Windows device must already be onboarded to Microsoft Defender for Endpoint.

For traditional WSL 2 distributions, Microsoft currently requires:

- Microsoft Defender for Endpoint Plan 2
- Windows 10 or Windows 11 on a supported release
- WSL 2
- WSL version 2.0.7.0 or later
- At least one active WSL distribution
- Microsoft Defender for Endpoint WSL plug\-in

Check the installed WSL version:

wsl \-\-version

Update WSL if necessary:

wsl \-\-update

---

# 2\. Install WSL

Open an elevated PowerShell or Windows Terminal window.

Install WSL:

wsl \-\-install

Restart Windows if prompted.

After restarting, verify the installation:

wsl \-\-version

List installed distributions:

wsl \-\-list \-\-verbose

You should see a distribution configured for **WSL version 2**.

Example:

NAME       STATE      VERSION

Ubuntu     Stopped    2

---

# 3\. Install a Linux distribution

You can view distributions available through WSL with:

wsl \-\-list \-\-online

Install the distribution you want to use for the lab.

For example:

wsl \-\-install \-d Ubuntu

The Defender WSL integration is not limited to Ubuntu. Use a WSL 2 distribution appropriate for your testing environment.

Start the distribution:

wsl

Or launch a specific installed distribution:

wsl \-d Ubuntu

Keep the distribution running while validating Defender integration.

---

# 4\. Download the Microsoft Defender for Endpoint WSL plug\-in

In the Microsoft Defender portal, browse to:

**Settings → Endpoints → Onboarding**

Select:

**Windows Subsystem for Linux 2 (plug\-in)**

Download the Microsoft Defender for Endpoint WSL plug\-in installer and install it on the Windows host.

The WSL subsystem does **not** require a separate Defender onboarding package. The WSL plug\-in uses the Defender onboarding of the Windows host.

---

# 5\. Validate the Defender WSL plug\-in

After installing the plug\-in, start your WSL distribution.

For example:

wsl

Leave the WSL session running.

Open another PowerShell window and run:

cd "$env:ProgramFiles\\Microsoft Defender for Endpoint plug\-in for WSL\\tools"

.\\healthcheck.exe

Initially, you might see:

WSL Distro Running: true

Waiting for Telemetry retry in 5 minutes

That indicates that the WSL VM has started but the Defender integration is still initializing.

Run the health check again after initialization:

.\\healthcheck.exe

Review fields including:

Plugin Version

WSL Version

Release Ring

VM Start Time

LKG Telemetry

WSL Distro Running

Windows Org ID

Windows Device ID

Defender App Version

WSL GUID

WSL Device ID

The WSL distribution should report:

WSL Distro Running: true

Microsoft notes that a WSL 2 instance can take up to 30 minutes to onboard and appear in Microsoft Defender. Short\-lived WSL instances might not appear in the portal.

---

# 6\. Verify the WSL device in Microsoft Defender

Open:

**Microsoft Defender → Assets → Devices**

Locate the WSL logical device associated with the Windows system.

The architecture is effectively:

Windows Device

    \|

    \+\-\- Microsoft Defender for Endpoint

    \|

    \+\-\- WSL 2

         \|

         \+\-\- Linux Distribution

         \|

         \+\-\- Defender for Endpoint WSL plug\-in

                \|

                \+\-\- Security telemetry

                \|

                \+\-\- Microsoft Defender

The purpose of the WSL plug\-in is to give Defender visibility into activity occurring within WSL.

---

# 7\. Generate harmless WSL activity

The following test intentionally performs benign actions. It does **not** download malware, exploit the system, modify security controls, or attempt persistence.

Open your WSL distribution.

Create a recognizable marker:

echo "MDE\-WSL\-LAB\-TEST\-$(date \+%s)" > /tmp/mde\-wsl\-test.txt

Read Linux OS information:

cat /etc/os\-release

Generate a recognizable command:

bash \-c 'echo "MDE WSL child process test"; sleep 2'

Generate a harmless outbound HTTPS request:

curl [https://www.microsoft.com](https://www.microsoft.com)

Inspect the test file:

ls \-la /tmp/mde\-wsl\-test.txt

The goal is not to trigger malware prevention.

The goal is to create identifiable WSL activity that can be investigated through Defender telemetry.

---

# 8\. Hunt for WSL process activity

Open:

**Microsoft Defender → Hunting → Advanced Hunting**

Start by looking for the distinctive lab activity.

DeviceProcessEvents
| where AccountName contains "wsl"
| where ProcessCommandLine has_any (
    "MDE-WSL-LAB-TEST",
    "MDE WSL child process test",
    "/etc/os-release"
)
| project
    Timestamp,
    DeviceName,
    DeviceId,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    AccountName
| order by Timestamp desc

If the marker is not returned, broaden the investigation:

DeviceProcessEvents
| where FileName in~ (
    "bash",
    "curl",
    "cat",
    "sleep"
)
| project
    Timestamp,
    DeviceName,
    DeviceId,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp desc

Use the results to identify the DeviceName and DeviceId associated with the WSL logical device.

Event availability can vary. Microsoft specifically notes that detection and alerting behavior can vary between Linux distributions.

---

# 9\. Hunt for network activity

Because the test made an HTTPS request to Microsoft's website, you can also check network telemetry.

DeviceNetworkEvents
| where RemoteUrl contains "microsoft.com"
| project
    Timestamp,
    DeviceName,
    DeviceId,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    RemoteUrl,
    RemoteIP,
    RemotePort,
    Protocol,
    ActionType
| order by Timestamp desc

If telemetry is present, verify that the DeviceName or DeviceId corresponds to the WSL logical device before using the event for a detection rule.

---

# 10\. Create a harmless Defender WSL alert

Once you have confirmed which process telemetry is reliably generated by your WSL environment, create a unique test command.

Inside WSL run:

bash \-c 'echo MDE\_WSL\_CUSTOM\_DETECTION\_TEST; sleep 5'

Search for the marker:

DeviceProcessEvents
| where AccountName contains "wsl"
| where ProcessCommandLine contains "TEST"
| project
    Timestamp,
    DeviceId,
    DeviceName,
    ReportId,
    FileName,
    ProcessCommandLine

**Do not create the detection until this query successfully returns the expected WSL device.**

This avoids building a detection around an event that your particular distribution does not expose.

---

# 11\. Create the custom detection

After confirming the query returns the expected WSL event, use the query as the basis of a Microsoft Defender XDR custom detection.

A simple starting query is:

DeviceProcessEvents
| where AccountName contains "wsl"
| where ProcessCommandLine contains "TEST"
| project
    Timestamp,
    DeviceId,
    DeviceName,
    AccountName,
    ReportId

From Advanced Hunting, create a custom detection based on the validated query.

Suggested lab values:

**Detection name**

LAB \- WSL Custom Detection Test

**Description**

Harmless lab detection used to validate Microsoft Defender for Endpoint visibility into Windows Subsystem for Linux activity.

Select an appropriate severity and configure the detection according to your lab requirements.

No automated remediation action is required for this validation test.

---

# 12\. Trigger the detection

Return to WSL and execute the distinctive command again:

bash \-c 'echo MDE\_WSL\_CUSTOM\_DETECTION\_TEST; sleep 5'

This command itself is harmless.

It exists solely to generate telemetry matching the custom detection rule.

The validation flow is:

WSL 2

  \|

  \+\-\- bash

       \|

       \+\-\- MDE\_WSL\_CUSTOM\_DETECTION\_TEST

                 \|

                 v

        Defender WSL telemetry

                 \|

                 v

          Advanced Hunting

                 \|

                 v

          Custom Detection

                 \|

                 v

            Defender Alert

---

# 13\. Investigate the resulting alert

When the custom detection processes a matching event, investigate the generated alert in Microsoft Defender.

Validate:

- Alert name
- Associated WSL logical device
- Device timeline
- Process information
- Command line
- Timestamp
- Detection source
- Incident correlation, if applicable

This provides a safe way to validate the complete WSL telemetry\-to\-alert workflow without introducing malware into the environment.

---

# Important WSL Defender limitations

Do not assume that the Defender WSL plug\-in provides feature parity with a standalone Linux device running the complete Microsoft Defender for Endpoint Linux agent.

Microsoft specifically documents that the WSL logical device does not provide:

- Antimalware functionality
- Threat and Vulnerability Management
- Response commands

The WSL plug\-in provides visibility into events occurring inside WSL, and detection and alert behavior can vary between Linux distributions.

Because of this, an **EICAR test should not be used as the primary validation mechanism for the WSL plug\-in**.

Microsoft publishes an EICAR validation procedure for the normal Microsoft Defender for Endpoint Linux agent using mdatp, real\-time protection, threat detection, and quarantine. That is a different validation scenario from the WSL plug\-in described in this lab.

---

# Troubleshooting

## WSL device does not appear in Defender

Verify that WSL is actually running:

wsl \-\-list \-\-verbose

You want to see:

STATE      VERSION

Running    2

Run:

cd "$env:ProgramFiles\\Microsoft Defender for Endpoint plug\-in for WSL\\tools"

.\\healthcheck.exe

Verify:

WSL Distro Running: true

Keep the WSL distribution running while the Defender integration initializes.

Microsoft documents that onboarding can take up to 30 minutes.

---

## HealthCheck reports "Waiting for Telemetry"

Keep the WSL distribution active and retry:

.\\healthcheck.exe

The telemetry and device identification fields should populate as the Defender integration initializes.

---

## Advanced Hunting does not return the lab marker

First broaden the query instead of assuming telemetry is broken:

DeviceProcessEvents
| where FileName in~ ("bash", "curl", "cat", "sleep")
| project
    Timestamp,
    DeviceName,
    DeviceId,
    FileName,
    ProcessCommandLine
| order by Timestamp desc

Because detection and alerting can vary between Linux distributions, determine which events your distribution exposes before designing the custom detection.

---

# Cleanup

Remove the harmless test file:

rm \-f /tmp/mde\-wsl\-test.txt

The custom detection can also be disabled or deleted after testing.

No malicious files or persistence mechanisms are created by this lab.

---

# Expected results

Successful completion should demonstrate this chain:

Windows onboarded to MDE

        ↓

WSL 2 installed

        ↓

Linux distribution running

        ↓

MDE WSL plug\-in operational

        ↓

WSL logical device visible

        ↓

WSL activity generated

        ↓

Telemetry visible in Defender

        ↓

Advanced Hunting identifies activity

        ↓

Custom Detection matches activity

        ↓

Defender alert generated

This validates both WSL security visibility and the Defender detection pipeline while keeping the test safe and repeatable.

---

# Microsoft documentation

- [Microsoft Defender for Endpoint plug\-in for Windows Subsystem for Linux (WSL)](https://learn.microsoft.com/en-us/defender-endpoint/mde-plugin-wsl)
- [Set up Windows Subsystem for Linux for your company](https://learn.microsoft.com/en-us/windows/wsl/enterprise)
- [Create custom detection rules in Microsoft Defender XDR](https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules)
- [Custom detections overview](https://learn.microsoft.com/en-us/defender-xdr/custom-detections-overview)

---

## Disclaimer

This lab is intended for authorized security validation and educational testing in a controlled environment. The activity generated by the lab is intentionally benign. Always perform security testing only on systems and tenants for which you have authorization.

