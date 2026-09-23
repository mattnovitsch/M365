# MDO SOC Validation Test Plan

## Goal

Use quick, repeatable tests to confirm Microsoft Defender for Office 365 (MDO) is applying the correct policy, taking the expected action, and giving the SOC enough evidence to investigate.

## Before You Start

- Use a dedicated pilot mailbox.
- Use a controlled external mailbox.
- Confirm the pilot mailbox is included in the intended MDO policies.
- Do not use real malware, live credential-harvesting pages, or uncontrolled malicious URLs.
- Save the message subject, sender, recipient, and time for every test.

## Standard SOC Validation

For each test, check:

1. **Explorer:** `security.microsoft.com/threatexplorerv3`
2. **Quarantine:** `security.microsoft.com/quarantine`
3. **Incidents and alerts:** `security.microsoft.com/incidents`
4. **Submissions:** `security.microsoft.com/reportsubmission`
5. **Message trace:** Exchange admin center > Mail flow > Message trace
6. **Email entity page:** Open the message from Explorer and record the detection technology, policy, verdict, action, and delivery location.

A test passes only when the SOC can answer:

- Which policy applied?
- What detected the message?
- What action did MDO take?
- Where is the message now?
- Can the SOC investigate and respond?

---

# Malicious Email SOC Test Cases

> Scope: This plan intentionally tests only malicious or suspicious email detection and response. Clean-mail, clean-attachment, general user-reporting, and business-flow tests are excluded.

## Test 1: Prompt Injection Protection

**Purpose:** Confirm MDO detects prompt-injection content delivered in inbound email.

**Requirement:** Microsoft Defender for Office 365 Plan 2.

### Steps

1. Obtain the approved `prompt injection attack.txt` test content from the M365 labs package.
2. From a controlled external mailbox, create a new message and paste the approved test content into the message body.
3. Send it to the pilot mailbox with subject `MDO-TEST-01-PROMPT-INJECTION`.
4. In Explorer, search for the subject and recipient.
5. Open the Email entity page and record verdict, detection technology, policy, action, and final delivery location.

### Expected result

- Verdict: **High confidence phishing**.
- Detection technology: **Prompt injection protection**.
- The message follows the configured high-confidence phishing action.
- The SOC can locate and investigate the detection in Defender.

---

## Test 2: User / Display-Name Impersonation

**Purpose:** Confirm anti-phishing impersonation protection detects a protected user's identity being imitated from an external mailbox.

### Steps

1. Confirm a test user or executive is configured for user impersonation protection.
2. Use an external mailbox such as Gmail or Outlook.com.
3. Change that mailbox's **display name** to the protected user's name. Do not attempt to forge a domain you do not own.
4. Send the pilot mailbox a message with subject `MDO-TEST-02-USER-IMPERSONATION`.
5. Review the message in Explorer and the Email entity page.

### Expected result

- MDO evaluates the message using the configured user-impersonation protection.
- Expected safety tip, quarantine, or other configured action is applied when the message meets the policy's detection criteria.
- The SOC can identify the applicable anti-phishing policy and resulting action.

---

## Test 3: EICAR Malware Attachment

**Purpose:** Confirm malicious attachment detection, quarantine, and SOC investigation using the harmless EICAR antivirus test file instead of real malware.

### Steps

1. Obtain the standard EICAR antivirus test file from an approved source.
2. Attach it to a message from the external test mailbox.
3. Send it to the pilot mailbox with subject `MDO-TEST-03-EICAR`.
4. Check Explorer, Quarantine, the Email entity page, and any resulting alert or incident.
5. Record the malware verdict, detection technology, policy, action, and delivery location.

### Expected result

- The malicious test attachment is detected and handled according to the configured policy.
- The SOC can see the verdict and response in Defender.
- Quarantine permissions prevent unauthorized release when configured to do so.

> Do not use actual malware. Some sending-side security products can intercept EICAR before it reaches Microsoft 365. If that occurs, record it as **not received by MDO**, not as an MDO failure.

---

## Test 4: High-Confidence Phishing Quarantine Restrictions

**Purpose:** Confirm a user cannot bypass the quarantine restrictions intended for high-confidence phishing.

### Steps

1. Reuse the quarantined message from the **Prompt Injection Protection** test, if available.
2. Sign in as the pilot user.
3. Open Quarantine.
4. Locate the test message.
5. Record the actions available to the user without releasing the message.
6. Compare available actions with the assigned quarantine policy.

### Expected result

- User actions match the organization's high-confidence phishing quarantine policy.
- Direct release is unavailable when the assigned policy prohibits it.

---

## Test 5: Malware Quarantine Restrictions

**Purpose:** Confirm users cannot bypass the quarantine controls assigned to malware detections.

### Steps

1. Reuse the quarantined EICAR test message, if it reached MDO.
2. Sign in as the pilot user.
3. Open Quarantine.
4. Locate the EICAR test message.
5. Record available user actions without releasing the message.
6. Compare the result with the assigned quarantine policy.

### Expected result

- Available actions match the malware quarantine policy.
- The SOC retains the expected administrative investigation and remediation workflow.

---

# Optional Advanced Malicious Email Tests

These are intentionally outside the core SOC test set because they require infrastructure or conditions many organizations will not have readily available.

## Domain Impersonation

Run only when the organization owns or has approved access to a suitable lookalike test domain. Do not forge an unowned domain from a command-line mail utility and treat that as a domain-impersonation test, because it can instead exercise spoofing and email-authentication protections.

## Spoofing / Authentication Failure

Run as a separate mail-engineering exercise when the organization has approved infrastructure for generating controlled spoof, SPF, DKIM, or DMARC failure scenarios.

## ZAP / Post-Delivery Verdict Change

Run only when there is an approved repeatable method for producing a safe message whose verdict changes after delivery.

---

# Microsoft References

- [Prompt injection protection in Microsoft Defender for Office 365](https://learn.microsoft.com/en-us/defender-office-365/step-by-step-guides/prompt-injection-protection-defender-for-office-365)
- [Recommended settings for EOP and Microsoft Defender for Office 365](https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365)
- [Anti-phishing policies in Microsoft 365](https://learn.microsoft.com/en-us/defender-office-365/anti-phishing-policies-about)
- [Safe Links in Microsoft Defender for Office 365](https://learn.microsoft.com/en-us/defender-office-365/safe-links-about)
- [Safe Attachments in Microsoft Defender for Office 365](https://learn.microsoft.com/en-us/defender-office-365/safe-attachments-about)
- [Understand detection technology on the Email entity page](https://learn.microsoft.com/en-us/defender-office-365/step-by-step-guides/understand-detection-technology-in-email-entity)
