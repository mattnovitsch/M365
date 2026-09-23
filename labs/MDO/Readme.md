# Validating Your Defender for Office Policies

## Goal

Use quick, repeatable tests to confirm Microsoft Defender for Office 365 (MDO) is applying the correct policy, taking the expected action, and giving the Security Engineer enough evidence to investigate.

## Before You Start

- Use a dedicated pilot mailbox.
- Use a controlled external mailbox.
- Confirm the pilot mailbox is included in the intended MDO policies.
- Do not use real malware, live credential-harvesting pages, or uncontrolled malicious URLs.
- Save the message subject, sender, recipient, and time for every test.

## Standard Validation

For each test, check:

1. **Explorer:** `security.microsoft.com/threatexplorerv3`
2. **Quarantine:** `security.microsoft.com/quarantine`
3. **Incidents and alerts:** `security.microsoft.com/incidents`
4. **Submissions:** `security.microsoft.com/reportsubmission`
5. **Message trace:** Exchange admin center > Mail flow > Message trace
6. **Email entity page:** Open the message from Explorer and record the detection technology, policy, verdict, action, and delivery location.

A test passes only when the Security Engineer can answer:

- Which policy applied?
- What detected the message?
- What action did MDO take?
- Where is the message now?
- Can the Security Engineer investigate and respond?

---

# Malicious Email Test Cases

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
- The Security Engineer can locate and investigate the detection in Defender.

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
- The Security Engineer can identify the applicable anti-phishing policy and resulting action.

---

## Test 3: EICAR Malware Attachment

**Purpose:** Confirm malicious attachment detection, quarantine, and the Security Engineer's investigation using the harmless EICAR antivirus test file instead of real malware.

### Steps

1. Obtain the standard EICAR antivirus test file from an approved source.
2. Attach it to a message from the external test mailbox.
3. Send it to the pilot mailbox with subject `MDO-TEST-03-EICAR`.
4. Check Explorer, Quarantine, the Email entity page, and any resulting alert or incident.
5. Record the malware verdict, detection technology, policy, action, and delivery location.

### Expected result

- The malicious test attachment is detected and handled according to the configured policy.
- The Security Engineer can see the verdict and response in Defender.
- Quarantine permissions prevent unauthorized release when configured to do so.

> Do not use actual malware. Some sending-side security products can intercept EICAR before it reaches Microsoft 365. If that occurs, record it as **not received by MDO**, not as an MDO failure.

---

## Test 4: Safe Links Email Detection

**Purpose:** Confirm MDO detects and handles an inbound external email containing the Safe Links test content from the MDO lab repository.

### Test file

Download and use [FileAttachmentwithlinks.txt](https://github.com/mattnovitsch/M365/blob/main/labs/MDO/FileAttachmentwithlinks.txt).

### Steps

1. Open the test file and use the **Download raw file** option in GitHub.
2. From an external mailbox, create a new email to a pilot user inside the customer domain.
3. Use the subject `MDO-TEST-04-SAFE-LINKS-EMAIL`.
4. Attach `FileAttachmentwithlinks.txt` to the email.
5. Send the message from the external mailbox to the pilot user.
6. In Microsoft Defender, open **Email & collaboration > Explorer**.
7. Search by the recipient, sender, subject, and test time.
8. Open the Email entity page.
9. Record the threat verdict, detection technology, policy, action, latest delivery location, and original delivery location.
10. Check Quarantine and any generated alert or incident.

### Expected result

- MDO detects the malicious links contained in the attached test file.
- The message receives the verdict and action configured by the applicable MDO policies.
- If the configured action is quarantine, Explorer shows **Quarantine** as the latest delivery location.
- The Security Engineer can locate the message and identify the detection technology and applied policy.

### Pass criteria

- The message is not delivered to the user's Inbox when the applicable policy requires blocking or quarantine.
- Explorer shows the expected threat verdict and action.
- The Security Engineer can open the Email entity page and trace why MDO acted on the message.

### Troubleshooting

If the message is delivered:

1. Confirm the recipient is covered by the intended Safe Links policy.
2. Confirm Safe Links protection is enabled for email.
3. Check whether a custom policy, preset policy, transport rule, connector, or allow entry changed the result.
4. Confirm the message entered Microsoft 365 from an external sender rather than being sent internally.
5. Search Explorer using the exact subject and review the Email entity page before marking the test failed.

---

## Test 5: High-Confidence Phishing Quarantine Restrictions

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

## Test 6: Malware Quarantine Restrictions

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
- The Security Engineer retains the expected administrative investigation and remediation workflow.

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

- [MDO lab test files](https://github.com/mattnovitsch/M365/tree/main/labs/MDO)
- [Safe Links email test file](https://github.com/mattnovitsch/M365/blob/main/labs/MDO/FileAttachmentwithlinks.txt)
- [Prompt injection protection in Microsoft Defender for Office 365](https://learn.microsoft.com/en-us/defender-office-365/step-by-step-guides/prompt-injection-protection-defender-for-office-365)
- [Recommended settings for EOP and Microsoft Defender for Office 365](https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365)
- [Anti-phishing policies in Microsoft 365](https://learn.microsoft.com/en-us/defender-office-365/anti-phishing-policies-about)
- [Safe Links in Microsoft Defender for Office 365](https://learn.microsoft.com/en-us/defender-office-365/safe-links-about)
- [Safe Attachments in Microsoft Defender for Office 365](https://learn.microsoft.com/en-us/defender-office-365/safe-attachments-about)
- [Understand detection technology on the Email entity page](https://learn.microsoft.com/en-us/defender-office-365/step-by-step-guides/understand-detection-technology-in-email-entity)
