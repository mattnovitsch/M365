# Microsoft Defender for Office 365 (MDO) Pilot Validation Test Plan

## Purpose

This test plan validates that Microsoft Defender for Office 365 is both **configured correctly** and **enforcing protections as designed**. Validation should confirm the complete path from policy assignment through detection, action, evidence, and operational response.

## Validation Standard

A test is successful only when the following chain is confirmed:

**Configuration → Test message → Detection → Correct policy → Correct action → Evidence → SecOps workflow**

> **Safety note:** Use only controlled test accounts, domains, URLs, and files. Use the EICAR antivirus test file instead of real malware. Never send actual malware or impersonate an unrelated real organization.

---

## 1. Test Preparation

### Required test resources

- At least one licensed MDO pilot user
- One controlled external test mailbox
- A controlled test domain, if testing spoofing or domain impersonation
- Access to the Microsoft Defender portal
- Access to Exchange Online message trace
- Permission to review Explorer or Real-time detections
- Permission to review quarantine, alerts, incidents, and submissions
- Microsoft Report Message or Report Phishing capability enabled for pilot users
- A documented list of expected policy assignments and policy priorities

### Evidence to capture for each test

- Test date and tester
- Sending and receiving addresses
- Message subject or Network Message ID
- Expected policy
- Policy actually applied
- Detection technology
- Threat verdict
- Delivery action and final delivery location
- Quarantine policy, if applicable
- Alert or incident, if generated
- Screenshots or exported evidence
- Pass, fail, or follow-up status

---

## 2. Pre-Test Configuration Validation

| ID | Validation | Test | Expected Result |
|---|---|---|---|
| CFG-01 | Licensing | Verify pilot accounts have the required MDO licensing | Required MDO capabilities are available |
| CFG-02 | Policy assignment | Verify every pilot user or group is included in the intended policy | Correct policy scope is confirmed |
| CFG-03 | Policy precedence | Review Built-in, Standard, Strict, and custom policy assignments | No unintended overlap or priority conflict exists |
| CFG-04 | Configuration Analyzer | Review recommendations and configuration drift | Exceptions are understood and documented |
| CFG-05 | Anti-malware | Review malware policy settings and actions | Settings match the approved baseline |
| CFG-06 | Anti-spam | Review inbound and outbound spam policies | SCL actions, notifications, and quarantine behavior match the design |
| CFG-07 | Anti-phishing | Review spoof intelligence, mailbox intelligence, impersonation protection, and thresholds | Required protections are enabled and scoped correctly |
| CFG-08 | Safe Attachments | Review policy mode, actions, and recipient scope | Pilot users are protected by the intended policy |
| CFG-09 | Safe Links | Review email, Office apps, and Teams protection | Pilot users are protected in all intended workloads |
| CFG-10 | Quarantine | Review quarantine policies and release permissions | Users and administrators have only the intended capabilities |
| CFG-11 | Tenant Allow/Block List | Review allowed and blocked senders, domains, URLs, and files | No overly broad entry undermines protection testing |
| CFG-12 | Mail flow | Review connectors, enhanced filtering, transport rules, and bypasses | No unintended route or rule bypasses MDO inspection |
| CFG-13 | Email authentication | Validate SPF, DKIM, DMARC, and accepted-domain configuration | Authentication posture matches the approved design |
| CFG-14 | User reporting | Verify Report Message or Report Phishing configuration | Users can submit suspicious and misclassified messages |
| CFG-15 | Alerts and notifications | Review alert policies and notification recipients | Required operational teams receive expected notifications |

### Configuration review notes

- Confirm which policy is expected to apply to each pilot user before running tests.
- Document all temporary exceptions used during the pilot.
- Confirm custom policies do not unintentionally override Standard or Strict preset protections.
- Review transport rules and connectors for SCL bypasses, trusted-source exceptions, or security filtering overrides.

---

## 3. Anti-Spam Testing

### SPAM-01: Bulk or spam-like message

**Test**

Send a controlled external message containing characteristics typical of unsolicited bulk mail.

**Validate**

- Spam Confidence Level
- Threat verdict
- Detection technology
- Applied policy
- Delivery action
- Final delivery location
- Quarantine reason, if applicable
- Message trace and Explorer results

**Pass criteria**

The message receives the verdict and disposition configured in the applicable anti-spam policy.

### SPAM-02: High-confidence spam

**Test**

Use an approved testing method to send a message expected to receive a high-confidence spam verdict.

**Validate**

- Threat category
- Delivery action
- Delivery location
- Detection technology
- Applied policy
- Quarantine policy

**Pass criteria**

High-confidence spam follows the action configured for the pilot population.

### SPAM-03: Outbound spam controls

**Test**

Review and, where safely permitted, validate the outbound anti-spam thresholds and restricted-user workflow using a controlled pilot account.

**Validate**

- Outbound policy assignment
- Recipient and message limits
- Alerting and notification configuration
- Restricted-user operational process

**Pass criteria**

The configured outbound controls, alerts, and response workflow match the approved design.

---

## 4. Sender Authentication Testing

### AUTH-01: SPF failure

**Test**

Using a controlled test domain, send a message from a source that is not permitted by that domain's SPF record.

**Validate**

- SPF result in the message headers
- Composite authentication result
- Defender verdict
- Policy and action

**Pass criteria**

The SPF failure is visible, evaluated by Defender, and handled according to the intended policy.

### AUTH-02: DKIM failure

**Test**

Using a controlled test domain, send a message with an intentionally invalid DKIM signature.

**Validate**

- DKIM result
- Composite authentication result
- Defender verdict
- Policy and action

**Pass criteria**

The DKIM failure is visible and the message receives the expected disposition.

### AUTH-03: DMARC failure

**Test**

Using a controlled test domain, send a message where the visible From domain does not align with the authenticated SPF or DKIM identity.

**Validate**

- SPF result
- DKIM result
- DMARC result
- Domain alignment
- Composite authentication result
- Defender disposition

**Pass criteria**

The DMARC failure is correctly identified and the configured protection action is applied.

> Do not mark an authentication test as passed solely because a message was blocked. Confirm why Defender reached the verdict.

---

## 5. Anti-Phishing Testing

### PHISH-01: Display-name impersonation

**Test**

Send from a controlled external mailbox using the display name of a protected pilot user.

Example:

`Matt Novitsch <external-test@example.com>`

**Validate**

- Impersonation detection
- Safety tip
- Detection technology
- Applied policy
- Final action

**Pass criteria**

The message is evaluated and handled according to the configured impersonation protection.

### PHISH-02: User impersonation

**Test**

Configure a protected pilot user and send a controlled message imitating that identity from external test infrastructure.

**Pass criteria**

User impersonation protection identifies the message and applies the configured action.

### PHISH-03: Domain impersonation

**Test**

Use a controlled test domain that visually resembles the organization's domain.

**Validate**

- Domain impersonation detection
- Safety tip
- Quarantine or delivery action
- Explorer result

**Pass criteria**

The test message is identified and handled according to the domain impersonation policy.

### PHISH-04: Spoof intelligence

**Test**

Perform a controlled spoofing test using the organization's authorized test domain and infrastructure.

**Validate**

- Spoof intelligence verdict
- Authentication results
- Composite authentication
- Applied policy
- Message disposition

**Pass criteria**

The spoofed message is evaluated and handled according to the approved configuration.

### PHISH-05: First-contact and unauthenticated sender indicators

**Test**

Send a benign message from a new external sender to a pilot user.

**Validate**

- First-contact safety tip, if configured
- Unauthenticated sender indicators, if applicable
- Normal delivery of benign content

**Pass criteria**

Expected user-facing indicators appear without incorrectly blocking legitimate mail.

---

## 6. Safe Attachments Testing

### ATTACH-01: EICAR antivirus test file

**Test**

Send the standard EICAR antivirus test file from the controlled external mailbox. Do not use real malware.

**Validate**

- Malware or attachment verdict
- Safe Attachments or anti-malware detection
- Delivery action
- Quarantine
- Explorer result
- Alert or incident, if generated
- Submission workflow

**Pass criteria**

The file and message are handled according to the configured malware and Safe Attachments policies.

### ATTACH-02: Clean attachments

**Test**

Send known-clean files such as:

- DOCX
- XLSX
- PDF
- ZIP

**Pass criteria**

Legitimate files are delivered normally without unexpected detonation failures or false positives.

### ATTACH-03: Password-protected attachment

**Test**

Send a password-protected ZIP or supported encrypted attachment that contains only benign content.

**Validate**

- Scan or detonation status
- Policy action for content that cannot be inspected
- Quarantine behavior
- User and administrator release options

**Pass criteria**

The result matches the approved Safe Attachments configuration.

### ATTACH-04: Dynamic Delivery, if configured

**Test**

Send a clean attachment that requires Safe Attachments processing.

**Validate**

- Message availability during scanning
- Attachment availability after scanning
- Final verdict and delivery state

**Pass criteria**

Behavior matches the configured Safe Attachments mode.

---

## 7. Safe Links Testing

### LINK-01: Normal URL

**Test**

Send a benign URL such as `https://www.microsoft.com`.

**Pass criteria**

The user can access the site and the message is not incorrectly blocked.

### LINK-02: Approved Safe Links test URL

**Test**

Use Microsoft's documented Safe Links demonstration or testing mechanism rather than a real malicious site.

**Validate**

- Safe Links processing
- Time-of-click result
- Click event reporting
- URL trace or Explorer visibility
- Alert or incident, if generated

**Pass criteria**

Safe Links applies the configured protection and records the expected evidence.

### LINK-03: Time-of-click protection

**Test**

Confirm that the pilot user is covered by the intended Safe Links policy, then validate behavior at the time the URL is selected.

**Pass criteria**

The URL is evaluated at click time and handled according to the policy.

### LINK-04: Link in an Office document

**Test**

Place an approved test URL in a Word document, email the document to the pilot user, and select the link from the document.

**Pass criteria**

Behavior matches the Safe Links for Office apps setting.

### LINK-05: Safe Links in Teams

**Test**

Post the approved test URL in a controlled Teams chat or channel and select it as a protected pilot user.

**Pass criteria**

Behavior matches the Safe Links for Teams configuration.

### LINK-06: Do-not-rewrite entries

**Test**

If the Safe Links policy contains do-not-rewrite URLs, send a benign URL that matches an approved entry.

**Pass criteria**

Only the intended URLs bypass rewriting, and the exception is documented and justified.

---

## 8. Quarantine Validation

### QUAR-01: Spam quarantine

Trigger a spam disposition and verify:

- Correct quarantine policy
- Correct user visibility
- Correct notification behavior
- Correct request-release or direct-release capability

### QUAR-02: Phishing quarantine

Trigger a phishing disposition and verify whether the user can:

- View the message
- Preview the message
- Request release
- Directly release the message
- Delete the message

**Pass criteria**

User permissions match the approved phishing quarantine model.

### QUAR-03: Malware quarantine

Use the EICAR test file and verify:

- Malware quarantine policy
- User visibility
- Release restrictions
- Administrator workflow

**Pass criteria**

Users cannot bypass the organization's intended malware quarantine controls.

### QUAR-04: Delegated administration

If agencies or delegated teams are used, verify that delegated operators can perform only the approved quarantine actions for the intended recipient scope.

**Pass criteria**

Delegated access follows the approved role and quarantine policy design.

---

## 9. Zero-hour Auto Purge and Post-Delivery Protection

### ZAP-01: Post-delivery verdict change

**Test**

Using an approved and safe testing method, identify a message whose verdict changes after initial delivery.

**Record**

- Initial delivery location
- Initial verdict
- Updated verdict
- Final delivery location
- Post-delivery action
- Explorer evidence

**Pass criteria**

Post-delivery action follows the applicable protection policy and is visible to the operations team.

---

## 10. User Submission Workflow

### SUBMIT-01: Report phishing

Have a pilot user select **Report → Phishing** for a controlled test message.

**Pass criteria**

The submission appears in the configured reporting workflow with the expected metadata.

### SUBMIT-02: Report junk

Have a pilot user report a known test message as junk.

**Pass criteria**

The submission is visible to the intended operations team.

### SUBMIT-03: False positive

Report a legitimate test message as clean or not junk through the approved workflow.

**Pass criteria**

The SecOps team can review and process the false-positive submission.

### SUBMIT-04: User notification and education

Review the user experience after reporting a message.

**Pass criteria**

User notifications and education messages match the organization's approved design.

---

## 11. Defender Operational Validation

For every malicious or unwanted-message test, review the applicable evidence in:

1. Exchange Online message trace
2. Explorer or Real-time detections
3. Email entity page
4. Message headers
5. Quarantine
6. Alerts
7. Incidents, when generated
8. Submissions
9. Advanced Hunting, if included in the pilot scope

### Operational validation questions

- Was the intended policy applied?
- Did Defender assign the expected verdict?
- Was the expected action taken?
- Can SecOps identify why the message was detected?
- Is the message visible in the expected investigation tools?
- Was an alert or incident expected for this test?
- Did the correct team receive the notification?
- Can the team investigate, release, submit, or remediate the message as designed?

---

## 12. False-Positive and Business-Flow Testing

Send legitimate examples of:

- Internal email
- External email
- Newsletter
- Bulk business email
- Automated application email
- Service-account email
- Partner or vendor email
- PDF attachment
- Office attachment
- ZIP file
- Message containing normal URLs
- Message from a newly contacted external sender
- Messages from approved line-of-business applications

### Pass criteria

There are no unexpected:

- Blocks
- Quarantines
- Impersonation detections
- Spam classifications
- URL blocks
- Attachment blocks
- Delivery delays outside the approved design

Any false positive must be documented with the detection technology, applied policy, business impact, and proposed tuning action.

---

## 13. Pilot Test Scorecard

| Test | Expected Result | Actual Result | Evidence | Status |
|---|---|---|---|---|
| CFG-01 Licensing | Required capabilities available | | | ⬜ |
| CFG-02 Policy assignment | Intended policy applies | | | ⬜ |
| CFG-03 Policy precedence | No unintended conflict | | | ⬜ |
| SPAM-01 Spam | Configured spam action | | Explorer | ⬜ |
| SPAM-02 High-confidence spam | Configured HCS action | | Explorer | ⬜ |
| SPAM-03 Outbound spam | Controls and workflow match design | | Policy/Alert | ⬜ |
| AUTH-01 SPF failure | Failure visible and evaluated | | Header/Explorer | ⬜ |
| AUTH-02 DKIM failure | Failure visible and evaluated | | Header/Explorer | ⬜ |
| AUTH-03 DMARC failure | Failure visible and evaluated | | Header/Explorer | ⬜ |
| PHISH-01 Display-name impersonation | Evaluated as designed | | Explorer | ⬜ |
| PHISH-02 User impersonation | Detected as designed | | Explorer | ⬜ |
| PHISH-03 Domain impersonation | Detected as designed | | Explorer | ⬜ |
| PHISH-04 Spoof intelligence | Evaluated as designed | | Header/Explorer | ⬜ |
| ATTACH-01 EICAR | Blocked or quarantined as designed | | Explorer/Quarantine | ⬜ |
| ATTACH-02 Clean attachment | Delivered | | Explorer | ⬜ |
| ATTACH-03 Protected ZIP | Policy-specific action | | Explorer | ⬜ |
| LINK-01 Normal URL | Allowed | | Explorer | ⬜ |
| LINK-02 Safe Links test | Protected as designed | | URL evidence | ⬜ |
| LINK-04 Office document link | Policy-specific result | | URL evidence | ⬜ |
| LINK-05 Teams link | Policy-specific result | | Defender | ⬜ |
| QUAR-01 Spam permissions | As designed | | Quarantine | ⬜ |
| QUAR-02 Phishing permissions | As designed | | Quarantine | ⬜ |
| QUAR-03 Malware permissions | As designed | | Quarantine | ⬜ |
| SUBMIT-01 Report phishing | Submission received | | Submissions | ⬜ |
| SUBMIT-02 Report junk | Submission received | | Submissions | ⬜ |
| SUBMIT-03 False positive | Submission received | | Submissions | ⬜ |
| FP-01 Clean message flows | Delivered normally | | Explorer | ⬜ |

Status values:

- ⬜ Not started
- 🟡 In progress or requires follow-up
- ✅ Passed
- ❌ Failed
- ⚪ Not applicable

---

## 14. Issue and Tuning Log

| ID | Test ID | Issue | Business Impact | Evidence | Proposed Change | Owner | Status |
|---|---|---|---|---|---|---|---|
| 1 | | | | | | | |

For each proposed policy change:

1. Record the original setting.
2. Document the test evidence.
3. Explain the business justification.
4. Apply the change to the pilot scope first.
5. Repeat the failed test.
6. Record the final result before wider deployment.

---

## 15. Pilot Exit Criteria

The MDO pilot is ready for broader deployment when:

- All pilot users are covered by the approved policies.
- Policy precedence and exceptions are documented.
- Anti-spam behavior is validated.
- SPF, DKIM, and DMARC test outcomes are understood.
- Spoof and impersonation protections operate as designed.
- Safe Attachments blocks harmful test content and permits clean content.
- Safe Links works in each enabled workload.
- Quarantine access and release permissions follow the approved operating model.
- User submissions reach the intended SecOps workflow.
- Alerts and investigation evidence are available to the operations team.
- Business-critical mail flows complete successfully.
- False positives are documented and resolved or formally accepted.
- Failed tests have owners and remediation plans.
- Final test evidence and configuration decisions are retained.

---

## 16. Official Microsoft References

- [Recommended settings for EOP and Microsoft Defender for Office 365](https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365)
- [Anti-phishing policies in Microsoft 365](https://learn.microsoft.com/en-us/defender-office-365/anti-phishing-policies-about)
- [Safe Links in Microsoft Defender for Office 365](https://learn.microsoft.com/en-us/defender-office-365/safe-links-about)
- [Set up Safe Links policies](https://learn.microsoft.com/en-us/defender-office-365/safe-links-policies-configure)
- [Safe Attachments in Microsoft Defender for Office 365](https://learn.microsoft.com/en-us/defender-office-365/safe-attachments-about)

---

## Approval

| Role | Name | Decision | Date | Comments |
|---|---|---|---|---|
| MDO Technical Owner | | | | |
| Messaging Owner | | | | |
| Security Operations Owner | | | | |
| Pilot Business Owner | | | | |
