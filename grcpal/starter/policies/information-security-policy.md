---
title: Information Security Policy
owner: security-lead
approver: executive-sponsor
controls: [GOV-01, GOV-04, GOV-06]
version: 1.0
effective: 2026-01-01
next_review: 2026-12-31
acknowledge: true
---

# Information Security Policy

> Sample policy shipped with GRC-pal. Replace every statement with what your organization
> actually does, then approve it by pull request.

## Purpose
Protect the confidentiality, integrity and availability of company and customer information,
and meet the commitments made to customers in contracts and the SOC 2 report.

## Scope
All employees, contractors and systems that store, process or transmit company or customer data.

## Policy
1. The executive sponsor approves this policy and every supporting policy at least once a year (GOV-01).
2. Every person with access reads and acknowledges this policy at hire and yearly (GOV-04).
3. Access to systems is granted on least privilege, approved by the system owner, reviewed quarterly
   and removed within one business day of termination (IAM controls).
4. All workforce accounts use phishing-resistant or app-based multi-factor authentication (IAM-02).
5. Company devices are enrolled in device management, encrypted and kept patched (END-01).
6. Production changes are peer reviewed and tested before release (CHG-01).
7. Security events are logged, monitored and handled under the Incident Response Plan (IR-01).
8. Customer data is classified, encrypted in transit and at rest, and deleted at the end of the contract (DAT controls).
9. New vendors that handle company data are risk reviewed before use (VEN-01).

## Roles and responsibilities
- Executive sponsor: approves policy, funds the program, reviews program health monthly.
- Security lead: maintains this policy and the control catalog, reports status.
- Managers: ensure their teams complete training and follow this policy.
- Everyone: follows this policy and reports suspected incidents immediately.

## Exceptions
Request through the exception register with compensating controls and executive sponsor approval.

## Enforcement
Violations are handled through the HR disciplinary process.
