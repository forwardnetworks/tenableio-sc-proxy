# Tenable.io Integration Test Requirements

## Purpose

This document defines the test scope, environment requirements, and acceptance criteria for validating the `tenableio-sc-proxy` solution.

## Solution Under Test

### Component

- Service: `tenableio-sc-proxy`
- Role: Translates Tenable.io responses into the Tenable.sc-compatible `sumip` analysis format used by Forward's Tenable SC integration path.

### Interfaces

- Inbound from collector/integration client:
  - `POST /rest/analysis`
  - Auth via `x-apikey` header (`accesskey=...; secretkey=...;`)
- Operational endpoints:
  - `GET /healthz`
  - `GET /readyz`
- Outbound to Tenable.io:
  - Vulnerability/workbench API calls over HTTPS

### Security Controls Implemented by Proxy

- Access-key allowlist (`security.allowed_access_keys`)
- Source CIDR allowlist (`security.allowed_source_cidrs`)
- TLS termination with cert/key management
- Optional diagnostics mode that avoids logging raw API keys

## Test Objectives

1. Validate successful end-to-end integration between Forward workflow and Tenable.io through the proxy.
2. Confirm security controls block unauthorized credentials and unauthorized source IPs.
3. Confirm operational reliability behavior, including cache and stale-response handling.
4. Validate observability and evidence capture for production onboarding.

## Environment Requirements

### Systems

- One Linux host for `tenableio-sc-proxy`
- One Forward collector/integration client host
- Access to a Tenable.io tenant with test data

### Network

- HTTPS connectivity from proxy host to Tenable.io APIs
- HTTPS connectivity from collector to proxy (`/rest/analysis`)
- Firewall rules permitting only approved test sources

### Configuration Baseline

- Use `config.example.yaml` as hardened baseline
- `dev.test_mode_enabled=false`
- Populate `security.allowed_access_keys` with test access key IDs
- Populate `security.allowed_source_cidrs` with approved source ranges
- Configure TLS certificate trust on test collector host

## External Tester Inputs Required Before Test Start

1. Approved test point-of-contact list and escalation contacts.
2. Approved source IP/CIDR ranges for integration test traffic.
3. Tenable.io test account/API credential policy and key rotation rules.
4. Data classification/handling constraints for logs, captures, and exported evidence.
5. Required retention period and approved storage location for test artifacts.
6. Formal definition of pass/fail threshold for pilot acceptance.

## Test Cases

### TC-01: Health and Readiness

- Verify `GET /healthz` returns success.
- Verify `GET /readyz` returns success with hardened config.

### TC-02: Authorized End-to-End Query

- Send valid `POST /rest/analysis` request through integration client.
- Confirm translated response contains expected `sumip`-compatible rows.

### TC-03: Unauthorized Credential Rejection

- Use invalid or non-allowlisted access key.
- Expect rejection (`401`) and diagnostic reason in logs.

### TC-04: Unauthorized Source Rejection

- Send request from non-allowlisted source.
- Expect rejection (`403`) and diagnostic reason in logs.

### TC-05: Upstream Failure and Stale Behavior

- Simulate Tenable.io unavailability.
- Confirm `STALE` cache behavior is used when within `reliability.max_stale`.
- Confirm failure behavior when stale cache is unavailable or expired.

### TC-06: Logging and Evidence Adequacy

- Enable diagnostics (`log.level=debug`, `log.diagnostics=true`).
- Validate logs include lifecycle, upstream status, and cache outcome without raw key disclosure.

## Entry Criteria

- Required pre-test inputs completed and approved.
- Environment deployed and reachable.
- Test credentials provisioned and validated.
- Time window and personnel availability confirmed.

## Exit Criteria

- All required test cases executed.
- No unresolved high-severity defects.
- Evidence package delivered and accepted by program stakeholders.
- Any open low/medium issues tracked with remediation owner and due date.

## Required Evidence Artifacts

- Config snapshot (with secrets redacted)
- Health/readiness command output
- Request/response samples for pass/fail cases
- Proxy logs for each test case
- Issue log with defect severity and disposition
- Final acceptance summary

## Open Items for Review

- Confirm required API scope minimums for Tenable.io test credentials.
- Confirm whether synthetic vulnerability data is required vs. production-like masked data.
- Confirm exact compliance reporting format expected for sign-off.

## Approval

- Test Lead: `TBD`
- Integration Owner: `TBD`
- Security Reviewer: `TBD`
- Planned Test Window: `TBD`
- Document Version: `v0.1`
