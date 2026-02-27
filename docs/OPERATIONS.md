# Operations Runbook

## Startup Checklist

1. Use `config.example.yaml` (prod mode) or equivalent hardened config.
2. Confirm `dev.test_mode_enabled=false`.
3. Confirm `security.allowed_access_keys` contains only authorized key IDs.
4. Confirm `security.allowed_source_cidrs` contains collector host CIDRs.
5. Confirm TLS endpoint is reachable and cert trust is pinned on collector host.

## Health Checks

- Liveness: `GET /healthz`
- Readiness: `GET /readyz`

Readiness will fail when critical hardening constraints are violated (e.g. dev mode in prod).

## Debug Mode for Customer Validation

When onboarding new credentials or debugging failures:

1. Set `log.level: "debug"`.
2. Set `log.diagnostics: true`.
3. Optional: set `log.request_body_sample_bytes` to a bounded value like `1024`.

This logs request lifecycle, source-IP and allowlist rejects, upstream latency/failures, and cache path decisions without exposing raw API keys.

## Data Gathering Controls

- `tenable.page_limit`: upstream assets per request page (default `5000`).
- `tenable.max_pages`: upper bound on page fetches per run (default `200`).
- `tenable.dedupe_by_ip`: merges duplicate assets by IP before building `sumip` rows.

With diagnostics enabled, logs include per-run data quality counters:

- parsed assets
- fallback parsing usage for score/severity fields
- invalid-IP drops
- duplicate merges (when dedupe is enabled)

## Common Failure Modes

### 401 from proxy

- Check Forward credential values and allowlist key IDs.
- Confirm `x-apikey` parsing format: `accesskey=...; secretkey=...;`.

### 403 from proxy

- Source IP is outside configured `allowed_source_cidrs`.

### 502 from proxy

- Tenable.io unavailable or upstream request errors.
- If stale cache is available and not older than `reliability.max_stale`, proxy should serve stale.

## Certificate Rotation

Self-signed mode uses certs in `tls.cert_dir`.

1. Stop service.
2. Remove old cert/key files from cert dir.
3. Start service; new cert/key are generated automatically.
4. Re-pin trust on collector host if required.

## Rollback

1. Keep previous binary under `/usr/local/bin/tenableio-sc-proxy.prev`.
2. Replace active binary with previous version.
3. Restart service and validate `/healthz` and `/readyz`.
