# Operations Runbook

## Startup Checklist

1. Use `config.example.yaml` (prod mode) or equivalent hardened config.
2. Confirm `security.allowed_source_cidrs` contains collector host CIDRs.
3. Confirm TLS mode is set correctly:
   - self-signed (`tls.auto_self_signed=true`) with Forward SSL validation disabled, or
   - custom trusted cert (`tls.auto_self_signed=false`) with cert/key paths configured.
4. Confirm endpoint is reachable from collector.

## Optional Access-Key Allowlist (No Keys in YAML)

If you want access-key allowlisting without putting keys in `config.yaml`, set environment variable
`PROXY_ALLOWED_ACCESS_KEYS` (comma-separated).

Example systemd drop-in:

```bash
sudo systemctl edit tenableio-sc-proxy
```

```ini
[Service]
Environment="PROXY_ALLOWED_ACCESS_KEYS=ak1,ak2"
```

Then apply:

```bash
sudo systemctl daemon-reload
sudo systemctl restart tenableio-sc-proxy
```

## Health Checks

- Liveness: `GET /healthz`
- Readiness: `GET /readyz`

Readiness will fail when critical hardening constraints are violated.

## Debug Mode for Customer Validation

When onboarding new credentials or debugging failures:

1. Set `log.level: "debug"`.
2. Set `log.diagnostics: true`.
3. Optional: set `log.request_body_sample_bytes` to a bounded value like `1024`.

This logs request lifecycle, source-IP and allowlist rejects, upstream latency/failures, and cache path decisions without exposing raw API keys.

## Escalated Debug Logging (Issue Reproduction)

If a problem is intermittent or unclear, temporarily increase debug sampling:

1. Set:
   - `log.level: "debug"`
   - `log.diagnostics: true`
   - `log.request_body_sample_bytes: 2048`
   - `log.upstream_body_sample_bytes: 8192`
2. Restart service:
   - `sudo systemctl restart tenableio-sc-proxy`
3. Reproduce the issue once from Forward.
4. Capture logs:
   - `sudo journalctl -u tenableio-sc-proxy --since "15 min ago" --no-pager`
5. Revert to baseline logging after capture (reduce sampling and/or return to `info` level).

Note: higher sample sizes can increase sensitive payload exposure in logs. Use only for short troubleshooting windows.

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

- Check Forward credential values.
- Confirm `x-apikey` parsing format: `accesskey=...; secretkey=...;`.
- If allowlist mode is enabled via `PROXY_ALLOWED_ACCESS_KEYS`, ensure key is listed.

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
