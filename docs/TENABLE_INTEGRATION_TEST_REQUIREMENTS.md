# Forward Tenable.io Integration Handoff Runbook (Oracle Linux)

## Purpose

This is a handoff-ready runbook for deploying and validating the Tenable.io integration endpoint on a Forward VM running Oracle Linux.

## Outcome

When complete, Forward can run Tenable collection successfully using these settings:

- URL: `https://<FORWARD_VM_OR_FQDN>:8080`
- Disable SSL Validation: `enabled` (required when using self-signed TLS)
- Credential username: `<TENABLE_ACCESS_KEY>`
- Credential password: `<TENABLE_SECRET_KEY>`

## Scope

### In Scope

- Oracle Linux setup on the Forward VM
- `systemd` service install and startup
- Proxy config required for Forward collection
- Exact Forward settings to enter
- Validation and troubleshooting checks

### Out of Scope

- Internal endpoint implementation details
- Component-level code behavior and design review

## Prerequisites

1. Forward VM (Oracle Linux) with sudo access.
2. Tenable.io access key and secret key for testing.
3. Collector source IP/CIDR that will call the endpoint.
4. This repo checked out on the Forward VM.

## Step 1: Install Binary and Runtime User

Run on the Forward VM:

```bash
sudo useradd --system --home-dir /var/lib/tenableio-sc-proxy --shell /sbin/nologin tenableproxy 2>/dev/null || true
sudo install -d -m 0750 -o tenableproxy -g tenableproxy /etc/tenableio-sc-proxy
sudo install -d -m 0750 -o tenableproxy -g tenableproxy /var/log/tenableio-sc-proxy
sudo install -m 0755 ./bin/tenableio-sc-proxy /usr/local/bin/tenableio-sc-proxy
```

## Step 2: Create Production Config

Create `/etc/tenableio-sc-proxy/config.yaml`:

```yaml
mode: "prod"

server:
  listen_addr: ":8080"
  read_timeout: 10s
  write_timeout: 30s
  idle_timeout: 60s

tls:
  enabled: true
  auto_self_signed: true
  cert_dir: "/tmp/tenableio-sc-proxy-tls"
  rotate_days: 30

security:
  allowed_access_keys:
    - "<TENABLE_ACCESS_KEY>"
  allowed_source_cidrs:
    - "127.0.0.1/32"
    - "<FORWARD_COLLECTOR_IP_OR_CIDR>"

dev:
  test_mode_enabled: false

reliability:
  serve_stale_on_upstream_error: true
  max_stale: 24h

tenable:
  base_url: "https://cloud.tenable.com"
  workbench_endpoint: "/workbenches/assets/vulnerabilities"
  page_limit: 5000
  max_pages: 200
  dedupe_by_ip: true
  timeout: 30s
  retry_max_attempts: 3
  retry_backoff_min: 500ms
  retry_backoff_max: 3s
  insecure_skip_verify: false

cache:
  ttl: 5m
  max_entries: 128

log:
  level: "info"
  format: "json"
  diagnostics: false
  request_body_sample_bytes: 0
  upstream_body_sample_bytes: 1024
```

Apply secure ownership/permissions:

```bash
sudo chown root:tenableproxy /etc/tenableio-sc-proxy/config.yaml
sudo chmod 0640 /etc/tenableio-sc-proxy/config.yaml
```

## Step 3: Validate Config Before Service Start

```bash
sudo /usr/local/bin/tenableio-sc-proxy configtest --config /etc/tenableio-sc-proxy/config.yaml
```

Expected output:

- `config ok`

## Step 4: Install and Start systemd Service

Install service unit from repo:

```bash
sudo install -m 0644 ./deploy/systemd/tenableio-sc-proxy.service /etc/systemd/system/tenableio-sc-proxy.service
sudo systemctl daemon-reload
sudo systemctl enable --now tenableio-sc-proxy
sudo systemctl status tenableio-sc-proxy --no-pager
```

Tail logs:

```bash
sudo journalctl -u tenableio-sc-proxy -n 100 --no-pager
```

## Step 5: Configure Forward Integration Settings

In Forward Tenable integration settings, enter exactly:

1. URL: `https://<FORWARD_VM_OR_FQDN>:8080`
2. Disable SSL Validation: `enabled` (for self-signed TLS)
3. Credential username: `<TENABLE_ACCESS_KEY>`
4. Credential password: `<TENABLE_SECRET_KEY>`

Important mapping:

- Forward credential username must match `security.allowed_access_keys`.
- Forward collector source IP must be included in `security.allowed_source_cidrs`.

## Step 6: Validate Service Locally on Forward VM

Health/readiness checks:

```bash
curl -kfsS https://127.0.0.1:8080/healthz
curl -kfsS https://127.0.0.1:8080/readyz
```

Optional direct endpoint probe (before running from Forward UI):

```bash
ACCESS_KEY='<TENABLE_ACCESS_KEY>'
SECRET_KEY='<TENABLE_SECRET_KEY>'
curl -skS https://127.0.0.1:8080/rest/analysis \
  -H "x-apikey: accesskey=${ACCESS_KEY}; secretkey=${SECRET_KEY};" \
  -H 'content-type: application/json' \
  --data '{"query":{"type":"vuln","tool":"sumip","startOffset":0,"endOffset":5,"filters":[{"filterName":"lastSeen","operator":"=","value":"0:1"}]},"sourceType":"cumulative","type":"vuln"}'
```

Expected result:

- HTTP `200` with JSON envelope and `error_code: 0`.

## Step 7: Validate from Forward

1. Save the Forward integration settings.
2. Run one manual collection.
3. Confirm run completes without fatal error.
4. Confirm Tenable-derived data appears in Forward.
5. Run one more collection and confirm stability.

## Troubleshooting Quick Map

- `401 unauthorized: invalid x-apikey`:
  - Re-check Forward credential format/values.
- `401 unauthorized: access key is not allowed`:
  - Add the credential username to `security.allowed_access_keys`.
- `403 forbidden: source IP not allowed`:
  - Add collector IP/CIDR to `security.allowed_source_cidrs`.
- `502 upstream fetch failed`:
  - Verify Tenable.io credentials and outbound HTTPS from VM.
- `/readyz` not ready:
  - Re-run `configtest` and fix config validation errors.

## Handoff Checklist

1. Service installed and active via `systemd`.
2. Local `healthz` and `readyz` pass.
3. Forward settings entered exactly as documented.
4. One successful Forward collection completed.
5. Evidence captured: service status, logs, and Forward run result.

## Document Metadata

- Version: `v0.3`
- Target Platform: `Oracle Linux on Forward VM`
