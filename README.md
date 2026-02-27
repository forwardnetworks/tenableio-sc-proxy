# tenableio-sc-proxy

Tenable.io -> Tenable.sc compatibility proxy for Forward's Tenable SC `sumip` integration path.

## Run

```bash
go run ./cmd/proxy run --config ./config.example.yaml
```

`config.example.yaml` is the production baseline.

In Forward Tenable SC settings:

- URL: `https://<proxy-host>:8080`
- Disable SSL Validation: enabled
- Credential username: `<TENABLE_ACCESS_KEY>`
- Credential password: `<TENABLE_SECRET_KEY>`

Operational endpoints:

- `GET /healthz` (liveness)
- `GET /readyz` (readiness)

Response headers on `/rest/analysis`:

- `X-Proxy-Cache: HIT|MISS|STALE|NONE`
- `X-Proxy-Stale-Age-Seconds` when stale cache is served

## Data Collection Tuning

In `tenable` config:

- `page_limit`: number of assets requested per upstream page (default `5000`)
- `max_pages`: hard stop to prevent runaway pagination (default `200`)
- `dedupe_by_ip`: merge duplicate assets by IP before response to Forward

## Debug Logging

For customer onboarding and credential troubleshooting, enable:

- `log.level: "debug"`
- `log.diagnostics: true`
- `log.request_body_sample_bytes: 1024` (or `0` to disable body sampling)
- `log.upstream_body_sample_bytes: 2048` (or `0` to suppress upstream samples)

Diagnostics mode logs:

- request acceptance/rejection reason
- access key hash (never logs raw keys)
- upstream fetch latency/outcome
- upstream URL, retry-attempt progression, HTTP status
- parsed asset counters and fallback usage (score/severity extraction)
- data quality counters (input rows, invalid IP drops, merged duplicates)
- cache behavior (`HIT|MISS|STALE|NONE`)
- end-to-end request duration

## Documentation

- Forward VM setup and validation handoff: `docs/TENABLE_INTEGRATION_TEST_REQUIREMENTS.md`
- Operations runbook: `docs/OPERATIONS.md`
- Optional local dev-mode testing: `docs/DEV_MODE_TESTING.md`

## Commands

- `proxy run --config <path>`
- `proxy configtest --config <path>`
- `proxy version`
