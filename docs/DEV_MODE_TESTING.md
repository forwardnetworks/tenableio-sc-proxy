# Dev Mode Testing (Optional)

This document is only for local fake-data testing. Do not use this mode in production.

## Run

```bash
go run ./cmd/proxy run --config ./config.dev.example.yaml
```

## Test Credentials

- Access key: `temp-forward-user`
- Secret key: `temp-forward-pass`

## Forward Localhost Settings

- URL: `https://127.0.0.1:8080`
- Disable SSL Validation: enabled
- Credential username: `temp-forward-user`
- Credential password: `temp-forward-pass`

## Behavior

- Requests with those credentials return fake `sumip` rows.
- No real Tenable.io API data is used.
