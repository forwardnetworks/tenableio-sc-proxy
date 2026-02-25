package tenableio

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/captainpacket/tenableio-sc-proxy/internal/auth"
)

type HostAggregate struct {
	IP         string
	DNSName    string
	MACAddress string
	Score      *int
	Medium     int
	High       int
	Critical   int
}

type Client interface {
	FetchHostAggregates(ctx context.Context, creds auth.Credentials) ([]HostAggregate, error)
}

type WorkbenchClient struct {
	httpClient      *http.Client
	logger          *slog.Logger
	baseURL         string
	endpoint        string
	maxAttempts     int
	retryBackoffMin time.Duration
	retryBackoffMax time.Duration
	diagnostics     bool
	bodySampleBytes int
}

func NewWorkbenchClient(logger *slog.Logger, baseURL, endpoint string, timeout time.Duration, insecureSkipVerify bool, maxAttempts int, backoffMin, backoffMax time.Duration, diagnostics bool, bodySampleBytes int) *WorkbenchClient {
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureSkipVerify}}
	if bodySampleBytes < 0 {
		bodySampleBytes = 0
	}
	return &WorkbenchClient{
		httpClient:      &http.Client{Timeout: timeout, Transport: transport},
		logger:          logger,
		baseURL:         strings.TrimRight(baseURL, "/"),
		endpoint:        endpoint,
		maxAttempts:     maxAttempts,
		retryBackoffMin: backoffMin,
		retryBackoffMax: backoffMax,
		diagnostics:     diagnostics,
		bodySampleBytes: bodySampleBytes,
	}
}

func (c *WorkbenchClient) FetchHostAggregates(ctx context.Context, creds auth.Credentials) ([]HostAggregate, error) {
	u, err := url.Parse(c.baseURL + c.endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid tenable url: %w", err)
	}

	q := u.Query()
	q.Set("limit", "5000")
	u.RawQuery = q.Encode()
	requestURL := u.String()

	var body []byte
	start := time.Now()
	if c.diagnostics {
		c.logger.Info("tenable upstream request start",
			"url", requestURL,
			"max_attempts", c.maxAttempts,
			"has_access_key", creds.AccessKey != "",
			"has_secret_key", creds.SecretKey != "",
		)
	}
	for attempt := 1; attempt <= c.maxAttempts; attempt++ {
		attemptStart := time.Now()
		body, err = c.fetchOnce(ctx, requestURL, creds)
		if err == nil {
			if c.diagnostics {
				c.logger.Info("tenable upstream request attempt success",
					"url", requestURL,
					"attempt", attempt,
					"duration_ms", time.Since(attemptStart).Milliseconds(),
					"response_bytes", len(body),
				)
			}
			break
		}
		if c.diagnostics {
			c.logger.Warn("tenable upstream request attempt failed",
				"url", requestURL,
				"attempt", attempt,
				"duration_ms", time.Since(attemptStart).Milliseconds(),
				"error", err.Error(),
			)
		}
		if attempt == c.maxAttempts {
			return nil, err
		}
		backoff := c.retryBackoffMin * time.Duration(math.Pow(2, float64(attempt-1)))
		if backoff > c.retryBackoffMax {
			backoff = c.retryBackoffMax
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
		}
	}

	rows, sourceField, err := parseHosts(body)
	if err != nil {
		if c.diagnostics {
			c.logger.Error("tenable upstream parse failed",
				"url", requestURL,
				"duration_ms", time.Since(start).Milliseconds(),
				"error", err.Error(),
				"body_sample", sampleBody(body, c.bodySampleBytes),
			)
		}
		return nil, err
	}
	if c.diagnostics {
		c.logger.Info("tenable upstream request complete",
			"url", requestURL,
			"duration_ms", time.Since(start).Milliseconds(),
			"rows", len(rows),
			"source_field", sourceField,
		)
	}
	return rows, nil
}

func (c *WorkbenchClient) fetchOnce(ctx context.Context, u string, creds auth.Credentials) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-ApiKeys", fmt.Sprintf("accessKey=%s; secretKey=%s;", creds.AccessKey, creds.SecretKey))
	req.Header.Set("User-Agent", "Integration/1.0 (Forward Networks; Tenable Collector; Build/1.0)")

	res, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("tenable request failed: %w", err)
	}
	defer res.Body.Close()

	b, _ := io.ReadAll(io.LimitReader(res.Body, 20*1024*1024))
	if res.StatusCode == http.StatusUnauthorized {
		if c.diagnostics {
			c.logger.Warn("tenable upstream unauthorized",
				"url", u,
				"status_code", res.StatusCode,
				"body_sample", sampleBody(b, c.bodySampleBytes),
			)
		}
		return nil, &UnauthorizedError{Message: "tenable.io unauthorized"}
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		if c.diagnostics {
			c.logger.Warn("tenable upstream non-2xx response",
				"url", u,
				"status_code", res.StatusCode,
				"body_sample", sampleBody(b, c.bodySampleBytes),
			)
		}
		return nil, fmt.Errorf("tenable.io status %d: %s", res.StatusCode, sampleBody(b, c.bodySampleBytes))
	}
	return b, nil
}

type UnauthorizedError struct{ Message string }

func (e *UnauthorizedError) Error() string { return e.Message }

func parseHosts(body []byte) ([]HostAggregate, string, error) {
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, "", fmt.Errorf("parse tenable response: %w", err)
	}

	sourceField := "assets"
	assets := findObjectList(payload, "assets")
	if len(assets) == 0 {
		sourceField = "results"
		assets = findObjectList(payload, "results")
	}
	if len(assets) == 0 {
		sourceField = "none"
		return []HostAggregate{}, sourceField, nil
	}

	rows := make([]HostAggregate, 0, len(assets))
	for _, asset := range assets {
		row := HostAggregate{
			IP:         extractFirstString(asset, "ipv4", "ip", "address"),
			DNSName:    extractFirstString(asset, "fqdn", "dnsName", "hostname", "host_name"),
			MACAddress: extractFirstString(asset, "macAddress", "mac_address", "mac"),
			Score:      extractFirstIntPointer(asset, "score", "risk_score", "riskScore"),
			Medium:     extractFirstInt(asset, "severityMedium", "medium_count", "severity_medium", "medium"),
			High:       extractFirstInt(asset, "severityHigh", "high_count", "severity_high", "high"),
			Critical:   extractFirstInt(asset, "severityCritical", "critical_count", "severity_critical", "critical"),
		}
		rows = append(rows, row)
	}

	return rows, sourceField, nil
}

func sampleBody(body []byte, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	if len(body) <= maxBytes {
		return string(body)
	}
	return string(body[:maxBytes])
}

func findObjectList(payload map[string]any, key string) []map[string]any {
	raw, ok := payload[key]
	if !ok {
		return nil
	}
	arr, ok := raw.([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(arr))
	for _, item := range arr {
		if m, ok := item.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func extractFirstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			switch t := v.(type) {
			case string:
				return strings.TrimSpace(t)
			case []any:
				for _, e := range t {
					if s, ok := e.(string); ok && strings.TrimSpace(s) != "" {
						return strings.TrimSpace(s)
					}
				}
			}
		}
	}
	return ""
}

func extractFirstInt(m map[string]any, keys ...string) int {
	if p := extractFirstIntPointer(m, keys...); p != nil {
		return *p
	}
	return 0
}

func extractFirstIntPointer(m map[string]any, keys ...string) *int {
	for _, k := range keys {
		v, ok := m[k]
		if !ok {
			continue
		}
		switch t := v.(type) {
		case float64:
			i := int(t)
			return &i
		case int:
			i := t
			return &i
		case string:
			i, err := strconv.Atoi(strings.TrimSpace(t))
			if err == nil {
				return &i
			}
		}
	}
	return nil
}
