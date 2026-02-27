package tenableio

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
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

const (
	workbenchPageLimit  = 5000
	maxPageRequests     = 200
	maxResponseBodySize = 20 * 1024 * 1024
)

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

	start := time.Now()
	if c.diagnostics {
		c.logger.Info("tenable upstream collection start",
			"base_url", c.baseURL,
			"endpoint", c.endpoint,
			"page_limit", workbenchPageLimit,
			"max_pages", maxPageRequests,
			"max_attempts", c.maxAttempts,
			"has_access_key", creds.AccessKey != "",
			"has_secret_key", creds.SecretKey != "",
		)
	}

	out := make([]HostAggregate, 0, workbenchPageLimit)
	offset := 0
	pages := 0
	sourceField := "none"
	var previousBodyHash [32]byte
	hasPreviousHash := false

	for pages < maxPageRequests {
		requestURL := pagedRequestURL(u, workbenchPageLimit, offset)
		body, err := c.fetchWithRetry(ctx, requestURL, creds)
		if err != nil {
			return nil, err
		}

		page, err := parseHostPage(body)
		if err != nil {
			if c.diagnostics {
				c.logger.Error("tenable upstream parse failed",
					"url", requestURL,
					"offset", offset,
					"duration_ms", time.Since(start).Milliseconds(),
					"error", err.Error(),
					"body_sample", sampleBody(body, c.bodySampleBytes),
				)
			}
			return nil, err
		}

		bodyHash := sha256.Sum256(body)
		if hasPreviousHash && previousBodyHash == bodyHash && len(page.Rows) > 0 {
			// Guard against servers that ignore pagination params and keep returning the same page.
			c.logger.Warn("tenable upstream repeated page detected; stopping pagination", "url", requestURL, "offset", offset, "rows", len(page.Rows))
			break
		}
		previousBodyHash = bodyHash
		hasPreviousHash = true

		pages++
		out = append(out, page.Rows...)
		if sourceField == "none" && page.SourceField != "none" {
			sourceField = page.SourceField
		}

		if c.diagnostics {
			c.logger.Info("tenable upstream page collected",
				"url", requestURL,
				"page", pages,
				"offset", offset,
				"returned_rows", len(page.Rows),
				"total_rows_so_far", len(out),
				"source_field", page.SourceField,
				"total_known", page.TotalKnown,
				"total", page.Total,
				"has_next", page.HasNext,
			)
		}

		if len(page.Rows) == 0 {
			break
		}

		offset += len(page.Rows)
		stopPaging := false
		switch {
		case page.HasNext:
			continue
		case page.TotalKnown:
			if offset >= page.Total {
				stopPaging = true
			}
		case len(page.Rows) < workbenchPageLimit:
			stopPaging = true
		}
		if stopPaging {
			break
		}
	}

	if pages >= maxPageRequests {
		c.logger.Warn("tenable upstream pagination stopped at max page limit", "max_pages", maxPageRequests, "rows_collected", len(out))
	}
	if c.diagnostics {
		c.logger.Info("tenable upstream collection complete",
			"duration_ms", time.Since(start).Milliseconds(),
			"rows", len(out),
			"source_field", sourceField,
			"pages", pages,
		)
	}
	return out, nil
}

func pagedRequestURL(base *url.URL, limit, offset int) string {
	u := *base
	q := u.Query()
	q.Set("limit", strconv.Itoa(limit))
	q.Set("offset", strconv.Itoa(offset))
	u.RawQuery = q.Encode()
	return u.String()
}

func (c *WorkbenchClient) fetchWithRetry(ctx context.Context, requestURL string, creds auth.Credentials) ([]byte, error) {
	var body []byte
	var err error
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
			return body, nil
		}

		retryable, retryAfter := shouldRetry(err)
		if c.diagnostics {
			c.logger.Warn("tenable upstream request attempt failed",
				"url", requestURL,
				"attempt", attempt,
				"duration_ms", time.Since(attemptStart).Milliseconds(),
				"retryable", retryable,
				"error", err.Error(),
			)
		}
		if !retryable || attempt == c.maxAttempts {
			return nil, err
		}

		backoff := c.retryBackoffMin * time.Duration(math.Pow(2, float64(attempt-1)))
		if backoff > c.retryBackoffMax {
			backoff = c.retryBackoffMax
		}
		if retryAfter > backoff {
			backoff = retryAfter
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
		}
	}
	return nil, err
}

func shouldRetry(err error) (bool, time.Duration) {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false, 0
	}

	var unAuth *UnauthorizedError
	if errors.As(err, &unAuth) {
		return false, 0
	}

	var statusErr *upstreamStatusError
	if errors.As(err, &statusErr) {
		if statusErr.StatusCode == http.StatusTooManyRequests || statusErr.StatusCode >= 500 {
			return true, statusErr.RetryAfter
		}
		return false, 0
	}

	var netErr net.Error
	if errors.As(err, &netErr) {
		return true, 0
	}
	return false, 0
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

	b, _ := io.ReadAll(io.LimitReader(res.Body, maxResponseBodySize))
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
		return nil, &upstreamStatusError{
			StatusCode: res.StatusCode,
			Message:    sampleBody(b, c.bodySampleBytes),
			RetryAfter: parseRetryAfter(res.Header.Get("Retry-After")),
		}
	}
	return b, nil
}

type UnauthorizedError struct{ Message string }

func (e *UnauthorizedError) Error() string { return e.Message }

type upstreamStatusError struct {
	StatusCode int
	Message    string
	RetryAfter time.Duration
}

func (e *upstreamStatusError) Error() string {
	return fmt.Sprintf("tenable.io status %d: %s", e.StatusCode, e.Message)
}

type hostPage struct {
	Rows        []HostAggregate
	SourceField string
	Total       int
	TotalKnown  bool
	HasNext     bool
}

func parseHostPage(body []byte) (hostPage, error) {
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return hostPage{}, fmt.Errorf("parse tenable response: %w", err)
	}

	sourceField := "assets"
	assets := findObjectList(payload, "assets")
	if len(assets) == 0 {
		sourceField = "results"
		assets = findObjectList(payload, "results")
	}
	if len(assets) == 0 {
		sourceField = "none"
		total, totalKnown := extractTotal(payload)
		return hostPage{
			Rows:        []HostAggregate{},
			SourceField: sourceField,
			Total:       total,
			TotalKnown:  totalKnown,
			HasNext:     extractHasNext(payload),
		}, nil
	}

	rows := make([]HostAggregate, 0, len(assets))
	for _, asset := range assets {
		medium := extractSeverityCount(asset, 2, "severityMedium", "medium_count", "severity_medium", "medium")
		high := extractSeverityCount(asset, 3, "severityHigh", "high_count", "severity_high", "high")
		critical := extractSeverityCount(asset, 4, "severityCritical", "critical_count", "severity_critical", "critical")
		row := HostAggregate{
			IP:         extractFirstString(asset, "ipv4", "ip", "address", "ipv6"),
			DNSName:    extractFirstString(asset, "fqdn", "dnsName", "hostname", "host_name"),
			MACAddress: extractFirstString(asset, "macAddress", "mac_address", "mac"),
			Score:      extractScore(asset),
			Medium:     medium,
			High:       high,
			Critical:   critical,
		}
		rows = append(rows, row)
	}

	total, totalKnown := extractTotal(payload)
	return hostPage{
		Rows:        rows,
		SourceField: sourceField,
		Total:       total,
		TotalKnown:  totalKnown,
		HasNext:     extractHasNext(payload),
	}, nil
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
					if obj, ok := e.(map[string]any); ok {
						s := extractFirstString(obj, "ip", "address", "value", "name")
						if strings.TrimSpace(s) != "" {
							return strings.TrimSpace(s)
						}
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

func extractTotal(payload map[string]any) (int, bool) {
	if v := extractFirstIntPointer(payload, "total", "total_count", "totalCount"); v != nil {
		return *v, true
	}
	pagination, ok := payload["pagination"].(map[string]any)
	if !ok {
		return 0, false
	}
	if v := extractFirstIntPointer(pagination, "total", "total_count", "totalCount"); v != nil {
		return *v, true
	}
	return 0, false
}

func extractHasNext(payload map[string]any) bool {
	if b, ok := payload["has_next"].(bool); ok {
		return b
	}
	if b, ok := payload["hasNext"].(bool); ok {
		return b
	}
	if next, ok := payload["next"].(string); ok {
		return strings.TrimSpace(next) != ""
	}
	pagination, ok := payload["pagination"].(map[string]any)
	if !ok {
		return false
	}
	if b, ok := pagination["has_next"].(bool); ok {
		return b
	}
	if b, ok := pagination["hasNext"].(bool); ok {
		return b
	}
	if next, ok := pagination["next"].(string); ok {
		return strings.TrimSpace(next) != ""
	}
	return false
}

func extractScore(asset map[string]any) *int {
	if v := extractFirstIntPointer(asset, "score", "risk_score", "riskScore"); v != nil {
		return v
	}
	for _, key := range []string{"risk", "vpr"} {
		raw, ok := asset[key]
		if !ok {
			continue
		}
		nested, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if v := extractFirstIntPointer(nested, "score", "risk_score", "riskScore", "value"); v != nil {
			return v
		}
	}
	return nil
}

func extractSeverityCount(asset map[string]any, severityLevel int, directKeys ...string) int {
	if p := extractFirstIntPointer(asset, directKeys...); p != nil {
		return clampNonNegative(*p)
	}

	targetName := severityName(severityLevel)
	for _, key := range []string{"severities", "severity_count", "severity_counts", "severityCount"} {
		raw, ok := asset[key]
		if !ok {
			continue
		}
		switch t := raw.(type) {
		case map[string]any:
			if p := extractFirstIntPointer(t, targetName, strconv.Itoa(severityLevel)); p != nil {
				return clampNonNegative(*p)
			}
		case []any:
			for _, item := range t {
				obj, ok := item.(map[string]any)
				if !ok {
					continue
				}
				count := extractFirstIntPointer(obj, "count", "value", "total", "num")
				if count == nil {
					continue
				}
				if level := extractFirstIntPointer(obj, "level", "severity", "severityLevel", "id"); level != nil && *level == severityLevel {
					return clampNonNegative(*count)
				}
				name := strings.ToLower(strings.TrimSpace(extractFirstString(obj, "name", "severity_name", "severityName")))
				if name == targetName {
					return clampNonNegative(*count)
				}
			}
		}
	}
	return 0
}

func severityName(level int) string {
	switch level {
	case 2:
		return "medium"
	case 3:
		return "high"
	case 4:
		return "critical"
	default:
		return strconv.Itoa(level)
	}
}

func clampNonNegative(v int) int {
	if v < 0 {
		return 0
	}
	return v
}

func parseRetryAfter(v string) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs < 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		d := time.Until(t)
		if d < 0 {
			return 0
		}
		return d
	}
	return 0
}
