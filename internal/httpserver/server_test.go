package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/captainpacket/tenableio-sc-proxy/internal/auth"
	"github.com/captainpacket/tenableio-sc-proxy/internal/config"
	"github.com/captainpacket/tenableio-sc-proxy/internal/forwardsc"
	"github.com/captainpacket/tenableio-sc-proxy/internal/tenableio"
)

type fakeClient struct {
	calls int
	hosts []tenableio.HostAggregate
	err   error
}

func (f *fakeClient) FetchHostAggregates(_ context.Context, _ auth.Credentials) ([]tenableio.HostAggregate, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.hosts, nil
}

func TestAnalysisDayZero(t *testing.T) {
	fc := &fakeClient{hosts: []tenableio.HostAggregate{{IP: "10.0.0.1", DNSName: "h1", Medium: 1, High: 2, Critical: 3}}}
	cfg := config.Config{
		Security: config.SecurityConfig{AllowedAccessKeys: []string{"ak1"}},
		Cache:    config.CacheConfig{TTL: 1000000000, MaxEntries: 10},
		Tenable:  config.TenableConfig{WorkbenchEndpoint: "/x"},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := New(cfg, logger, fc, "test")

	body := []byte(`{"query":{"type":"vuln","tool":"sumip","startOffset":0,"endOffset":10,"filters":[{"filterName":"lastSeen","operator":"=","value":"0:1"}]},"sourceType":"cumulative","type":"vuln"}`)
	req := httptest.NewRequest(http.MethodPost, "/rest/analysis", bytes.NewReader(body))
	req.Header.Set("x-apikey", "accesskey=ak1; secretkey=sk1;")
	rr := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rr.Code, rr.Body.String())
	}
	if fc.calls != 1 {
		t.Fatalf("expected 1 upstream call, got %d", fc.calls)
	}

	var env forwardsc.AnalysisEnvelope
	if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
		t.Fatalf("json unmarshal: %v", err)
	}
	if env.Response.ReturnedRecords != 1 {
		t.Fatalf("expected one record, got %d", env.Response.ReturnedRecords)
	}
}

func TestAnalysisOldDayReturnsEmpty(t *testing.T) {
	fc := &fakeClient{hosts: []tenableio.HostAggregate{{IP: "10.0.0.1", Medium: 1, High: 1, Critical: 1}}}
	cfg := config.Config{
		Security: config.SecurityConfig{AllowedAccessKeys: []string{"ak1"}},
		Cache:    config.CacheConfig{TTL: 1000000000, MaxEntries: 10},
		Tenable:  config.TenableConfig{WorkbenchEndpoint: "/x"},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := New(cfg, logger, fc, "test")

	body := []byte(`{"query":{"type":"vuln","tool":"sumip","startOffset":0,"endOffset":10,"filters":[{"filterName":"lastSeen","operator":"=","value":"4:5"}]},"sourceType":"cumulative","type":"vuln"}`)
	req := httptest.NewRequest(http.MethodPost, "/rest/analysis", bytes.NewReader(body))
	req.Header.Set("x-apikey", "accesskey=ak1; secretkey=sk1;")
	rr := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d", rr.Code)
	}
	if fc.calls != 0 {
		t.Fatalf("expected 0 upstream call, got %d", fc.calls)
	}
}

func TestAnalysisUnauthorizedInbound(t *testing.T) {
	fc := &fakeClient{}
	cfg := config.Config{
		Security: config.SecurityConfig{AllowedAccessKeys: []string{"allowed"}},
		Cache:    config.CacheConfig{TTL: 1000000000, MaxEntries: 10},
		Tenable:  config.TenableConfig{WorkbenchEndpoint: "/x"},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := New(cfg, logger, fc, "test")

	body := []byte(`{"query":{"type":"vuln","tool":"sumip","startOffset":0,"endOffset":10,"filters":[{"filterName":"lastSeen","operator":"=","value":"0:1"}]},"sourceType":"cumulative","type":"vuln"}`)
	req := httptest.NewRequest(http.MethodPost, "/rest/analysis", bytes.NewReader(body))
	req.Header.Set("x-apikey", "accesskey=not-allowed; secretkey=sk1;")
	rr := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestAnalysisDevModeBypass(t *testing.T) {
	fc := &fakeClient{}
	cfg := config.Config{
		Security: config.SecurityConfig{AllowedAccessKeys: []string{"temp-forward-user"}},
		Dev:      config.DevConfig{TestModeEnabled: true, AccessKey: "temp-forward-user", SecretKey: "temp-forward-pass"},
		Cache:    config.CacheConfig{TTL: 1000000000, MaxEntries: 10},
		Tenable:  config.TenableConfig{WorkbenchEndpoint: "/x"},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := New(cfg, logger, fc, "test")

	body := []byte(`{"query":{"type":"vuln","tool":"sumip","startOffset":0,"endOffset":1,"filters":[{"filterName":"lastSeen","operator":"=","value":"0:1"}]},"sourceType":"cumulative","type":"vuln"}`)
	req := httptest.NewRequest(http.MethodPost, "/rest/analysis", bytes.NewReader(body))
	req.Header.Set("x-apikey", "accesskey=temp-forward-user; secretkey=temp-forward-pass;")
	rr := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", rr.Code, rr.Body.String())
	}
	if fc.calls != 0 {
		t.Fatalf("expected 0 upstream calls in dev mode, got %d", fc.calls)
	}
	var env forwardsc.AnalysisEnvelope
	if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
		t.Fatalf("json unmarshal: %v", err)
	}
	if env.Response.ReturnedRecords < 1 {
		t.Fatalf("expected fake rows in dev mode, got %d", env.Response.ReturnedRecords)
	}
}

func TestSourceCIDRForbidden(t *testing.T) {
	fc := &fakeClient{}
	cfg := config.Config{
		Security: config.SecurityConfig{
			AllowedAccessKeys:  []string{"ak1"},
			AllowedSourceCIDRs: []string{"127.0.0.1/32"},
		},
		Cache:   config.CacheConfig{TTL: time.Second, MaxEntries: 10},
		Tenable: config.TenableConfig{WorkbenchEndpoint: "/x"},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := New(cfg, logger, fc, "test")

	body := []byte(`{"query":{"type":"vuln","tool":"sumip","startOffset":0,"endOffset":10,"filters":[{"filterName":"lastSeen","operator":"=","value":"0:1"}]},"sourceType":"cumulative","type":"vuln"}`)
	req := httptest.NewRequest(http.MethodPost, "/rest/analysis", bytes.NewReader(body))
	req.Header.Set("x-apikey", "accesskey=ak1; secretkey=sk1;")
	req.RemoteAddr = "10.99.99.99:12345"
	rr := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
}

func TestServeStaleOnUpstreamError(t *testing.T) {
	fc := &fakeClient{hosts: []tenableio.HostAggregate{{IP: "10.0.0.1", DNSName: "h1", Medium: 1, High: 2, Critical: 3}}}
	cfg := config.Config{
		Security: config.SecurityConfig{AllowedAccessKeys: []string{"ak1"}},
		Reliability: config.ReliabilityConfig{
			ServeStaleOnUpstreamError: true,
			MaxStale:                  time.Hour,
		},
		Cache:   config.CacheConfig{TTL: time.Millisecond, MaxEntries: 10},
		Tenable: config.TenableConfig{WorkbenchEndpoint: "/x"},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := New(cfg, logger, fc, "test")

	body := []byte(`{"query":{"type":"vuln","tool":"sumip","startOffset":0,"endOffset":10,"filters":[{"filterName":"lastSeen","operator":"=","value":"0:1"}]},"sourceType":"cumulative","type":"vuln"}`)
	req1 := httptest.NewRequest(http.MethodPost, "/rest/analysis", bytes.NewReader(body))
	req1.Header.Set("x-apikey", "accesskey=ak1; secretkey=sk1;")
	rr1 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("first request failed: %d", rr1.Code)
	}

	time.Sleep(5 * time.Millisecond)
	fc.err = &tenableio.UnauthorizedError{Message: "unauthorized"}
	req2 := httptest.NewRequest(http.MethodPost, "/rest/analysis", bytes.NewReader(body))
	req2.Header.Set("x-apikey", "accesskey=ak1; secretkey=sk1;")
	rr2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("expected stale 200, got %d body=%s", rr2.Code, rr2.Body.String())
	}
	if rr2.Header().Get("X-Proxy-Cache") != "STALE" {
		t.Fatalf("expected STALE header, got %q", rr2.Header().Get("X-Proxy-Cache"))
	}
}
