package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Mode        string            `yaml:"mode"`
	Server      ServerConfig      `yaml:"server"`
	TLS         TLSConfig         `yaml:"tls"`
	Security    SecurityConfig    `yaml:"security"`
	Dev         DevConfig         `yaml:"dev"`
	Reliability ReliabilityConfig `yaml:"reliability"`
	Tenable     TenableConfig     `yaml:"tenable"`
	Cache       CacheConfig       `yaml:"cache"`
	Log         LogConfig         `yaml:"log"`
}

type ServerConfig struct {
	ListenAddr   string        `yaml:"listen_addr"`
	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`
	IdleTimeout  time.Duration `yaml:"idle_timeout"`
}

type SecurityConfig struct {
	AllowedAccessKeys  []string `yaml:"allowed_access_keys"`
	AllowedSourceCIDRs []string `yaml:"allowed_source_cidrs"`
}

type DevConfig struct {
	TestModeEnabled bool         `yaml:"test_mode_enabled"`
	AccessKey       string       `yaml:"access_key"`
	SecretKey       string       `yaml:"secret_key"`
	FakeRows        []DevFakeRow `yaml:"fake_rows"`
}

type DevFakeRow struct {
	IP               string `yaml:"ip"`
	DNSName          string `yaml:"dns_name"`
	MACAddress       string `yaml:"mac_address"`
	Score            string `yaml:"score"`
	SeverityMedium   string `yaml:"severity_medium"`
	SeverityHigh     string `yaml:"severity_high"`
	SeverityCritical string `yaml:"severity_critical"`
}

type TLSConfig struct {
	Enabled        bool   `yaml:"enabled"`
	AutoSelfSigned bool   `yaml:"auto_self_signed"`
	CertFile       string `yaml:"cert_file"`
	KeyFile        string `yaml:"key_file"`
	CertDir        string `yaml:"cert_dir"`
	RotateDays     int    `yaml:"rotate_days"`
}

type ReliabilityConfig struct {
	ServeStaleOnUpstreamError bool          `yaml:"serve_stale_on_upstream_error"`
	MaxStale                  time.Duration `yaml:"max_stale"`
}

type TenableConfig struct {
	BaseURL            string        `yaml:"base_url"`
	WorkbenchEndpoint  string        `yaml:"workbench_endpoint"`
	PageLimit          int           `yaml:"page_limit"`
	MaxPages           int           `yaml:"max_pages"`
	DedupeByIP         bool          `yaml:"dedupe_by_ip"`
	Timeout            time.Duration `yaml:"timeout"`
	RetryMaxAttempts   int           `yaml:"retry_max_attempts"`
	RetryBackoffMin    time.Duration `yaml:"retry_backoff_min"`
	RetryBackoffMax    time.Duration `yaml:"retry_backoff_max"`
	InsecureSkipVerify bool          `yaml:"insecure_skip_verify"`
}

type CacheConfig struct {
	TTL        time.Duration `yaml:"ttl"`
	MaxEntries int           `yaml:"max_entries"`
}

type LogConfig struct {
	Level                   string `yaml:"level"`
	Format                  string `yaml:"format"`
	Diagnostics             bool   `yaml:"diagnostics"`
	RequestBodySampleBytes  int    `yaml:"request_body_sample_bytes"`
	UpstreamBodySampleBytes int    `yaml:"upstream_body_sample_bytes"`
}

func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}

	applyDefaults(&cfg)
	overrideFromEnv(&cfg)
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func applyDefaults(cfg *Config) {
	if cfg.Mode == "" {
		cfg.Mode = "prod"
	}
	if cfg.Server.ListenAddr == "" {
		cfg.Server.ListenAddr = ":8080"
	}
	if cfg.Server.ReadTimeout == 0 {
		cfg.Server.ReadTimeout = 10 * time.Second
	}
	if cfg.Server.WriteTimeout == 0 {
		cfg.Server.WriteTimeout = 30 * time.Second
	}
	if cfg.Server.IdleTimeout == 0 {
		cfg.Server.IdleTimeout = 60 * time.Second
	}
	if cfg.TLS.CertDir == "" {
		cfg.TLS.CertDir = "/tmp/tenableio-sc-proxy-tls"
	}
	if cfg.TLS.RotateDays == 0 {
		cfg.TLS.RotateDays = 30
	}
	if cfg.Reliability.MaxStale == 0 {
		cfg.Reliability.MaxStale = 24 * time.Hour
	}
	if cfg.Tenable.Timeout == 0 {
		cfg.Tenable.Timeout = 30 * time.Second
	}
	if cfg.Tenable.PageLimit == 0 {
		cfg.Tenable.PageLimit = 5000
	}
	if cfg.Tenable.MaxPages == 0 {
		cfg.Tenable.MaxPages = 200
	}
	if cfg.Tenable.RetryMaxAttempts == 0 {
		cfg.Tenable.RetryMaxAttempts = 3
	}
	if cfg.Tenable.RetryBackoffMin == 0 {
		cfg.Tenable.RetryBackoffMin = 500 * time.Millisecond
	}
	if cfg.Tenable.RetryBackoffMax == 0 {
		cfg.Tenable.RetryBackoffMax = 3 * time.Second
	}
	if cfg.Cache.TTL == 0 {
		cfg.Cache.TTL = 5 * time.Minute
	}
	if cfg.Cache.MaxEntries == 0 {
		cfg.Cache.MaxEntries = 128
	}
	if cfg.Log.Level == "" {
		cfg.Log.Level = "info"
	}
	if cfg.Log.Format == "" {
		cfg.Log.Format = "json"
	}
	if cfg.Log.RequestBodySampleBytes < 0 {
		cfg.Log.RequestBodySampleBytes = 0
	}
	if cfg.Log.UpstreamBodySampleBytes == 0 {
		cfg.Log.UpstreamBodySampleBytes = 1024
	}
	if cfg.Log.UpstreamBodySampleBytes < 0 {
		cfg.Log.UpstreamBodySampleBytes = 0
	}
}

func overrideFromEnv(cfg *Config) {
	if v := os.Getenv("PROXY_LISTEN_ADDR"); v != "" {
		cfg.Server.ListenAddr = v
	}
	if v := os.Getenv("PROXY_MODE"); v != "" {
		cfg.Mode = strings.ToLower(strings.TrimSpace(v))
	}
	if v := os.Getenv("PROXY_ALLOWED_ACCESS_KEYS"); v != "" {
		cfg.Security.AllowedAccessKeys = splitCSV(v)
	}
	if v := os.Getenv("PROXY_ALLOWED_SOURCE_CIDRS"); v != "" {
		cfg.Security.AllowedSourceCIDRs = splitCSV(v)
	}
	if v := os.Getenv("PROXY_TLS_ENABLED"); strings.EqualFold(v, "true") || v == "1" {
		cfg.TLS.Enabled = true
	}
	if v := os.Getenv("PROXY_TLS_AUTO_SELF_SIGNED"); strings.EqualFold(v, "true") || v == "1" {
		cfg.TLS.AutoSelfSigned = true
	}
	if v := os.Getenv("PROXY_TLS_CERT_FILE"); v != "" {
		cfg.TLS.CertFile = v
	}
	if v := os.Getenv("PROXY_TLS_KEY_FILE"); v != "" {
		cfg.TLS.KeyFile = v
	}
	if v := os.Getenv("PROXY_TLS_CERT_DIR"); v != "" {
		cfg.TLS.CertDir = v
	}
	if v := os.Getenv("PROXY_TENABLE_BASE_URL"); v != "" {
		cfg.Tenable.BaseURL = v
	}
	if v := os.Getenv("PROXY_TENABLE_WORKBENCH_ENDPOINT"); v != "" {
		cfg.Tenable.WorkbenchEndpoint = v
	}
	if v := os.Getenv("PROXY_TENABLE_PAGE_LIMIT"); v != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			cfg.Tenable.PageLimit = n
		}
	}
	if v := os.Getenv("PROXY_TENABLE_MAX_PAGES"); v != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			cfg.Tenable.MaxPages = n
		}
	}
	if v := os.Getenv("PROXY_TENABLE_DEDUPE_BY_IP"); v != "" {
		cfg.Tenable.DedupeByIP = strings.EqualFold(v, "true") || v == "1"
	}
	if v := os.Getenv("PROXY_DEV_TEST_MODE_ENABLED"); strings.EqualFold(v, "true") || v == "1" {
		cfg.Dev.TestModeEnabled = true
	}
	if v := os.Getenv("PROXY_DEV_ACCESS_KEY"); v != "" {
		cfg.Dev.AccessKey = v
	}
	if v := os.Getenv("PROXY_DEV_SECRET_KEY"); v != "" {
		cfg.Dev.SecretKey = v
	}
	if v := os.Getenv("PROXY_LOG_LEVEL"); v != "" {
		cfg.Log.Level = v
	}
	if v := os.Getenv("PROXY_LOG_DIAGNOSTICS"); strings.EqualFold(v, "true") || v == "1" {
		cfg.Log.Diagnostics = true
	}
	if v := os.Getenv("PROXY_LOG_REQUEST_BODY_SAMPLE_BYTES"); v != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			cfg.Log.RequestBodySampleBytes = n
		}
	}
	if v := os.Getenv("PROXY_LOG_UPSTREAM_BODY_SAMPLE_BYTES"); v != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			cfg.Log.UpstreamBodySampleBytes = n
		}
	}
}

func splitCSV(v string) []string {
	items := strings.Split(v, ",")
	out := make([]string, 0, len(items))
	for _, item := range items {
		trimmed := strings.TrimSpace(item)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func (c Config) Validate() error {
	if c.Mode != "prod" && c.Mode != "dev" {
		return errors.New("mode must be either 'prod' or 'dev'")
	}
	if c.Tenable.BaseURL == "" {
		return errors.New("tenable.base_url is required")
	}
	if c.Tenable.WorkbenchEndpoint == "" {
		return errors.New("tenable.workbench_endpoint is required")
	}
	if c.Tenable.PageLimit < 1 {
		return errors.New("tenable.page_limit must be >= 1")
	}
	if c.Tenable.MaxPages < 1 {
		return errors.New("tenable.max_pages must be >= 1")
	}
	if c.Tenable.RetryMaxAttempts < 1 {
		return errors.New("tenable.retry_max_attempts must be >= 1")
	}
	if c.Cache.TTL <= 0 {
		return errors.New("cache.ttl must be > 0")
	}
	if c.Cache.MaxEntries < 1 {
		return errors.New("cache.max_entries must be >= 1")
	}
	if c.TLS.Enabled && !c.TLS.AutoSelfSigned && (c.TLS.CertFile == "" || c.TLS.KeyFile == "") {
		return errors.New("tls.cert_file and tls.key_file are required when tls is enabled and auto_self_signed is false")
	}
	if c.Reliability.MaxStale <= 0 {
		return errors.New("reliability.max_stale must be > 0")
	}
	if len(c.Security.AllowedAccessKeys) == 0 {
		return errors.New("security.allowed_access_keys must contain at least one key")
	}
	if c.Mode == "prod" {
		if len(c.Security.AllowedSourceCIDRs) == 0 {
			return errors.New("security.allowed_source_cidrs must contain at least one CIDR in prod mode")
		}
		if c.Dev.TestModeEnabled {
			return errors.New("dev.test_mode_enabled must be false in prod mode")
		}
	}
	if c.Dev.TestModeEnabled && (c.Dev.AccessKey == "" || c.Dev.SecretKey == "") {
		return errors.New("dev.access_key and dev.secret_key are required when dev.test_mode_enabled is true")
	}
	if c.Log.RequestBodySampleBytes < 0 {
		return errors.New("log.request_body_sample_bytes must be >= 0")
	}
	if c.Log.UpstreamBodySampleBytes < 0 {
		return errors.New("log.upstream_body_sample_bytes must be >= 0")
	}
	return nil
}
