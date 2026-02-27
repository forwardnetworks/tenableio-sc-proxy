package httpserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/captainpacket/tenableio-sc-proxy/internal/auth"
	"github.com/captainpacket/tenableio-sc-proxy/internal/cache"
	"github.com/captainpacket/tenableio-sc-proxy/internal/config"
	"github.com/captainpacket/tenableio-sc-proxy/internal/forwardsc"
	"github.com/captainpacket/tenableio-sc-proxy/internal/health"
	"github.com/captainpacket/tenableio-sc-proxy/internal/tenableio"
	"github.com/captainpacket/tenableio-sc-proxy/internal/tlsutil"
	"github.com/captainpacket/tenableio-sc-proxy/internal/transform"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

type Server struct {
	cfg         config.Config
	logger      *slog.Logger
	tenable     tenableio.Client
	rowsCache   *cache.Cache[[]forwardsc.SumipHost]
	sourceCIDRs []*net.IPNet
	version     string
}

func New(cfg config.Config, logger *slog.Logger, client tenableio.Client, version string) *Server {
	parsedCIDRs := make([]*net.IPNet, 0, len(cfg.Security.AllowedSourceCIDRs))
	for _, cidr := range cfg.Security.AllowedSourceCIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			parsedCIDRs = append(parsedCIDRs, ipNet)
		}
	}
	return &Server{
		cfg:         cfg,
		logger:      logger,
		tenable:     client,
		rowsCache:   cache.New[[]forwardsc.SumipHost](cfg.Cache.TTL, cfg.Cache.MaxEntries),
		sourceCIDRs: parsedCIDRs,
		version:     version,
	}
}

func (s *Server) Handler() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(2 * time.Minute))

	r.Get("/healthz", health.Handler(s.version))
	r.Get("/readyz", health.ReadyHandler(s.version, s.Ready))
	r.Post("/rest/analysis", s.handleAnalysis)
	return r
}

func (s *Server) handleAnalysis(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	reqID := middleware.GetReqID(r.Context())
	remoteIP := clientIP(r.RemoteAddr)

	if !s.isSourceAllowed(r) {
		s.logger.Warn("request rejected: source ip not allowed", "request_id", reqID, "remote_ip", remoteIP, "path", r.URL.Path)
		s.writeSCError(w, http.StatusForbidden, 1000, "forbidden: source IP not allowed", 0, 0)
		return
	}
	creds, err := auth.ParseXAPIKey(r.Header.Get("x-apikey"))
	if err != nil {
		s.logger.Warn("request rejected: invalid x-apikey", "request_id", reqID, "remote_ip", remoteIP, "path", r.URL.Path)
		s.writeSCError(w, http.StatusUnauthorized, 1001, "unauthorized: invalid x-apikey", 0, 0)
		return
	}
	if !auth.IsAllowed(creds.AccessKey, s.cfg.Security.AllowedAccessKeys) {
		s.logger.Warn("request rejected: access key not allowlisted", "request_id", reqID, "remote_ip", remoteIP, "access_key_hash", accessKeyHash(creds.AccessKey))
		s.writeSCError(w, http.StatusUnauthorized, 1002, "unauthorized: access key is not allowed", 0, 0)
		return
	}

	rawBody, err := io.ReadAll(io.LimitReader(r.Body, 2*1024*1024))
	if err != nil {
		s.logger.Warn("request rejected: body read failed", "request_id", reqID, "error", err.Error())
		s.writeSCError(w, http.StatusBadRequest, 2001, "bad request: invalid json", 0, 0)
		return
	}
	var req forwardsc.AnalysisRequest
	if err := json.NewDecoder(bytes.NewReader(rawBody)).Decode(&req); err != nil {
		s.logger.Warn("request rejected: invalid json", "request_id", reqID, "remote_ip", remoteIP, "error", err.Error())
		s.writeSCError(w, http.StatusBadRequest, 2001, "bad request: invalid json", 0, 0)
		return
	}
	if err := req.Validate(); err != nil {
		s.logger.Warn("request rejected: invalid analysis query", "request_id", reqID, "remote_ip", remoteIP, "error", err.Error())
		s.writeSCError(w, http.StatusBadRequest, 2002, "bad request: "+err.Error(), req.Query.StartOffset, req.Query.EndOffset)
		return
	}

	daysAgo, err := req.DaysAgo()
	if err != nil {
		s.logger.Warn("request rejected: invalid lastSeen filter", "request_id", reqID, "remote_ip", remoteIP, "error", err.Error())
		s.writeSCError(w, http.StatusBadRequest, 2003, "bad request: "+err.Error(), req.Query.StartOffset, req.Query.EndOffset)
		return
	}
	if s.cfg.Log.Diagnostics {
		s.logger.Info(
			"analysis request",
			"request_id", reqID,
			"remote_ip", remoteIP,
			"access_key_hash", accessKeyHash(creds.AccessKey),
			"days_ago", daysAgo,
			"start_offset", req.Query.StartOffset,
			"end_offset", req.Query.EndOffset,
		)
		if s.cfg.Log.RequestBodySampleBytes > 0 {
			sample := string(rawBody)
			if len(sample) > s.cfg.Log.RequestBodySampleBytes {
				sample = sample[:s.cfg.Log.RequestBodySampleBytes]
			}
			s.logger.Debug("analysis request body sample", "request_id", reqID, "sample", sample)
		}
	}

	if daysAgo != 0 {
		w.Header().Set("X-Proxy-Cache", "NONE")
		s.writeJSON(w, http.StatusOK, forwardsc.EmptyEnvelope(req.Query.StartOffset, req.Query.EndOffset))
		if s.cfg.Log.Diagnostics {
			s.logger.Info("analysis response", "request_id", reqID, "cache", "NONE", "status", http.StatusOK, "duration_ms", time.Since(start).Milliseconds())
		}
		return
	}
	if s.cfg.Dev.TestModeEnabled && creds.AccessKey == s.cfg.Dev.AccessKey && creds.SecretKey == s.cfg.Dev.SecretKey {
		// Dev shortcut to validate Forward<->proxy connectivity without real Tenable.io credentials.
		rows := s.devRows()
		slice := paginate(rows, req.Query.StartOffset, req.Query.EndOffset)
		env := forwardsc.AnalysisEnvelope{
			Type:      "regular",
			ErrorCode: 0,
			ErrorMsg:  "",
			Response: forwardsc.AnalysisResponse{
				TotalRecords:    len(rows),
				ReturnedRecords: len(slice),
				StartOffset:     req.Query.StartOffset,
				EndOffset:       req.Query.EndOffset,
				Results:         slice,
			},
		}
		w.Header().Set("X-Proxy-Cache", "DEV")
		s.writeJSON(w, http.StatusOK, env)
		if s.cfg.Log.Diagnostics {
			s.logger.Info("analysis response", "request_id", reqID, "cache", "DEV", "status", http.StatusOK, "records", len(slice), "duration_ms", time.Since(start).Milliseconds())
		}
		return
	}

	rows, cacheStatus, staleAge, err := s.loadRows(r.Context(), creds)
	if err != nil {
		var unAuth *tenableio.UnauthorizedError
		if errors.As(err, &unAuth) {
			s.logger.Warn("upstream unauthorized", "request_id", reqID, "access_key_hash", accessKeyHash(creds.AccessKey))
			s.writeSCError(w, http.StatusUnauthorized, 3001, "upstream unauthorized", req.Query.StartOffset, req.Query.EndOffset)
			return
		}
		s.logger.Error("upstream fetch failed", "request_id", reqID, "access_key_hash", accessKeyHash(creds.AccessKey), "error", err.Error())
		s.writeSCError(w, http.StatusBadGateway, 3002, "upstream fetch failed", req.Query.StartOffset, req.Query.EndOffset)
		return
	}
	w.Header().Set("X-Proxy-Cache", cacheStatus)
	if cacheStatus == "STALE" {
		w.Header().Set("X-Proxy-Stale-Age-Seconds", fmt.Sprintf("%.0f", staleAge.Seconds()))
	}

	slice := paginate(rows, req.Query.StartOffset, req.Query.EndOffset)
	env := forwardsc.AnalysisEnvelope{
		Type:      "regular",
		ErrorCode: 0,
		ErrorMsg:  "",
		Response: forwardsc.AnalysisResponse{
			TotalRecords:    len(rows),
			ReturnedRecords: len(slice),
			StartOffset:     req.Query.StartOffset,
			EndOffset:       req.Query.EndOffset,
			Results:         slice,
		},
	}
	s.writeJSON(w, http.StatusOK, env)
	if s.cfg.Log.Diagnostics {
		s.logger.Info("analysis response", "request_id", reqID, "cache", cacheStatus, "status", http.StatusOK, "total_records", len(rows), "returned_records", len(slice), "duration_ms", time.Since(start).Milliseconds())
	}
}

func (s *Server) loadRows(ctx context.Context, creds auth.Credentials) ([]forwardsc.SumipHost, string, time.Duration, error) {
	cacheKey := accessKeyHash(creds.AccessKey + "|" + s.cfg.Tenable.WorkbenchEndpoint)
	if fresh, ok := s.rowsCache.GetFresh(cacheKey); ok {
		return fresh, "HIT", 0, nil
	}
	loaded, err := s.rowsCache.GetOrLoad(cacheKey, func() ([]forwardsc.SumipHost, error) {
		start := time.Now()
		hosts, err := s.tenable.FetchHostAggregates(ctx, creds)
		if err != nil {
			if s.cfg.Log.Diagnostics {
				s.logger.Warn("upstream fetch attempt failed", "request_id", middleware.GetReqID(ctx), "access_key_hash", cacheKey, "duration_ms", time.Since(start).Milliseconds(), "error", err.Error())
			}
			return nil, err
		}
		rows, tstats := transform.ToSumipRowsWithStats(hosts, transform.Options{
			DedupeByIP: s.cfg.Tenable.DedupeByIP,
		})
		if s.cfg.Log.Diagnostics {
			s.logger.Info(
				"upstream fetch success",
				"request_id", middleware.GetReqID(ctx),
				"access_key_hash", cacheKey,
				"hosts", len(hosts),
				"rows", len(rows),
				"duration_ms", time.Since(start).Milliseconds(),
				"dedupe_by_ip", s.cfg.Tenable.DedupeByIP,
				"dq_input_rows", tstats.InputRows,
				"dq_output_rows", tstats.OutputRows,
				"dq_drop_invalid_ip", tstats.DroppedInvalidIP,
				"dq_drop_negative_severity", tstats.DroppedNegativeSeverity,
				"dq_duplicates_merged", tstats.DuplicatesMerged,
			)
		}
		return rows, nil
	})
	if err == nil {
		return loaded, "MISS", 0, nil
	}
	if s.cfg.Reliability.ServeStaleOnUpstreamError {
		if staleItem, ok := s.rowsCache.GetAny(cacheKey); ok {
			age := time.Since(staleItem.CreatedAt)
			if age <= s.cfg.Reliability.MaxStale {
				s.logger.Warn("serving stale cache due to upstream error", "error", err.Error(), "stale_age_sec", age.Seconds())
				return staleItem.Value, "STALE", age, nil
			}
		}
	}
	return nil, "", 0, err
}

func accessKeyHash(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:8])
}

func paginate(rows []forwardsc.SumipHost, start, end int) []forwardsc.SumipHost {
	if start < 0 || end < 0 || end <= start || start >= len(rows) {
		return []forwardsc.SumipHost{}
	}
	if end > len(rows) {
		end = len(rows)
	}
	out := make([]forwardsc.SumipHost, end-start)
	copy(out, rows[start:end])
	return out
}

func (s *Server) writeSCError(w http.ResponseWriter, status, errorCode int, message string, startOffset, endOffset int) {
	env := forwardsc.AnalysisEnvelope{
		Type:      "regular",
		ErrorCode: errorCode,
		ErrorMsg:  message,
		Response: forwardsc.AnalysisResponse{
			TotalRecords:    0,
			ReturnedRecords: 0,
			StartOffset:     startOffset,
			EndOffset:       endOffset,
			Results:         []forwardsc.SumipHost{},
		},
	}
	s.writeJSON(w, status, env)
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		s.logger.Error("failed to write json", "error", err.Error())
	}
}

func (s *Server) devRows() []forwardsc.SumipHost {
	if len(s.cfg.Dev.FakeRows) == 0 {
		return []forwardsc.SumipHost{
			{
				IP:               "10.10.10.10",
				DNSName:          "dev-host-1.local",
				MACAddress:       "00:11:22:33:44:55",
				Score:            "180",
				SeverityMedium:   "3",
				SeverityHigh:     "2",
				SeverityCritical: "1",
			},
		}
	}
	out := make([]forwardsc.SumipHost, 0, len(s.cfg.Dev.FakeRows))
	for _, row := range s.cfg.Dev.FakeRows {
		out = append(out, forwardsc.SumipHost{
			IP:               row.IP,
			DNSName:          row.DNSName,
			MACAddress:       row.MACAddress,
			Score:            row.Score,
			SeverityMedium:   row.SeverityMedium,
			SeverityHigh:     row.SeverityHigh,
			SeverityCritical: row.SeverityCritical,
		})
	}
	return out
}

func (s *Server) Ready() (bool, string) {
	if len(s.cfg.Security.AllowedAccessKeys) == 0 {
		return false, "missing allowed access keys"
	}
	if s.cfg.Mode == "prod" && s.cfg.Dev.TestModeEnabled {
		return false, "dev test mode enabled in prod"
	}
	if s.cfg.Mode == "prod" && len(s.sourceCIDRs) == 0 {
		return false, "no allowed source cidrs in prod"
	}
	if s.cfg.TLS.Enabled && !s.cfg.TLS.AutoSelfSigned {
		if _, err := os.Stat(s.cfg.TLS.CertFile); err != nil {
			return false, "tls cert file not found"
		}
		if _, err := os.Stat(s.cfg.TLS.KeyFile); err != nil {
			return false, "tls key file not found"
		}
	}
	return true, "ok"
}

func (s *Server) isSourceAllowed(r *http.Request) bool {
	if len(s.sourceCIDRs) == 0 {
		return true
	}
	host := r.RemoteAddr
	if strings.Contains(host, ":") {
		h, _, err := net.SplitHostPort(r.RemoteAddr)
		if err == nil {
			host = h
		}
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil {
		return false
	}
	for _, cidr := range s.sourceCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func clientIP(remoteAddr string) string {
	host := remoteAddr
	if strings.Contains(host, ":") {
		h, _, err := net.SplitHostPort(remoteAddr)
		if err == nil {
			host = h
		}
	}
	return strings.TrimSpace(host)
}

func Addr(cfg config.Config) string {
	if cfg.Server.ListenAddr == "" {
		return ":8080"
	}
	return cfg.Server.ListenAddr
}

func Start(ctx context.Context, cfg config.Config, logger *slog.Logger, server *Server) error {
	httpServer := &http.Server{
		Addr:         Addr(cfg),
		Handler:      server.Handler(),
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	errCh := make(chan error, 1)
	go func() {
		if cfg.TLS.Enabled {
			certFile := cfg.TLS.CertFile
			keyFile := cfg.TLS.KeyFile
			if cfg.TLS.AutoSelfSigned {
				var err error
				certFile, keyFile, err = tlsutil.EnsureSelfSigned(cfg.TLS.CertDir)
				if err != nil {
					errCh <- fmt.Errorf("generate self-signed cert: %w", err)
					return
				}
			}
			if ageDays, err := tlsutil.CertAgeDays(certFile, time.Now().UTC()); err == nil && ageDays >= float64(cfg.TLS.RotateDays) {
				logger.Warn("tls certificate age exceeded rotation threshold", "cert", certFile, "age_days", ageDays, "rotate_days", cfg.TLS.RotateDays)
			}
			logger.Info("starting HTTPS server", "addr", httpServer.Addr, "cert", certFile)
			errCh <- httpServer.ListenAndServeTLS(certFile, keyFile)
			return
		}
		logger.Info("starting HTTP server", "addr", httpServer.Addr)
		errCh <- httpServer.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
		return nil
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("listen and serve: %w", err)
		}
		return nil
	}
}
