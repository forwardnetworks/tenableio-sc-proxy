package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/captainpacket/tenableio-sc-proxy/internal/config"
	"github.com/captainpacket/tenableio-sc-proxy/internal/httpserver"
	"github.com/captainpacket/tenableio-sc-proxy/internal/tenableio"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "run":
		run(os.Args[2:])
	case "configtest":
		configTest(os.Args[2:])
	case "version":
		fmt.Println(version)
	default:
		usage()
		os.Exit(2)
	}
}

func run(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	configPath := fs.String("config", "./config.example.yaml", "path to config yaml")
	_ = fs.Parse(args)

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config load failed: %v\n", err)
		os.Exit(1)
	}

	logger := newLogger(cfg.Log.Level)
	client := tenableio.NewWorkbenchClient(
		logger,
		cfg.Tenable.BaseURL,
		cfg.Tenable.WorkbenchEndpoint,
		cfg.Tenable.Timeout,
		cfg.Tenable.InsecureSkipVerify,
		cfg.Tenable.RetryMaxAttempts,
		cfg.Tenable.RetryBackoffMin,
		cfg.Tenable.RetryBackoffMax,
		cfg.Log.Diagnostics,
		cfg.Log.UpstreamBodySampleBytes,
	)
	server := httpserver.New(cfg, logger, client, version)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := httpserver.Start(ctx, cfg, logger, server); err != nil {
		logger.Error("server exited with error", "error", err.Error())
		os.Exit(1)
	}
}

func configTest(args []string) {
	fs := flag.NewFlagSet("configtest", flag.ExitOnError)
	configPath := fs.String("config", "./config.example.yaml", "path to config yaml")
	_ = fs.Parse(args)

	if _, err := config.Load(*configPath); err != nil {
		fmt.Fprintf(os.Stderr, "invalid config: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("config ok")
}

func usage() {
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  proxy run --config <path>")
	fmt.Fprintln(os.Stderr, "  proxy configtest --config <path>")
	fmt.Fprintln(os.Stderr, "  proxy version")
}

func newLogger(level string) *slog.Logger {
	var lv slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lv = slog.LevelDebug
	case "warn":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		lv = slog.LevelInfo
	}
	h := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lv})
	return slog.New(h)
}
