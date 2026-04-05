package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Avik-creator/mitm-proxy/internal/ca"
	"github.com/Avik-creator/mitm-proxy/internal/logger"
	"github.com/Avik-creator/mitm-proxy/internal/middleware"
	"github.com/Avik-creator/mitm-proxy/internal/proxy"
)

func main() {
	// ── CLI flags ──────────────────────────────────────────────────
	addr := flag.String("addr", "127.0.0.1:8080", "Proxy listen address")
	certFile := flag.String("cert", "certs/ca.crt", "Path to CA certificate (created if missing)")
	keyFile := flag.String("key", "certs/ca.key", "Path to CA private key (created if missing)")
	verbosity := flag.Int("v", 1, "Verbosity: 0=silent, 1=info, 2=verbose")
	insecure := flag.Bool("insecure", false, "Skip TLS verification for upstream connections")
	flag.Usage = usage
	flag.Parse()

	// ── Logger ─────────────────────────────────────────────────────
	logger.SetLevel(logger.Level(*verbosity))

	// ── CA ─────────────────────────────────────────────────────────
	if err := os.MkdirAll("certs", 0700); err != nil {
		fatal("create certs dir: %v", err)
	}
	rootCA, err := ca.New(*certFile, *keyFile)
	if err != nil {
		fatal("init CA: %v", err)
	}

	// ── Middleware chain ────────────────────────────────────────────
	// Add your hooks here. These are examples — customize freely.
	chain := middleware.New().
		// Stamp every forwarded request so the server knows it passed through us.
		UseRequest(middleware.AddRequestHeader("X-MITM-Proxy", "1")).
		// Expose the proxy version in every response.
		UseResponse(middleware.AddResponseHeader("X-Intercepted-By", "mitm-proxy/1.0")).
		// Example: block ads (commented out — uncomment to enable)
		// UseRequest(middleware.BlockHost("doubleclick.net")).
		// Example: drop tracking headers
		UseRequest(middleware.RemoveRequestHeader("X-Forwarded-For"))

	// ── Proxy ──────────────────────────────────────────────────────
	p := proxy.New(proxy.Config{
		Addr:             *addr,
		CA:               rootCA,
		Middleware:       chain,
		InsecureUpstream: *insecure,
	})

	// ── Graceful shutdown ──────────────────────────────────────────
	go func() {
		if err := p.Start(); err != nil && err != http.ErrServerClosed {
			fatal("proxy: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.LogInfo("Shutting down…")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = p.Shutdown(ctx)
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "FATAL: "+format+"\n", args...)
	os.Exit(1)
}

func usage() {
	fmt.Fprintf(os.Stderr, `MITM Proxy — intercept, inspect, and modify HTTP/HTTPS/WS/H2 traffic

Usage:
  proxy [flags]

Flags:
`)
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, `
Quick start:
  1. Run:    go run ./cmd/proxy -v 2
  2. Trust:  certs/ca.crt  (add to OS / browser trust store)
  3. Set:    HTTP proxy → 127.0.0.1:8080  (in browser or system settings)
  4. Browse — all traffic is intercepted and logged.

`)
}
