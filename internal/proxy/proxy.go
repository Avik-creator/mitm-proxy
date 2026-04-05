package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/Avik-creator/mitm-proxy/internal/ca"

	"github.com/Avik-creator/mitm-proxy/internal/logger"
	"github.com/Avik-creator/mitm-proxy/internal/middleware"
)

// Config holds proxy configuration.
type Config struct {
	Addr       string
	CA         *ca.CA
	Middleware *middleware.Chain
	// InsecureUpstream skips TLS verification when connecting to upstream (useful for testing).
	InsecureUpstream bool
}

// Proxy is the MITM proxy server.
type Proxy struct {
	cfg    Config
	server *http.Server
}

// New creates a new Proxy.
func New(cfg Config) *Proxy {
	p := &Proxy{cfg: cfg}
	p.server = &http.Server{
		Addr:         cfg.Addr,
		Handler:      p,
		ReadTimeout:  0, // streaming-friendly
		WriteTimeout: 0,
	}
	return p
}

// Start begins listening. Blocks until the server stops.
func (p *Proxy) Start() error {
	logger.LogInfo("Proxy listening on http://%s (set as your browser/system proxy)", p.cfg.Addr)
	return p.server.ListenAndServe()
}

// Shutdown gracefully stops the proxy.
func (p *Proxy) Shutdown(ctx context.Context) error {
	return p.server.Shutdown(ctx)
}

// ServeHTTP routes all traffic.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleCONNECT(w, r)
		return
	}
	p.handleHTTP(w, r, false)
}

// ─────────────────────────────────────────
// CONNECT / TLS interception
// ─────────────────────────────────────────

// shouldInterceptHost checks if we should intercept TLS for this host.
// Some CDN/streaming hosts send non-standard protocols that break HTTP/1.x fallback.
func shouldInterceptHost(host string) bool {
	bypass := []string{
		"googlevideo.com",
		"googleusercontent.com",
		"rr",
	}
	for _, b := range bypass {
		if strings.Contains(host, b) {
			return false
		}
	}
	return true
}

func (p *Proxy) handleCONNECT(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
	}

	// Skip interception for problematic hosts (just tunnel TLS without MITM)
	if !shouldInterceptHost(host) {
		// For these hosts, establish standard TLS without our CA interception
		upstreamConn, err := tls.Dial("tcp", r.Host, &tls.Config{
			InsecureSkipVerify: p.cfg.InsecureUpstream,
		})
		if err != nil {
			logger.LogError("passthrough dial %s: %v", r.Host, err)
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer upstreamConn.Close()

		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijacking not supported", http.StatusInternalServerError)
			return
		}
		clientConn, _, err := hj.Hijack()
		if err != nil {
			logger.LogError("hijack: %v", err)
			return
		}
		defer clientConn.Close()

		_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		go io.Copy(upstreamConn, clientConn)
		io.Copy(clientConn, upstreamConn)
		return
	}

	// Hijack the raw connection.
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		logger.LogError("hijack: %v", err)
		return
	}
	defer clientConn.Close()

	// Acknowledge the CONNECT tunnel.
	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Wrap the client side in TLS using a dynamically-generated cert.
	tlsCfg, err := p.cfg.CA.TLSConfigForHost(host)
	if err != nil {
		logger.LogError("TLS config for %s: %v", host, err)
		return
	}
	tlsClient := tls.Server(clientConn, tlsCfg)
	if err := tlsClient.Handshake(); err != nil {
		// Client may not trust our CA — expected for non-configured clients.
		logger.LogError("TLS handshake with client (%s): %v", host, err)
		return
	}
	defer tlsClient.Close()

	// Peek to detect WebSocket or HTTP/2.
	br := bufio.NewReader(tlsClient)
	hdr, _ := br.Peek(3)

	// HTTP/2 preface starts with "PRI"
	if string(hdr) == "PRI" && shouldInterceptHost(host) {
		p.handleH2Tunnel(tlsClient, br, host)
		return
	}

	// Read HTTP request(s) from the now-decrypted stream.
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		req.URL.Scheme = "https"
		if req.URL.Host == "" {
			req.URL.Host = r.Host
		}

		isWS := isWebSocketUpgrade(req)

		if isWS {
			p.handleWebSocket(tlsClient, req)
			return
		}

		resp, modified, err := p.roundTrip(req)
		if err != nil {
			writeError(tlsClient, err)
			return
		}

		event := buildEvent("HTTPS", req, resp, modified)
		logger.Log(event)

		if err := resp.Write(tlsClient); err != nil {
			return
		}
		resp.Body.Close()

		if !isKeepAlive(req) {
			return
		}
	}
}

// ─────────────────────────────────────────
// Plain HTTP
// ─────────────────────────────────────────

func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request, intercepted bool) {
	if r.URL.Host == "" {
		r.URL.Host = r.Host
	}
	if r.URL.Scheme == "" {
		r.URL.Scheme = "http"
	}
	// Remove proxy-specific hop-by-hop headers.
	r.RequestURI = ""
	removeHopByHop(r.Header)

	resp, modified, err := p.roundTrip(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	event := buildEvent("HTTP", r, resp, modified)
	logger.Log(event)

	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// ─────────────────────────────────────────
// Round-trip with middleware
// ─────────────────────────────────────────

func (p *Proxy) roundTrip(req *http.Request) (*http.Response, bool, error) {
	// Snapshot original body for logging.
	var reqBody []byte
	var err error
	reqBody, req.Body, err = logger.DrainBody(req.Body)
	if err != nil {
		return nil, false, err
	}

	// Snapshot headers before modification for diff.
	origHeaderSig := headerSignature(req.Header)

	// Run request middleware.
	if err := p.cfg.Middleware.RunRequest(req); err != nil {
		if be, ok := err.(interface{ IsBlocked() bool }); ok && be.IsBlocked() {
			return blockedResponse(req), false, nil
		}
		return nil, false, err
	}
	reqModified := headerSignature(req.Header) != origHeaderSig || !bytes.Equal(reqBody, mustRead(req.Body))

	// Restore body for transport.
	req.Body = io.NopCloser(bytes.NewReader(reqBody))

	transport := p.transport()
	resp, err := transport.RoundTrip(req)
	if err != nil {
		return nil, false, fmt.Errorf("upstream: %w", err)
	}

	// Drain response body.
	var respBody []byte
	respBody, resp.Body, err = logger.DrainBody(resp.Body)
	if err != nil {
		return nil, false, err
	}
	origRespSig := fmt.Sprintf("%d-%s", resp.StatusCode, headerSignature(resp.Header))

	// Run response middleware.
	if err := p.cfg.Middleware.RunResponse(req, resp); err != nil {
		return nil, false, err
	}
	respModified := fmt.Sprintf("%d-%s", resp.StatusCode, headerSignature(resp.Header)) != origRespSig

	// Restore body.
	resp.Body = io.NopCloser(bytes.NewReader(respBody))

	return resp, reqModified || respModified, nil
}

func (p *Proxy) transport() *http.Transport {
	return &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: p.cfg.InsecureUpstream,
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          200,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

// ─────────────────────────────────────────
// HTTP/2 tunnel (using reverse proxy)
// ─────────────────────────────────────────

func (p *Proxy) handleH2Tunnel(conn net.Conn, br *bufio.Reader, host string) {
	// Build an HTTP/2-capable reverse proxy for this host.
	rp := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = "https"
			req.URL.Host = host
			removeHopByHop(req.Header)
			// Enable retries on stream reset by providing GetBody
			if req.Body != nil && req.Body != http.NoBody {
				body, _ := io.ReadAll(req.Body)
				req.Body = io.NopCloser(bytes.NewReader(body))
				req.GetBody = func() (io.ReadCloser, error) {
					return io.NopCloser(bytes.NewReader(body)), nil
				}
			}
		},
		Transport: p.transport(),
		ModifyResponse: func(resp *http.Response) error {
			return p.cfg.Middleware.RunResponse(resp.Request, resp)
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			logger.LogError("H2 reverse proxy: %v", err)
			w.WriteHeader(http.StatusBadGateway)
		},
	}

	// Wrap connection so net/http can serve it.
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Wrap ResponseWriter to capture status code
			rw := &statusRecorder{ResponseWriter: w, code: http.StatusOK}
			if err := p.cfg.Middleware.RunRequest(r); err != nil {
				http.Error(rw, err.Error(), http.StatusBadGateway)
				return
			}
			proto := "H2"
			if r.ProtoMajor == 1 {
				proto = "HTTPS"
			}
			start := time.Now()
			rp.ServeHTTP(rw, r)
			e := logger.NewEvent(proto, r.Method, "https://"+host+r.RequestURI, r.Header, nil)
			e.StatusCode = rw.code
			e.Duration = time.Since(start)
			logger.Log(e)
		}),
		TLSConfig: func() *tls.Config {
			cfg, _ := p.cfg.CA.TLSConfigForHost(host)
			return cfg
		}(),
	}

	// Serve over the already-TLS'd connection.
	_ = srv.Serve(&singleConnListener{
		conn:   &prefixedConn{Conn: conn, r: io.MultiReader(br, conn)},
		closed: make(chan struct{}),
	})
}

// ─────────────────────────────────────────
// WebSocket passthrough
// ─────────────────────────────────────────

func (p *Proxy) handleWebSocket(clientConn net.Conn, req *http.Request) {
	logger.LogInfo("WS  %s %s", req.Method, req.URL)

	upstreamConn, err := tls.Dial("tcp", req.URL.Host, &tls.Config{
		InsecureSkipVerify: p.cfg.InsecureUpstream,
	})
	if err != nil {
		logger.LogError("WS dial upstream: %v", err)
		return
	}
	defer upstreamConn.Close()

	// Forward the upgrade request upstream.
	if err := req.Write(upstreamConn); err != nil {
		logger.LogError("WS write upgrade: %v", err)
		return
	}

	// Bidirectional copy.
	done := make(chan struct{}, 2)
	go func() { io.Copy(upstreamConn, clientConn); done <- struct{}{} }()
	go func() { io.Copy(clientConn, upstreamConn); done <- struct{}{} }()
	<-done
}

// ─────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────

var hopByHop = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Transfer-Encoding",
	"Upgrade", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailers",
}

func removeHopByHop(h http.Header) {
	for _, k := range hopByHop {
		h.Del(k)
	}
}

func copyHeader(dst, src http.Header) {
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

func isKeepAlive(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Connection"), "keep-alive") || r.ProtoAtLeast(1, 1)
}

func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}

func headerSignature(h http.Header) string {
	var b strings.Builder
	for k, vs := range h {
		b.WriteString(k)
		b.WriteString(strings.Join(vs, ","))
	}
	return b.String()
}

func mustRead(rc io.ReadCloser) []byte {
	if rc == nil {
		return nil
	}
	b, _ := io.ReadAll(rc)
	rc.Close()
	return b
}

func buildEvent(proto string, req *http.Request, resp *http.Response, modified bool) *logger.RequestEvent {
	e := logger.NewEvent(proto, req.Method, req.URL.String(), req.Header, nil)
	if resp != nil {
		e.StatusCode = resp.StatusCode
		e.RespHdr = resp.Header.Clone()
	}
	e.ReqModified = modified
	return e
}

func blockedResponse(req *http.Request) *http.Response {
	return &http.Response{
		StatusCode: http.StatusForbidden,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1, ProtoMinor: 1,
		Header:  http.Header{"Content-Type": []string{"text/plain"}},
		Body:    io.NopCloser(strings.NewReader("Blocked by MITM proxy\n")),
		Request: req,
	}
}

func writeError(conn net.Conn, err error) {
	msg := fmt.Sprintf("HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\n\r\n%s\n", err)
	conn.Write([]byte(msg))
}

// singleConnListener wraps a single net.Conn as a net.Listener.
type singleConnListener struct {
	conn   net.Conn
	once   bool
	closed chan struct{}
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if l.once {
		<-l.closed
		return nil, fmt.Errorf("done")
	}
	l.once = true
	return l.conn, nil
}
func (l *singleConnListener) Close() error {
	if l.closed != nil {
		close(l.closed)
	}
	return nil
}
func (l *singleConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

// statusRecorder captures the HTTP response status code.
type statusRecorder struct {
	http.ResponseWriter
	code int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.code = code
	r.ResponseWriter.WriteHeader(code)
}

// prefixedConn replays buffered bytes before delegating to the real conn.
type prefixedConn struct {
	net.Conn
	r io.Reader
}

func (c *prefixedConn) Read(b []byte) (int, error) { return c.r.Read(b) }
