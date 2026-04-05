# MITM Proxy

A Man-in-the-Middle proxy written in Go from scratch.  
Intercepts, logs, and modifies **HTTP**, **HTTPS** (TLS interception), **WebSocket**, and **HTTP/2** traffic.

---

## Features

| Feature | Details |
|---|---|
| **TLS interception** | Dynamically generates per-host leaf certificates signed by a local CA |
| **HTTP/2** | Detected via connection preface (`PRI …`), handled via a reverse proxy |
| **WebSocket** | Detected via `Upgrade: websocket`, bidirectional passthrough with logging |
| **Middleware chain** | Composable request/response hooks — add headers, block hosts, rewrite bodies |
| **Structured logging** | Color-coded per-request log with optional verbose header/body dump |
| **CLI flags** | Listen address, cert paths, verbosity, insecure upstream |

---

## Quick Start

```bash
# 1. Build
go build -o mitm-proxy ./cmd/proxy

# 2. Run (generates certs/ca.crt + certs/ca.key on first run)
./mitm-proxy -v 2

# 3. Trust the CA
#    macOS:   open certs/ca.crt → Keychain → "Always Trust"
#    Linux:   sudo cp certs/ca.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates
#    Firefox: about:preferences#privacy → View Certificates → Import

# 4. Point your browser/system proxy to:  127.0.0.1:8080
```

---

## CLI Flags

```
-addr    string   Proxy listen address        (default "127.0.0.1:8080")
-cert    string   Path to CA certificate      (default "certs/ca.crt")
-key     string   Path to CA private key      (default "certs/ca.key")
-v       int      Verbosity 0=silent 1=info 2=verbose  (default 1)
-insecure         Skip TLS verification for upstream connections
```

---

## Project Layout

```
mitm-proxy/
├── cmd/proxy/
│   └── main.go              ← entrypoint, CLI flags, middleware wiring
├── internal/
│   ├── ca/
│   │   └── ca.go            ← root CA generation + per-host cert cache
│   ├── proxy/
│   │   └── proxy.go         ← HTTP/HTTPS/WS/H2 interception engine
│   ├── middleware/
│   │   └── middleware.go    ← hook system + built-in hooks
│   └── logger/
│       └── logger.go        ← color-coded structured request logging
└── certs/                   ← auto-created; holds ca.crt + ca.key
```

---

## Adding Middleware

Edit `cmd/proxy/main.go`:

```go
chain := middleware.New().
    // Add a request hook
    UseRequest(func(req *http.Request) error {
        req.Header.Set("X-Custom", "hello")
        return nil
    }).
    // Add a response hook — rewrite body
    UseResponse(func(req *http.Request, resp *http.Response) error {
        body, _ := io.ReadAll(resp.Body)
        body = bytes.ReplaceAll(body, []byte("foo"), []byte("bar"))
        resp.Body = io.NopCloser(bytes.NewReader(body))
        resp.ContentLength = int64(len(body))
        return nil
    })
```

### Built-in hooks (`middleware` package)

| Hook | Description |
|---|---|
| `AddRequestHeader(k, v)` | Inject header into every request |
| `AddResponseHeader(k, v)` | Inject header into every response |
| `RemoveRequestHeader(k)` | Strip header from every request |
| `BlockHost(host)` | Return 403 for a specific host |

---

## How TLS Interception Works

```
Browser ──CONNECT example.com:443──► Proxy
           ◄── 200 Connection Established ──

Browser ──TLS (proxy's leaf cert for example.com)──► Proxy
           ◄── TLS ──
                                  Proxy ──TLS (real cert)──► example.com

Browser sees a cert for example.com signed by "MITM Proxy CA".
As long as the CA is trusted, no browser warning appears.
```

Leaf certificates are cached in memory and re-used for subsequent connections to the same host.

---

## Verbosity Levels

| `-v` | Output |
|---|---|
| `0` | Silent |
| `1` | One line per request: timestamp · ID · proto · method · URL → status · duration |
| `2` | + request/response headers and body preview (first 512 bytes) |

---

## Extending

- **Body rewriting**: drain `req.Body` / `resp.Body` in a hook, modify bytes, replace with `io.NopCloser`
- **Filtering by URL**: inspect `req.URL.Path` or `req.URL.Host` inside a hook
- **Saving to disk**: write events to a file inside a `UseResponse` hook
- **gRPC**: works over HTTP/2; extend the H2 tunnel handler to parse protobuf frames
