package logger

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

type Level int

const (
	LevelSilent Level = iota
	LevelInfo
	LevelVerbose
)

var globalLevel atomic.Int32

// SetLevel sets the global log level.
func SetLevel(l Level) { globalLevel.Store(int32(l)) }

func current() Level { return Level(globalLevel.Load()) }

type RequestEvent struct {
	ID        uint64
	Timestamp time.Time
	Proto     string // HTTP/1.1 | HTTP/2 | WS

	// Request
	Method  string
	URL     string
	ReqHdr  http.Header
	ReqBody []byte

	// Response
	StatusCode int
	RespHdr    http.Header
	RespBody   []byte
	Duration   time.Duration

	// Modification flags
	ReqModified  bool
	RespModified bool
}

var counter atomic.Uint64

func NewEvent(proto, method, url string, reqHdr http.Header, reqBody []byte) *RequestEvent {
	return &RequestEvent{
		ID:        counter.Add(1),
		Timestamp: time.Now(),
		Proto:     proto,
		Method:    method,
		URL:       url,
		ReqHdr:    reqHdr.Clone(),
		ReqBody:   reqBody,
	}
}

func Log(e *RequestEvent) {
	l := current()
	if l == LevelSilent {
		return
	}

	modReq := ""
	if e.ReqModified {
		modReq = " \033[33m[req modified]\033[0m"
	}
	modResp := ""
	if e.RespModified {
		modResp = " \033[33m[resp modified]\033[0m"
	}

	statusColor := statusCodeColor(e.StatusCode)

	fmt.Fprintf(os.Stdout,
		"\033[90m%s\033[0m #%-4d \033[36m%-7s\033[0m %s%s → %s%d\033[0m%s  \033[90m%s\033[0m\n",
		e.Timestamp.Format("15:04:05.000"),
		e.ID,
		e.Proto,
		e.Method+" ",
		e.URL,
		statusColor,
		e.StatusCode,
		modReq+modResp,
		e.Duration.Round(time.Millisecond),
	)

	if l == LevelVerbose {
		printHeaders("  ↑ ", e.ReqHdr)
		printBody("  ↑ body", e.ReqBody)
		printHeaders("  ↓ ", e.RespHdr)
		printBody("  ↓ body", e.RespBody)
		fmt.Println()
	}
}

// LogError prints an error line.
func LogError(format string, args ...any) {
	if current() == LevelSilent {
		return
	}
	fmt.Fprintf(os.Stderr, "\033[31m[ERR]\033[0m "+format+"\n", args...)
}

// LogInfo prints an info line.
func LogInfo(format string, args ...any) {
	if current() < LevelInfo {
		return
	}
	fmt.Fprintf(os.Stdout, "\033[32m[INF]\033[0m "+format+"\n", args...)
}

// DrainBody reads the full body and replaces rc with a fresh reader.
func DrainBody(rc io.ReadCloser) ([]byte, io.ReadCloser, error) {
	if rc == nil || rc == http.NoBody {
		return nil, http.NoBody, nil
	}
	data, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		return nil, http.NoBody, err
	}
	return data, io.NopCloser(bytes.NewReader(data)), nil
}

func printHeaders(prefix string, h http.Header) {
	for k, vs := range h {
		fmt.Printf("  %s\033[90m%s:\033[0m %s\n", prefix, k, strings.Join(vs, ", "))
	}
}

func printBody(label string, body []byte) {
	if len(body) == 0 {
		return
	}
	preview := body
	truncated := ""
	if len(preview) > 512 {
		preview = preview[:512]
		truncated = fmt.Sprintf("… [+%d bytes]", len(body)-512)
	}
	fmt.Printf("  %s (%d bytes): %s%s\n", label, len(body), preview, truncated)
}

func statusCodeColor(code int) string {
	switch {
	case code >= 500:
		return "\033[31m" // red
	case code >= 400:
		return "\033[33m" // yellow
	case code >= 300:
		return "\033[36m" // cyan
	case code >= 200:
		return "\033[32m" // green
	default:
		return "\033[0m"
	}
}
