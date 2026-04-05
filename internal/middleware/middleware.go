package middleware

import (
	"net/http"
)

// RequestHook is called before the request is forwarded upstream.
// Modify req in place; return an error to abort with 502.
type RequestHook func(req *http.Request) error

// ResponseHook is called after the upstream response is received.
// Modify resp in place; return an error to abort with 502.
type ResponseHook func(req *http.Request, resp *http.Response) error

// Chain holds an ordered list of request and response hooks.
type Chain struct {
	reqHooks  []RequestHook
	respHooks []ResponseHook
}

// New creates an empty middleware chain.
func New() *Chain { return &Chain{} }

// UseRequest appends a request hook.
func (c *Chain) UseRequest(h RequestHook) *Chain {
	c.reqHooks = append(c.reqHooks, h)
	return c
}

// UseResponse appends a response hook.
func (c *Chain) UseResponse(h ResponseHook) *Chain {
	c.respHooks = append(c.respHooks, h)
	return c
}

// RunRequest executes all request hooks in order.
func (c *Chain) RunRequest(req *http.Request) error {
	for _, h := range c.reqHooks {
		if err := h(req); err != nil {
			return err
		}
	}
	return nil
}

// RunResponse executes all response hooks in order.
func (c *Chain) RunResponse(req *http.Request, resp *http.Response) error {
	for _, h := range c.respHooks {
		if err := h(req, resp); err != nil {
			return err
		}
	}
	return nil
}

// ----------------------------------------
// Built-in hooks (add your own below)
// ----------------------------------------

// AddRequestHeader injects a header into every outgoing request.
func AddRequestHeader(key, value string) RequestHook {
	return func(req *http.Request) error {
		req.Header.Set(key, value)
		return nil
	}
}

// AddResponseHeader injects a header into every incoming response.
func AddResponseHeader(key, value string) ResponseHook {
	return func(_ *http.Request, resp *http.Response) error {
		resp.Header.Set(key, value)
		return nil
	}
}

// RemoveRequestHeader strips a header from every outgoing request.
func RemoveRequestHeader(key string) RequestHook {
	return func(req *http.Request) error {
		req.Header.Del(key)
		return nil
	}
}

// BlockHost returns a request hook that rejects requests to a given host with 403.
func BlockHost(host string) RequestHook {
	return func(req *http.Request) error {
		if req.URL.Hostname() == host || req.Host == host {
			return &BlockedError{Host: host}
		}
		return nil
	}
}

// BlockedError is returned when a host is blocked.
type BlockedError struct{ Host string }

func (e *BlockedError) Error() string   { return "blocked host: " + e.Host }
func (e *BlockedError) IsBlocked() bool { return true }
