// Package ipc defines the versioned Go<->Rust protocol. v1 uses JSON over a
// loopback TCP socket (Unix socket on Linux in production) with typed
// request/response envelopes, timeouts, and health checks. proto/exec.proto
// is the IDL source of truth; this file is its Go binding.
package ipc

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// ProtocolVersion negotiated on every call.
const ProtocolVersion = 1

// Request is the typed envelope sent to the Rust worker.
type Request struct {
	Version string         `json:"version"`
	ID      string         `json:"id"`
	Op      string         `json:"op"`
	Payload map[string]any `json:"payload"`
}

// Response is the typed envelope returned by the Rust worker.
type Response struct {
	Version string         `json:"version"`
	ID      string         `json:"id"`
	OK      bool           `json:"ok"`
	Result  map[string]any `json:"result,omitempty"`
	Error   *ErrorBody     `json:"error,omitempty"`
}

// ErrorBody is a structured, non-stringly error.
type ErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Client dials the Rust sidecar.
type Client struct {
	Addr    string
	Timeout time.Duration
}

// Call performs one request/response round-trip with timeout.
func (c *Client) Call(op string, payload map[string]any) (Response, error) {
	timeout := c.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	conn, err := net.DialTimeout("tcp", c.Addr, 5*time.Second)
	if err != nil {
		return Response{}, fmt.Errorf("ipc dial %s: %w", c.Addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	req := Request{Version: "v1", ID: fmt.Sprintf("%d", time.Now().UnixNano()), Op: op, Payload: payload}
	raw, _ := json.Marshal(req)
	if _, err := conn.Write(append(raw, '\n')); err != nil {
		return Response{}, err
	}
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		return Response{}, fmt.Errorf("ipc read: %w", err)
	}
	var resp Response
	if err := json.Unmarshal(line, &resp); err != nil {
		return Response{}, fmt.Errorf("ipc decode: %w", err)
	}
	if resp.Version != "v1" {
		return resp, fmt.Errorf("ipc version mismatch: %q", resp.Version)
	}
	return resp, nil
}

// Health pings the sidecar.
func (c *Client) Health() error {
	resp, err := c.Call("health", map[string]any{})
	if err != nil {
		return err
	}
	if !resp.OK {
		return fmt.Errorf("sidecar unhealthy: %+v", resp.Error)
	}
	return nil
}
