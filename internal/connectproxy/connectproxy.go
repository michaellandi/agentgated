// Package connectproxy implements an HTTP CONNECT tunnel proxy. It enforces
// the same hostname allow/deny policy as the DNS proxy, evaluated against
// the CONNECT target itself, so a client that already knows a destination
// IP can't bypass policy by skipping DNS resolution. It does not terminate
// TLS — once a tunnel is permitted, bytes are relayed opaquely in both
// directions.
package connectproxy

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/michaellandi/agentgated/internal/filter"
)

const (
	readHeaderTimeout = 10 * time.Second
	dialTimeout       = 10 * time.Second
)

// Proxy is an HTTP CONNECT tunnel proxy that filters targets and relays
// permitted connections.
type Proxy struct {
	filter filter.Filter
	logger *slog.Logger
}

// New builds a Proxy from its dependencies.
func New(f filter.Filter, logger *slog.Logger) *Proxy {
	return &Proxy{filter: f, logger: logger}
}

// ListenAndServe listens for TCP connections on addr and serves them until
// Accept fails.
func (p *Proxy) ListenAndServe(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", addr, err)
	}
	defer ln.Close()
	return p.Serve(ln)
}

// Serve accepts and handles connections from ln until Accept fails.
func (p *Proxy) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go p.handle(conn)
	}
}

func (p *Proxy) handle(conn net.Conn) {
	defer conn.Close()
	start := time.Now()
	client := clientAddr(conn)

	conn.SetReadDeadline(time.Now().Add(readHeaderTimeout))
	req, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		return
	}
	conn.SetReadDeadline(time.Time{})

	if req.Method != http.MethodConnect {
		respond(conn, http.StatusMethodNotAllowed, "only CONNECT is supported")
		p.log(client, req.Method, req.Host, "reject", "method_not_allowed", start)
		return
	}

	host, _, err := net.SplitHostPort(req.Host)
	if err != nil {
		respond(conn, http.StatusBadRequest, "malformed CONNECT target")
		p.log(client, req.Method, req.Host, "reject", "bad_target", start)
		return
	}

	if p.filter.Evaluate(host) == filter.Block {
		respond(conn, http.StatusForbidden, "host blocked by policy")
		p.log(client, req.Method, req.Host, "block", "policy", start)
		return
	}

	upstream, err := net.DialTimeout("tcp", req.Host, dialTimeout)
	if err != nil {
		respond(conn, http.StatusBadGateway, "upstream connect failed")
		p.log(client, req.Method, req.Host, "allow", "dial_failed", start)
		return
	}
	defer upstream.Close()

	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	p.log(client, req.Method, req.Host, "allow", "tunnel", start)

	relay(conn, upstream)
}

// relay copies bytes bidirectionally between a and b until both directions
// are closed.
func relay(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		io.Copy(dst, src)
		if c, ok := dst.(interface{ CloseWrite() error }); ok {
			c.CloseWrite()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
}

func respond(conn net.Conn, code int, msg string) {
	fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		code, http.StatusText(code), len(msg), msg)
}

func (p *Proxy) log(client, method, target, decision, reason string, start time.Time) {
	p.logger.Info("connect",
		"client", client,
		"method", method,
		"target", target,
		"decision", decision,
		"reason", reason,
		"duration_ms", time.Since(start).Milliseconds(),
	)
}

func clientAddr(conn net.Conn) string {
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return conn.RemoteAddr().String()
	}
	return host
}
