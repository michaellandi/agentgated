package connectproxy

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/textproto"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/michaellandi/agentgated/internal/filter"
	"github.com/michaellandi/agentgated/internal/tenant"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// startProxy starts a Proxy with every Options knob left at its zero value
// (unrestricted ports, no denylist, private IPs allowed, no idle/max
// tunnel limits) -- the tests using it are exercising something other than
// those knobs, and most dial loopback fixtures that BlockPrivateIPs would
// otherwise reject.
func startProxy(t *testing.T, f filter.Filter) string {
	t.Helper()
	return startProxyWith(t, f, Options{})
}

func startProxyWith(t *testing.T, f filter.Filter, opts Options) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	p := New(tenant.StaticResolver{Filter: f}, testLogger(), opts)
	go p.Serve(ln)
	return ln.Addr().String()
}

func echoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr().String()
}

// connectRequest sends a raw CONNECT request to the proxy and parses the
// status line and headers, returning the still-open connection (and its
// buffered reader, since any tunnel bytes must be read through it too) for
// the caller to use as a tunnel.
func connectRequest(t *testing.T, proxyAddr, target string) (net.Conn, *bufio.Reader, int) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		t.Fatalf("write request: %v", err)
	}

	br := bufio.NewReader(conn)
	tp := textproto.NewReader(br)
	statusLine, err := tp.ReadLine()
	if err != nil {
		t.Fatalf("read status line: %v", err)
	}
	if _, err := tp.ReadMIMEHeader(); err != nil {
		t.Fatalf("read headers: %v", err)
	}

	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) < 2 {
		t.Fatalf("malformed status line: %q", statusLine)
	}
	status, err := strconv.Atoi(parts[1])
	if err != nil {
		t.Fatalf("parse status code %q: %v", parts[1], err)
	}
	return conn, br, status
}

func TestConnectAllowedTunnelsTraffic(t *testing.T) {
	upstream := echoServer(t)
	proxyAddr := startProxy(t, filter.Filter{Mode: filter.None})

	conn, br, status := connectRequest(t, proxyAddr, upstream)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(br, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echo = %q, want %q", buf, "ping")
	}
}

func TestConnectBlockedByPolicy(t *testing.T) {
	dir := t.TempDir()
	denylistPath := filepath.Join(dir, "denylist.txt")
	if err := os.WriteFile(denylistPath, []byte("blocked.example.com\n"), 0o644); err != nil {
		t.Fatalf("write deny list: %v", err)
	}
	denyList, err := filter.LoadList(denylistPath)
	if err != nil {
		t.Fatalf("load deny list: %v", err)
	}

	proxyAddr := startProxy(t, filter.Filter{Mode: filter.DenyList, DenyList: denyList})

	_, _, status := connectRequest(t, proxyAddr, "blocked.example.com:443")
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", status)
	}
}

func TestEvaluateBlocksRawIPLiteralNotOnAllowList(t *testing.T) {
	// filter_mode: deny with an empty deny list would otherwise silently
	// allow any raw IP, since an IP essentially never matches a deny list
	// of hostnames. A CONNECT target that's already an IP has skipped DNS
	// entirely, so this must not be implicitly allowed.
	f := filter.Filter{Mode: filter.DenyList}
	if got := evaluate(f, "93.184.216.34"); got != filter.Block {
		t.Errorf("evaluate() = %v, want Block for an unlisted raw IP under deny mode", got)
	}
}

func TestEvaluateAllowsRawIPLiteralExplicitlyOnAllowList(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allowlist.txt")
	if err := os.WriteFile(path, []byte("93.184.216.34\n"), 0o644); err != nil {
		t.Fatalf("write allow list: %v", err)
	}
	allowList, err := filter.LoadList(path)
	if err != nil {
		t.Fatalf("load allow list: %v", err)
	}

	f := filter.Filter{Mode: filter.DenyList, AllowList: allowList}
	if got := evaluate(f, "93.184.216.34"); got != filter.Allow {
		t.Errorf("evaluate() = %v, want Allow for a raw IP explicitly on the allow list", got)
	}
}

func TestEvaluateNoneModeIgnoresRawIPRule(t *testing.T) {
	// filter.None means filtering is off entirely; the raw-IP restriction
	// must not silently reintroduce filtering when an operator explicitly
	// disabled it.
	f := filter.Filter{Mode: filter.None}
	if got := evaluate(f, "93.184.216.34"); got != filter.Allow {
		t.Errorf("evaluate() = %v, want Allow for a raw IP under none mode", got)
	}
}

func TestEvaluateHostnamesUnaffectedByRawIPRule(t *testing.T) {
	f := filter.Filter{Mode: filter.DenyList}
	if got := evaluate(f, "example.com"); got != filter.Allow {
		t.Errorf("evaluate() = %v, want Allow for an unlisted hostname under deny mode", got)
	}
}

func TestConnectBlocksRawIPLiteralByDefault(t *testing.T) {
	// upstream is already "127.0.0.1:<port>" — a raw IP literal target.
	upstream := echoServer(t)

	// deny mode, nothing on the deny list: a hostname target would be
	// allowed, but a raw IP target must not be.
	proxyAddr := startProxy(t, filter.Filter{Mode: filter.DenyList})

	_, _, status := connectRequest(t, proxyAddr, upstream)
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for an unlisted raw IP CONNECT target", status)
	}
}

func TestConnectAllowsRawIPLiteralOnAllowList(t *testing.T) {
	upstream := echoServer(t)
	upstreamIP, _, err := net.SplitHostPort(upstream)
	if err != nil {
		t.Fatalf("split upstream addr: %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "allowlist.txt")
	if err := os.WriteFile(path, []byte(upstreamIP+"\n"), 0o644); err != nil {
		t.Fatalf("write allow list: %v", err)
	}
	allowList, err := filter.LoadList(path)
	if err != nil {
		t.Fatalf("load allow list: %v", err)
	}

	proxyAddr := startProxy(t, filter.Filter{Mode: filter.DenyList, AllowList: allowList})

	_, _, status := connectRequest(t, proxyAddr, upstream)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 for a raw IP explicitly on the allow list", status)
	}
}

func TestConnectRejectsDisallowedPort(t *testing.T) {
	upstream := echoServer(t) // random high port, not 443
	proxyAddr := startProxyWith(t, filter.Filter{Mode: filter.None}, Options{AllowedPorts: []string{"443"}})

	_, _, status := connectRequest(t, proxyAddr, upstream)
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a CONNECT target port outside connect_allowed_ports", status)
	}
}

func TestConnectAllowsConfiguredPort(t *testing.T) {
	upstream := echoServer(t)
	_, upstreamPort, err := net.SplitHostPort(upstream)
	if err != nil {
		t.Fatalf("split upstream addr: %v", err)
	}
	proxyAddr := startProxyWith(t, filter.Filter{Mode: filter.None}, Options{AllowedPorts: []string{upstreamPort}})

	_, _, status := connectRequest(t, proxyAddr, upstream)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 for a CONNECT target port in connect_allowed_ports", status)
	}
}

func TestConnectDenyListOverridesAllowedPolicy(t *testing.T) {
	// A host explicitly allowed by tenant policy must still be blocked by
	// the built-in denylist — it exists specifically to hold hosts (e.g.
	// known DoH/DoT resolvers) that must never be reachable via CONNECT
	// regardless of what any allow list says.
	upstream := echoServer(t)
	upstreamHost, _, err := net.SplitHostPort(upstream)
	if err != nil {
		t.Fatalf("split upstream addr: %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "connect-denylist.txt")
	if err := os.WriteFile(path, []byte(upstreamHost+"\n"), 0o644); err != nil {
		t.Fatalf("write connect denylist: %v", err)
	}
	denyList, err := filter.LoadList(path)
	if err != nil {
		t.Fatalf("load connect denylist: %v", err)
	}

	proxyAddr := startProxyWith(t, filter.Filter{Mode: filter.None}, Options{DenyList: denyList})

	_, _, status := connectRequest(t, proxyAddr, upstream)
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a host on the built-in denylist despite filter.None", status)
	}
}

func TestConnectBlocksPrivateIPWhenGuardEnabled(t *testing.T) {
	// TestConnectAllowsRawIPLiteralOnAllowList shows a loopback target
	// explicitly on the allow list is normally permitted. With the
	// private-IP guard enabled, it must be blocked anyway -- the guard
	// overrides tenant policy the same way the built-in denylist does.
	upstream := echoServer(t)
	upstreamIP, _, err := net.SplitHostPort(upstream)
	if err != nil {
		t.Fatalf("split upstream addr: %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "allowlist.txt")
	if err := os.WriteFile(path, []byte(upstreamIP+"\n"), 0o644); err != nil {
		t.Fatalf("write allow list: %v", err)
	}
	allowList, err := filter.LoadList(path)
	if err != nil {
		t.Fatalf("load allow list: %v", err)
	}

	proxyAddr := startProxyWith(t,
		filter.Filter{Mode: filter.DenyList, AllowList: allowList},
		Options{BlockPrivateIPs: true},
	)

	_, _, status := connectRequest(t, proxyAddr, upstream)
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a loopback target with connect_block_private_ips enabled", status)
	}
}

func TestConnectIdleTimeoutClosesTunnel(t *testing.T) {
	upstream := echoServer(t)
	proxyAddr := startProxyWith(t, filter.Filter{Mode: filter.None}, Options{IdleTimeout: 50 * time.Millisecond})

	conn, br, status := connectRequest(t, proxyAddr, upstream)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}

	// Nothing is sent in either direction; the tunnel must be closed by
	// idle_timeout well before our own read deadline below fires.
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := br.Read(make([]byte, 1)); err == nil {
		t.Fatalf("read succeeded, want the idle tunnel closed by idle_timeout")
	} else if isDeadlineExceeded(err) {
		t.Fatalf("read hit our own 3s deadline: idle_timeout did not close the tunnel: %v", err)
	}
}

func TestConnectMaxDurationClosesTunnel(t *testing.T) {
	upstream := echoServer(t)
	proxyAddr := startProxyWith(t, filter.Filter{Mode: filter.None}, Options{MaxDuration: 100 * time.Millisecond})

	conn, br, status := connectRequest(t, proxyAddr, upstream)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}

	// Confirm the tunnel works before the ceiling hits.
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	pingBuf := make([]byte, 4)
	if _, err := io.ReadFull(br, pingBuf); err != nil {
		t.Fatalf("read echo: %v", err)
	}

	// No idle_timeout is set, so only max_duration can close this -- and it
	// must, even though the tunnel was just actively used.
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := br.Read(make([]byte, 1)); err == nil {
		t.Fatalf("read succeeded, want the tunnel closed by max_duration despite being active")
	} else if isDeadlineExceeded(err) {
		t.Fatalf("read hit our own 3s deadline: max_duration did not close the tunnel: %v", err)
	}
}

// isDeadlineExceeded reports whether err is our own test-side read deadline
// firing, as opposed to the proxy closing the connection -- the two are
// otherwise both just "a read error" and must not be confused.
func isDeadlineExceeded(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func TestConnectRejectsNonConnectMethod(t *testing.T) {
	proxyAddr := startProxy(t, filter.Filter{Mode: filter.None})

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}

	tp := textproto.NewReader(bufio.NewReader(conn))
	statusLine, err := tp.ReadLine()
	if err != nil {
		t.Fatalf("read status line: %v", err)
	}
	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) < 2 {
		t.Fatalf("malformed status line: %q", statusLine)
	}
	status, err := strconv.Atoi(parts[1])
	if err != nil {
		t.Fatalf("parse status code %q: %v", parts[1], err)
	}
	if status != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", status)
	}
}
