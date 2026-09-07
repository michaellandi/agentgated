package connectproxy

import (
	"bufio"
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
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func startProxy(t *testing.T, f filter.Filter) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	p := New(f, testLogger())
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
	blacklistPath := filepath.Join(dir, "blacklist.txt")
	if err := os.WriteFile(blacklistPath, []byte("blocked.example.com\n"), 0o644); err != nil {
		t.Fatalf("write blacklist: %v", err)
	}
	blacklist, err := filter.LoadList(blacklistPath)
	if err != nil {
		t.Fatalf("load blacklist: %v", err)
	}

	proxyAddr := startProxy(t, filter.Filter{Mode: filter.Blacklist, Blacklist: blacklist})

	_, _, status := connectRequest(t, proxyAddr, "blocked.example.com:443")
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", status)
	}
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
