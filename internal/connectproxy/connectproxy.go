// Package connectproxy implements an HTTP CONNECT tunnel proxy. It enforces
// the same hostname allow/deny policy as the DNS proxy, evaluated against
// the CONNECT target itself, so a client that already knows a destination
// IP can't bypass policy by skipping DNS resolution. It does not terminate
// TLS — once a tunnel is permitted, bytes are relayed opaquely in both
// directions, so nothing inside the tunnel is inspected. Options narrows
// what "permitted" can mean regardless of hostname policy: which ports a
// target may use, a hard-override denylist, whether a target resolving to
// a loopback/link-local/private address is rejected, and how long an open
// tunnel may sit idle or stay open in total.
package connectproxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/michaellandi/agentgated/internal/filter"
	"github.com/michaellandi/agentgated/internal/tenant"
)

const (
	readHeaderTimeout = 10 * time.Second
	dialTimeout       = 10 * time.Second
)

// Options holds Proxy's optional hardening knobs, each independent of
// tenant/hostname policy. See internal/config for the corresponding
// connect_* settings and the reasoning behind each one.
type Options struct {
	AllowedPorts    []string
	DenyList        *filter.List
	BlockPrivateIPs bool
	IdleTimeout     time.Duration
	MaxDuration     time.Duration
}

// Proxy is an HTTP CONNECT tunnel proxy that filters targets and relays
// permitted connections.
type Proxy struct {
	resolver tenant.Resolver
	logger   *slog.Logger

	// allowedPorts restricts CONNECT target ports; empty means unrestricted.
	allowedPorts map[string]struct{}

	// denyList always blocks a matching host, regardless of tenant policy
	// or filter mode. See ConnectDenyListFile in internal/config.
	denyList *filter.List

	blockPrivateIPs bool
	idleTimeout     time.Duration
	maxDuration     time.Duration
}

// New builds a Proxy from its dependencies and Options.
func New(r tenant.Resolver, logger *slog.Logger, opts Options) *Proxy {
	ports := make(map[string]struct{}, len(opts.AllowedPorts))
	for _, p := range opts.AllowedPorts {
		ports[p] = struct{}{}
	}
	return &Proxy{
		resolver:        r,
		logger:          logger,
		allowedPorts:    ports,
		denyList:        opts.DenyList,
		blockPrivateIPs: opts.BlockPrivateIPs,
		idleTimeout:     opts.IdleTimeout,
		maxDuration:     opts.MaxDuration,
	}
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

	host, port, err := net.SplitHostPort(req.Host)
	if err != nil {
		respond(conn, http.StatusBadRequest, "malformed CONNECT target")
		p.log(client, req.Method, req.Host, "reject", "bad_target", start)
		return
	}

	if len(p.allowedPorts) > 0 {
		if _, ok := p.allowedPorts[port]; !ok {
			respond(conn, http.StatusForbidden, "port not permitted")
			p.log(client, req.Method, req.Host, "reject", "port_not_allowed", start)
			return
		}
	}

	f := p.resolver.Resolve(context.Background(), tenant.Request{IP: client, Header: req.Header})
	decision, reason := evaluate(f, host), "policy"
	if decision != filter.Block && p.denyList != nil && p.denyList.Contains(host) {
		decision, reason = filter.Block, "connect_denylist"
	}
	if decision == filter.Block {
		respond(conn, http.StatusForbidden, "host blocked by policy")
		p.log(client, req.Method, req.Host, "block", reason, start)
		return
	}

	addr := req.Host
	if p.blockPrivateIPs {
		resolved, ok := resolveSafeAddr(context.Background(), host, port)
		if !ok {
			respond(conn, http.StatusForbidden, "target address not permitted")
			p.log(client, req.Method, req.Host, "block", "private_ip", start)
			return
		}
		addr = resolved
	}

	upstream, err := net.DialTimeout("tcp", addr, dialTimeout)
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

	relay(conn, upstream, p.idleTimeout, p.maxDuration)
}

// resolveSafeAddr resolves host and rejects it if resolution fails or any
// candidate address is disallowed (see isDisallowedIP) — guarding against
// an allowed hostname (or one later rebound via DNS) reaching an
// internal-only service such as a cloud metadata endpoint. On success it
// returns the resolved IP joined with port rather than host again, so the
// address actually dialed is the one that was validated, not whatever a
// second, independent resolution might return. Resolution failure fails
// closed rather than falling through to the dialer's own (unvalidated)
// resolution: a resolver that answers the validating lookup and the
// dialer's lookup differently -- deliberately, for an attacker-controlled
// name, or just by transient failure -- must not be able to use that gap
// to reach an address that was never checked.
func resolveSafeAddr(ctx context.Context, host, port string) (addr string, ok bool) {
	if ip := net.ParseIP(host); ip != nil {
		if isDisallowedIP(ip) {
			return "", false
		}
		return net.JoinHostPort(host, port), true
	}

	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(addrs) == 0 {
		return "", false
	}
	for _, a := range addrs {
		if isDisallowedIP(a.IP) {
			return "", false
		}
	}
	return net.JoinHostPort(addrs[0].IP.String(), port), true
}

// extraDisallowedCIDRs covers ranges net.IP's own IsPrivate/IsLoopback/
// IsLinkLocalUnicast/IsUnspecified don't: those are RFC 1918 + RFC 4193
// only (the Go stdlib's own IsPrivate doc says as much: "does not describe
// a security property of addresses, and should not be used for access
// control"). Shared address space (100.64.0.0/10, RFC 6598) is the gap that
// matters most in practice -- it's what carrier-grade NAT and overlay
// networks like Tailscale use, so an internal-only gateway can live there
// on a network this guard is meant to protect. The other two are lower
// stakes but equally uncovered: benchmark-testing space (RFC 2544) and the
// still-reserved 240.0.0.0/4.
var extraDisallowedCIDRs = []*net.IPNet{
	mustCIDR("100.64.0.0/10"),
	mustCIDR("198.18.0.0/15"),
	mustCIDR("240.0.0.0/4"),
}

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

// ipv4TransitionPrefixes are IPv6 ranges that carry an embedded IPv4
// address net.IP's own checks don't look inside: an address in one of
// these can look like ordinary global-unicast IPv6 while actually routing
// to whatever IPv4 address (private, CGNAT, loopback...) is encoded in its
// low bits. All three prefixes are reserved exclusively for this purpose
// (IANA special-purpose registries), so matching one is never a false
// positive. Teredo's embedded client address is additionally obfuscated by
// XOR with 0xFFFFFFFF per RFC 4380.
var (
	sixToFourPrefix = mustCIDR("2002::/16")    // RFC 3056
	nat64Prefix     = mustCIDR("64:ff9b::/96") // RFC 6052 well-known prefix
	teredoPrefix    = mustCIDR("2001::/32")    // RFC 4380
)

// embeddedIPv4 extracts the IPv4 address encoded in a 6to4, NAT64, or
// Teredo IPv6 address, or nil if ip is none of those.
func embeddedIPv4(ip net.IP) net.IP {
	ip16 := ip.To16()
	if ip16 == nil || ip.To4() != nil {
		return nil
	}
	switch {
	case sixToFourPrefix.Contains(ip16):
		return net.IPv4(ip16[2], ip16[3], ip16[4], ip16[5])
	case nat64Prefix.Contains(ip16):
		return net.IPv4(ip16[12], ip16[13], ip16[14], ip16[15])
	case teredoPrefix.Contains(ip16):
		return net.IPv4(ip16[12]^0xFF, ip16[13]^0xFF, ip16[14]^0xFF, ip16[15]^0xFF)
	default:
		return nil
	}
}

func isDisallowedIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() ||
		ip.IsPrivate() || ip.IsUnspecified() {
		return true
	}
	for _, cidr := range extraDisallowedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	if embedded := embeddedIPv4(ip); embedded != nil {
		return isDisallowedIP(embedded)
	}
	return false
}

// relay copies bytes bidirectionally between a and b until both directions
// are closed, one direction sits idle longer than idleTimeout, or
// maxDuration elapses since the tunnel opened — whichever comes first.
// Either zero value disables that limit.
func relay(a, b net.Conn, idleTimeout, maxDuration time.Duration) {
	var deadline time.Time
	if maxDuration > 0 {
		deadline = time.Now().Add(maxDuration)
	}

	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		copyWithLimits(dst, src, idleTimeout, deadline)
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

// copyWithLimits is io.Copy with an optional idle read deadline, renewed
// before every read, and an optional absolute deadline that overrides it
// once closer. src must support SetReadDeadline (net.Conn always does).
func copyWithLimits(dst io.Writer, src net.Conn, idleTimeout time.Duration, maxDeadline time.Time) {
	buf := make([]byte, 32*1024)
	for {
		if idleTimeout > 0 || !maxDeadline.IsZero() {
			readDeadline := maxDeadline
			if idleTimeout > 0 {
				if idle := time.Now().Add(idleTimeout); readDeadline.IsZero() || idle.Before(readDeadline) {
					readDeadline = idle
				}
			}
			src.SetReadDeadline(readDeadline)
		}

		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
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

// evaluate applies f to a CONNECT target host, with one addition: a raw IP
// literal is never implicitly permitted just because it doesn't appear on
// a deny list. Unlike a hostname, there's no way to enumerate "bad IPs" in
// advance, so f's deny-list mode would otherwise silently allow a CONNECT
// straight to any IP an agent already knows — bypassing hostname policy
// entirely. An IP literal must be explicitly present on the allow list to
// pass, except in filter.None mode, which disables filtering entirely.
func evaluate(f filter.Filter, host string) filter.Decision {
	decision := f.Evaluate(host)
	if f.Mode == filter.None || decision == filter.Block {
		return decision
	}
	if net.ParseIP(host) == nil {
		return decision
	}
	if f.AllowList != nil && f.AllowList.Contains(host) {
		return filter.Allow
	}
	return filter.Block
}

func clientAddr(conn net.Conn) string {
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return conn.RemoteAddr().String()
	}
	return host
}
