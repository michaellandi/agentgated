// Package proxy implements the DNS request handler: filter, cache, and
// upstream forwarding.
package proxy

import (
	"log/slog"
	"net"
	"time"

	"github.com/miekg/dns"

	"github.com/michaellandi/agentgated/internal/cache"
	"github.com/michaellandi/agentgated/internal/config"
	"github.com/michaellandi/agentgated/internal/filter"
)

// Proxy is a dns.Handler that filters, caches, and forwards queries.
type Proxy struct {
	cfg      config.Config
	filter   filter.Filter
	cache    *cache.Cache
	upstream *dns.Client
	logger   *slog.Logger
}

// New builds a Proxy from its dependencies.
func New(cfg config.Config, f filter.Filter, c *cache.Cache, logger *slog.Logger) *Proxy {
	return &Proxy{
		cfg:      cfg,
		filter:   f,
		cache:    c,
		upstream: &dns.Client{Timeout: 5 * time.Second},
		logger:   logger,
	}
}

// ServeDNS implements dns.Handler.
func (p *Proxy) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	start := time.Now()
	resp := new(dns.Msg)
	resp.SetReply(r)

	if len(r.Question) != 1 {
		resp.Rcode = dns.RcodeFormatError
		p.write(w, resp)
		return
	}
	q := r.Question[0]
	client := clientAddr(w)

	if p.filter.Evaluate(q.Name) == filter.Block {
		p.respondBlocked(w, resp, q, client, start)
		return
	}

	if p.cfg.DNSCache {
		if cached, ok := p.cache.Get(q); ok {
			cached.Id = r.Id
			p.write(w, cached)
			p.log(q, client, "allow", "cache", start, nil)
			return
		}
	}

	upstreamResp, _, err := p.upstream.Exchange(r, p.cfg.DNSUpstream)
	if err != nil {
		resp.Rcode = dns.RcodeServerFailure
		p.write(w, resp)
		p.log(q, client, "allow", "upstream", start, err)
		return
	}

	if p.cfg.DNSCache {
		p.cache.Set(q, upstreamResp)
	}
	p.write(w, upstreamResp)
	p.log(q, client, "allow", "upstream", start, nil)
}

func (p *Proxy) respondBlocked(w dns.ResponseWriter, resp *dns.Msg, q dns.Question, client string, start time.Time) {
	if p.cfg.DNSBlockedIP == "" || q.Qtype != dns.TypeA {
		resp.Rcode = dns.RcodeNameError
		p.write(w, resp)
		p.log(q, client, "block", "nxdomain", start, nil)
		return
	}
	resp.Answer = append(resp.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.ParseIP(p.cfg.DNSBlockedIP),
	})
	p.write(w, resp)
	p.log(q, client, "block", "redirect", start, nil)
}

func (p *Proxy) write(w dns.ResponseWriter, resp *dns.Msg) {
	if err := w.WriteMsg(resp); err != nil {
		p.logger.Error("write response failed", "error", err)
	}
}

func (p *Proxy) log(q dns.Question, client, decision, source string, start time.Time, err error) {
	attrs := []any{
		"query", q.Name,
		"qtype", dns.TypeToString[q.Qtype],
		"client", client,
		"decision", decision,
		"source", source,
		"duration_ms", time.Since(start).Milliseconds(),
	}
	if err != nil {
		attrs = append(attrs, "error", err.Error())
		p.logger.Warn("query", attrs...)
		return
	}
	p.logger.Info("query", attrs...)
}

func clientAddr(w dns.ResponseWriter) string {
	host, _, err := net.SplitHostPort(w.RemoteAddr().String())
	if err != nil {
		return w.RemoteAddr().String()
	}
	return host
}
