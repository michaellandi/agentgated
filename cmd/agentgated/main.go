// Command agentgated is an egress control daemon for AI agents: it forwards
// DNS queries and proxies HTTP CONNECT tunnels while applying a shared
// static allow/deny list to both.
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/miekg/dns"

	"github.com/michaellandi/agentgated/internal/cache"
	"github.com/michaellandi/agentgated/internal/config"
	"github.com/michaellandi/agentgated/internal/connectproxy"
	"github.com/michaellandi/agentgated/internal/filter"
	"github.com/michaellandi/agentgated/internal/proxy"
)

func main() {
	configPath := flag.String("config", "/etc/agentgated/agentgated.yaml", "path to config file")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	if err := run(*configPath, logger); err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}
}

func run(configPath string, logger *slog.Logger) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	if cfg.LogPath != "" {
		f, err := os.OpenFile(cfg.LogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("opening log path: %w", err)
		}
		defer f.Close()
		logger = slog.New(slog.NewTextHandler(f, nil))
	}

	allowList, err := filter.LoadList(cfg.AllowListFile)
	if err != nil {
		return fmt.Errorf("loading allow list: %w", err)
	}
	denyList, err := filter.LoadList(cfg.DenyListFile)
	if err != nil {
		return fmt.Errorf("loading deny list: %w", err)
	}

	f := filter.Filter{
		Mode:      filter.Mode(cfg.FilterMode),
		AllowList: allowList,
		DenyList:  denyList,
	}

	p := proxy.New(cfg, f, cache.New(cfg.DNSCacheMaxTTL), logger)
	cp := connectproxy.New(f, logger)

	logger.Info("starting agentgated",
		"dns_listen", cfg.DNSListen,
		"dns_upstream", cfg.DNSUpstream,
		"filter_mode", cfg.FilterMode,
		"allowlist_entries", allowList.Len(),
		"denylist_entries", denyList.Len(),
		"connect_listen", cfg.ConnectListen,
	)

	handler := dns.HandlerFunc(p.ServeDNS)
	udpServer := &dns.Server{Addr: cfg.DNSListen, Net: "udp", Handler: handler}
	tcpServer := &dns.Server{Addr: cfg.DNSListen, Net: "tcp", Handler: handler}

	errCh := make(chan error, 3)
	go func() { errCh <- udpServer.ListenAndServe() }()
	go func() { errCh <- tcpServer.ListenAndServe() }()
	if cfg.ConnectListen != "" {
		go func() { errCh <- cp.ListenAndServe(cfg.ConnectListen) }()
	}

	return <-errCh
}
