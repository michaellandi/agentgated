// Package config loads and validates agentgated's YAML configuration.
package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"
)

// FilterMode selects how queries are evaluated against the allow/deny lists.
type FilterMode string

const (
	FilterNone  FilterMode = "none"
	FilterAllow FilterMode = "allow"
	FilterDeny  FilterMode = "deny"
)

// Config holds the daemon's runtime configuration. Options scoped to one
// listener are prefixed accordingly (dns_, connect_); unprefixed options
// (filter_mode, allowlist_file, denylist_file, log_path) apply to all of
// them.
type Config struct {
	DNSListen      string        `yaml:"dns_listen"`
	DNSUpstream    string        `yaml:"dns_upstream"`
	FilterMode     FilterMode    `yaml:"filter_mode"`
	AllowListFile  string        `yaml:"allowlist_file"`
	DenyListFile   string        `yaml:"denylist_file"`
	DNSBlockedIP   string        `yaml:"dns_blocked_ip"`
	DNSCache       bool          `yaml:"dns_cache"`
	DNSCacheMaxTTL time.Duration `yaml:"dns_cache_max_ttl"`
	LogPath        string        `yaml:"log_path"`
	ConnectListen  string        `yaml:"connect_listen"`

	// ConnectAllowedPorts restricts which ports a CONNECT target may use,
	// independent of the hostname policy. A CONNECT tunnel isn't inspected
	// once permitted, so an allowed hostname would otherwise be reachable
	// on any port — including a DNS-over-TLS (853) or DNS-over-HTTPS (443,
	// same port as normal HTTPS) resolver, letting an agent tunnel DNS
	// queries for arbitrary domains completely outside this proxy's own
	// filtering. Empty means unrestricted.
	ConnectAllowedPorts []string `yaml:"connect_allowed_ports"`

	// ConnectDenyListFile is a hostname list (same format as denylist_file)
	// that always blocks a CONNECT target, regardless of filter_mode or
	// AllowListURLTemplate/DenyListURLTemplate policy — including in
	// filter_mode: none. It exists to hold known DNS-over-HTTPS/DNS-over-
	// TLS resolver hostnames: even a fully trusted allow-listed host must
	// not become a channel for resolving/exfiltrating data via names this
	// proxy never sees. Edit the file directly to change what it blocks;
	// there is no separate override list. Empty path disables it.
	ConnectDenyListFile string `yaml:"connect_denylist_file"`

	// ConnectBlockPrivateIPs rejects a CONNECT target that resolves to a
	// loopback, link-local, private, or unspecified address, regardless of
	// filter_mode or any allow list — including one populated from a
	// dynamic AllowListURLTemplate source, which agentgated does not
	// authenticate. Without this, an allowed hostname (or one later
	// rebound via DNS to a different address) can reach internal-only
	// services, e.g. a cloud metadata endpoint like 169.254.169.254. The
	// resolved address is validated once and dialed directly — the
	// hostname is not resolved a second time — so a rebind between check
	// and dial can't slip through.
	ConnectBlockPrivateIPs bool `yaml:"connect_block_private_ips"`

	// ConnectIdleTimeout closes a CONNECT tunnel after this long without
	// data in either direction. Zero disables it.
	ConnectIdleTimeout time.Duration `yaml:"connect_idle_timeout"`

	// ConnectMaxDuration closes a CONNECT tunnel after this long regardless
	// of activity, capping how long any single tunnel can stay open. Zero
	// disables it.
	ConnectMaxDuration time.Duration `yaml:"connect_max_duration"`

	// AllowListURLTemplate and DenyListURLTemplate, when set, resolve a
	// per-request policy source URL instead of using the static list
	// files above. Supported placeholders: {ip} (client source IP) and
	// {header.Name} (an HTTP header value; CONNECT requests only — DNS
	// has no headers). agentgated does not authenticate the values it
	// substitutes; ensuring they can't be spoofed is the deploying
	// admin's responsibility.
	AllowListURLTemplate  string        `yaml:"allowlist_url_template"`
	DenyListURLTemplate   string        `yaml:"denylist_url_template"`
	PolicyRefreshInterval time.Duration `yaml:"policy_refresh_interval"`
	PolicyFetchTimeout    time.Duration `yaml:"policy_fetch_timeout"`
}

// Default returns the configuration used for any fields a loaded file omits.
func Default() Config {
	return Config{
		DNSListen:              ":53",
		DNSUpstream:            "1.1.1.1:53",
		FilterMode:             FilterDeny,
		AllowListFile:          "/etc/agentgated/allowlist.txt",
		DenyListFile:           "/etc/agentgated/denylist.txt",
		DNSCache:               true,
		DNSCacheMaxTTL:         time.Hour,
		PolicyRefreshInterval:  5 * time.Minute,
		PolicyFetchTimeout:     10 * time.Second,
		ConnectAllowedPorts:    []string{"443"},
		ConnectDenyListFile:    "/etc/agentgated/connect-denylist.txt",
		ConnectBlockPrivateIPs: true,
		ConnectIdleTimeout:     5 * time.Minute,
		ConnectMaxDuration:     time.Hour,
	}
}

// Load reads and validates the config file at path, applying defaults for
// any fields it doesn't set.
func Load(path string) (Config, error) {
	cfg := Default()

	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("reading config: %w", err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parsing config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// Validate checks that the configuration is internally consistent.
func (c Config) Validate() error {
	switch c.FilterMode {
	case FilterNone, FilterAllow, FilterDeny:
	default:
		return fmt.Errorf("invalid filter_mode %q", c.FilterMode)
	}
	if c.DNSBlockedIP != "" && net.ParseIP(c.DNSBlockedIP) == nil {
		return fmt.Errorf("invalid dns_blocked_ip %q", c.DNSBlockedIP)
	}
	if c.DNSListen == "" {
		return fmt.Errorf("dns_listen must not be empty")
	}
	if c.DNSUpstream == "" {
		return fmt.Errorf("dns_upstream must not be empty")
	}
	for _, p := range c.ConnectAllowedPorts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("invalid connect_allowed_ports entry %q", p)
		}
	}
	return nil
}
