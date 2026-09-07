// Package config loads and validates agentgated's YAML configuration.
package config

import (
	"fmt"
	"net"
	"os"
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
		DNSListen:             ":53",
		DNSUpstream:           "1.1.1.1:53",
		FilterMode:            FilterDeny,
		AllowListFile:         "/etc/agentgated/allowlist.txt",
		DenyListFile:          "/etc/agentgated/denylist.txt",
		DNSCache:              true,
		DNSCacheMaxTTL:        time.Hour,
		PolicyRefreshInterval: 5 * time.Minute,
		PolicyFetchTimeout:    10 * time.Second,
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
	return nil
}
