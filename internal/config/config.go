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
	FilterNone      FilterMode = "none"
	FilterWhitelist FilterMode = "whitelist"
	FilterBlacklist FilterMode = "blacklist"
)

// Config holds the daemon's runtime configuration. Options scoped to one
// listener are prefixed accordingly (dns_, connect_); unprefixed options
// (filter_mode, blacklist_file, whitelist_file, log_path) apply to all of
// them.
type Config struct {
	DNSListen      string        `yaml:"dns_listen"`
	DNSUpstream    string        `yaml:"dns_upstream"`
	FilterMode     FilterMode    `yaml:"filter_mode"`
	BlacklistFile  string        `yaml:"blacklist_file"`
	WhitelistFile  string        `yaml:"whitelist_file"`
	DNSBlockedIP   string        `yaml:"dns_blocked_ip"`
	DNSCache       bool          `yaml:"dns_cache"`
	DNSCacheMaxTTL time.Duration `yaml:"dns_cache_max_ttl"`
	LogPath        string        `yaml:"log_path"`
	ConnectListen  string        `yaml:"connect_listen"`
}

// Default returns the configuration used for any fields a loaded file omits.
func Default() Config {
	return Config{
		DNSListen:      ":53",
		DNSUpstream:    "1.1.1.1:53",
		FilterMode:     FilterBlacklist,
		BlacklistFile:  "/etc/agentgated/blacklist.txt",
		WhitelistFile:  "/etc/agentgated/whitelist.txt",
		DNSCache:       true,
		DNSCacheMaxTTL: time.Hour,
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
	case FilterNone, FilterWhitelist, FilterBlacklist:
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
