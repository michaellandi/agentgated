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

// Config holds the daemon's runtime configuration.
type Config struct {
	Listen        string        `yaml:"listen"`
	Upstream      string        `yaml:"upstream"`
	FilterMode    FilterMode    `yaml:"filter_mode"`
	BlacklistFile string        `yaml:"blacklist_file"`
	WhitelistFile string        `yaml:"whitelist_file"`
	BlockedIP     string        `yaml:"blocked_ip"`
	Cache         bool          `yaml:"cache"`
	CacheMaxTTL   time.Duration `yaml:"cache_max_ttl"`
	LogPath       string        `yaml:"log_path"`
	ConnectListen string        `yaml:"connect_listen"`
}

// Default returns the configuration used for any fields a loaded file omits.
func Default() Config {
	return Config{
		Listen:        ":53",
		Upstream:      "1.1.1.1:53",
		FilterMode:    FilterBlacklist,
		BlacklistFile: "/etc/agentgated/blacklist.txt",
		WhitelistFile: "/etc/agentgated/whitelist.txt",
		Cache:         true,
		CacheMaxTTL:   time.Hour,
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
	if c.BlockedIP != "" && net.ParseIP(c.BlockedIP) == nil {
		return fmt.Errorf("invalid blocked_ip %q", c.BlockedIP)
	}
	if c.Listen == "" {
		return fmt.Errorf("listen must not be empty")
	}
	if c.Upstream == "" {
		return fmt.Errorf("upstream must not be empty")
	}
	return nil
}
