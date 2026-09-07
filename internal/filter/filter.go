// Package filter implements static allow/deny list matching for DNS query
// names.
package filter

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
)

// Mode selects how a Filter evaluates a query name.
type Mode string

const (
	None      Mode = "none"
	Whitelist Mode = "whitelist"
	Blacklist Mode = "blacklist"
)

// Decision is the outcome of evaluating a query name against a Filter.
type Decision int

const (
	Allow Decision = iota
	Block
)

// List is a set of hostnames matched by exact name or domain suffix — an
// entry "example.com" also matches "sub.example.com".
type List struct {
	mu      sync.RWMutex
	entries map[string]struct{}
}

// LoadList reads one hostname per line from path. Blank lines and lines
// starting with '#' are ignored. An empty path yields an empty, valid list.
func LoadList(path string) (*List, error) {
	l := &List{entries: make(map[string]struct{})}
	if path == "" {
		return l, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening list %s: %w", path, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		l.entries[normalize(line)] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading list %s: %w", path, err)
	}
	return l, nil
}

func normalize(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

// Contains reports whether name matches an entry exactly or is a subdomain
// of one.
func (l *List) Contains(name string) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()

	name = normalize(name)
	for {
		if _, ok := l.entries[name]; ok {
			return true
		}
		idx := strings.IndexByte(name, '.')
		if idx == -1 {
			return false
		}
		name = name[idx+1:]
	}
}

// Len returns the number of entries in the list.
func (l *List) Len() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.entries)
}

// Filter evaluates query names against the configured mode and lists.
type Filter struct {
	Mode      Mode
	Blacklist *List
	Whitelist *List
}

// Evaluate returns Allow or Block for name according to f.Mode.
func (f Filter) Evaluate(name string) Decision {
	switch f.Mode {
	case Whitelist:
		if f.Whitelist != nil && f.Whitelist.Contains(name) {
			return Allow
		}
		return Block
	case Blacklist:
		if f.Blacklist != nil && f.Blacklist.Contains(name) {
			return Block
		}
		return Allow
	default:
		return Allow
	}
}
