// Package cache implements a small in-memory DNS response cache keyed by
// query name, type, and class.
package cache

import (
	"sync"
	"time"

	"github.com/miekg/dns"
)

type entry struct {
	msg     *dns.Msg
	expires time.Time
}

// Cache is a concurrency-safe, in-memory DNS response cache. Entries expire
// based on the minimum TTL among the cached response's answer records,
// capped at maxTTL.
type Cache struct {
	mu      sync.Mutex
	entries map[string]entry
	maxTTL  time.Duration
}

// New returns an empty Cache that caps entry lifetimes at maxTTL.
func New(maxTTL time.Duration) *Cache {
	return &Cache{
		entries: make(map[string]entry),
		maxTTL:  maxTTL,
	}
}

func key(q dns.Question) string {
	return q.Name + "|" + dns.TypeToString[q.Qtype] + "|" + dns.ClassToString[q.Qclass]
}

// Get returns a copy of the cached response for q, if present and not
// expired.
func (c *Cache) Get(q dns.Question) (*dns.Msg, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	e, ok := c.entries[key(q)]
	if !ok || time.Now().After(e.expires) {
		return nil, false
	}
	return e.msg.Copy(), true
}

// Set stores a copy of msg for q, using the minimum answer TTL (capped at
// maxTTL) as the entry's lifetime. Responses with no answer records, or a
// zero TTL, are not cached.
func (c *Cache) Set(q dns.Question, msg *dns.Msg) {
	ttl := minTTL(msg)
	if ttl <= 0 {
		return
	}
	if ttl > c.maxTTL {
		ttl = c.maxTTL
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key(q)] = entry{msg: msg.Copy(), expires: time.Now().Add(ttl)}
}

func minTTL(msg *dns.Msg) time.Duration {
	var min uint32
	found := false
	for _, rr := range msg.Answer {
		ttl := rr.Header().Ttl
		if !found || ttl < min {
			min = ttl
			found = true
		}
	}
	if !found {
		return 0
	}
	return time.Duration(min) * time.Second
}
