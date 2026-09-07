package tenant

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/michaellandi/agentgated/internal/filter"
)

// maxListBytes caps how much of a fetched list response is read.
const maxListBytes = 10 << 20 // 10 MiB

// Resolver returns the effective Filter to evaluate a request against.
// Resolve always returns a usable Filter — it never returns an error, so
// callers don't need per-request error handling; resolution and fetch
// failures are handled internally (see DynamicResolver).
type Resolver interface {
	Resolve(ctx context.Context, req Request) filter.Filter
}

// StaticResolver always returns the same fixed Filter, ignoring req. It's
// used when no allow/deny URL template is configured.
type StaticResolver struct {
	Filter filter.Filter
}

// Resolve implements Resolver.
func (s StaticResolver) Resolve(context.Context, Request) filter.Filter {
	return s.Filter
}

// cachedList is a fetched-and-parsed list plus its fetch state.
type cachedList struct {
	mu        sync.RWMutex
	list      *filter.List
	fetchedAt time.Time
	lastErr   error
}

func (c *cachedList) get() (*filter.List, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.list == nil {
		return nil, false
	}
	return c.list, true
}

// set records a fetch result. A successful fetch (err == nil) replaces the
// cached list; a failed fetch only records the error, leaving any
// previously cached list in place — refresh failures must never blank out
// a working list from under live traffic.
func (c *cachedList) set(l *filter.List, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err == nil {
		c.list = l
		c.fetchedAt = time.Now()
	}
	c.lastErr = err
}

// DynamicResolver resolves a per-request Filter by substituting request
// values into configured allow/deny URL templates, fetching and caching
// each resolved URL's list (keyed by URL, so tenants sharing a URL share a
// fetch), and refreshing it on RefreshInterval. If a template is nil,
// resolution fails (e.g. a referenced header is missing), or a URL's first
// fetch fails before anything is cached, that side falls back to
// Fallback's corresponding list.
type DynamicResolver struct {
	AllowTemplate   *Template
	DenyTemplate    *Template
	Fallback        filter.Filter
	Client          *http.Client
	RefreshInterval time.Duration
	Logger          *slog.Logger

	mu    sync.Mutex
	cache map[string]*cachedList
}

// NewDynamicResolver builds a DynamicResolver and starts its background
// refresh loop, which runs until ctx is cancelled.
func NewDynamicResolver(ctx context.Context, allowTemplate, denyTemplate *Template, fallback filter.Filter, fetchTimeout, refreshInterval time.Duration, logger *slog.Logger) *DynamicResolver {
	r := &DynamicResolver{
		AllowTemplate:   allowTemplate,
		DenyTemplate:    denyTemplate,
		Fallback:        fallback,
		Client:          &http.Client{Timeout: fetchTimeout},
		RefreshInterval: refreshInterval,
		Logger:          logger,
		cache:           make(map[string]*cachedList),
	}
	go r.refreshLoop(ctx)
	return r
}

// Resolve implements Resolver.
func (r *DynamicResolver) Resolve(ctx context.Context, req Request) filter.Filter {
	return filter.Filter{
		Mode:      r.Fallback.Mode,
		AllowList: r.resolveList(ctx, r.AllowTemplate, req, r.Fallback.AllowList),
		DenyList:  r.resolveList(ctx, r.DenyTemplate, req, r.Fallback.DenyList),
	}
}

func (r *DynamicResolver) resolveList(ctx context.Context, tmpl *Template, req Request, fallback *filter.List) *filter.List {
	if tmpl == nil {
		return fallback
	}

	resolvedURL, err := tmpl.Resolve(req)
	if err != nil {
		r.warn("template resolution failed, using fallback list", "error", err)
		return fallback
	}

	r.mu.Lock()
	c, ok := r.cache[resolvedURL]
	if !ok {
		c = &cachedList{}
		r.cache[resolvedURL] = c
	}
	r.mu.Unlock()

	if list, ok := c.get(); ok {
		return list
	}

	// First time seeing this URL: fetch synchronously since there's
	// nothing cached yet to fall back to.
	list, err := r.fetch(ctx, resolvedURL)
	if err != nil {
		r.warn("initial policy fetch failed, using fallback list", "url", resolvedURL, "error", err)
		return fallback
	}
	c.set(list, nil)
	return list
}

func (r *DynamicResolver) fetch(ctx context.Context, listURL string) (*filter.List, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, listURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := r.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d fetching %s", resp.StatusCode, listURL)
	}
	return filter.ParseList(io.LimitReader(resp.Body, maxListBytes))
}

func (r *DynamicResolver) refreshLoop(ctx context.Context) {
	ticker := time.NewTicker(r.RefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.refreshAll(ctx)
		}
	}
}

func (r *DynamicResolver) refreshAll(ctx context.Context) {
	r.mu.Lock()
	urls := make([]string, 0, len(r.cache))
	for u := range r.cache {
		urls = append(urls, u)
	}
	r.mu.Unlock()

	for _, u := range urls {
		list, err := r.fetch(ctx, u)

		r.mu.Lock()
		c := r.cache[u]
		r.mu.Unlock()
		if c == nil {
			continue
		}

		if err != nil {
			r.warn("policy refresh failed, keeping last-known-good list", "url", u, "error", err)
			c.set(nil, err)
			continue
		}
		c.set(list, nil)
	}
}

func (r *DynamicResolver) warn(msg string, args ...any) {
	if r.Logger != nil {
		r.Logger.Warn(msg, args...)
	}
}
