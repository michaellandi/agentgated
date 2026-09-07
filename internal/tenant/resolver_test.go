package tenant

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/michaellandi/agentgated/internal/filter"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestStaticResolverIgnoresRequest(t *testing.T) {
	f := filter.Filter{Mode: filter.DenyList}
	r := StaticResolver{Filter: f}

	got1 := r.Resolve(context.Background(), Request{IP: "1.2.3.4"})
	got2 := r.Resolve(context.Background(), Request{IP: "5.6.7.8", Header: http.Header{"X": {"y"}}})

	if got1 != f || got2 != f {
		t.Error("StaticResolver.Resolve returned different Filters for different requests")
	}
}

func TestDynamicResolverFetchesPerTenant(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/tenants/1.1.1.1/allow.txt", func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "one.example.com\n")
	})
	mux.HandleFunc("/tenants/2.2.2.2/allow.txt", func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "two.example.com\n")
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	allowTemplate, err := ParseTemplate(server.URL + "/tenants/{ip}/allow.txt")
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	r := NewDynamicResolver(ctx, allowTemplate, nil, filter.Filter{Mode: filter.AllowList}, time.Second, time.Hour, testLogger())

	f1 := r.Resolve(ctx, Request{IP: "1.1.1.1"})
	if !f1.AllowList.Contains("one.example.com") {
		t.Error("tenant 1.1.1.1: expected one.example.com to be allow-listed")
	}
	if f1.AllowList.Contains("two.example.com") {
		t.Error("tenant 1.1.1.1: did not expect two.example.com to be allow-listed")
	}

	f2 := r.Resolve(ctx, Request{IP: "2.2.2.2"})
	if !f2.AllowList.Contains("two.example.com") {
		t.Error("tenant 2.2.2.2: expected two.example.com to be allow-listed")
	}
	if f2.AllowList.Contains("one.example.com") {
		t.Error("tenant 2.2.2.2: did not expect one.example.com to be allow-listed")
	}
}

func TestDynamicResolverRefreshPicksUpChanges(t *testing.T) {
	var content atomic.Value
	content.Store("old.example.com\n")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, content.Load().(string))
	}))
	t.Cleanup(server.Close)

	tmpl, err := ParseTemplate(server.URL + "/allow.txt")
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	r := NewDynamicResolver(ctx, tmpl, nil, filter.Filter{Mode: filter.AllowList}, time.Second, 20*time.Millisecond, testLogger())

	f := r.Resolve(ctx, Request{IP: "1.1.1.1"})
	if !f.AllowList.Contains("old.example.com") {
		t.Fatal("expected initial fetch to contain old.example.com")
	}

	content.Store("new.example.com\n")

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		f = r.Resolve(ctx, Request{IP: "1.1.1.1"})
		if f.AllowList.Contains("new.example.com") {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("background refresh did not pick up the updated list within timeout")
}

func TestDynamicResolverFailSafeKeepsLastGoodList(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "good.example.com\n")
	}))

	tmpl, err := ParseTemplate(server.URL + "/allow.txt")
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	r := NewDynamicResolver(ctx, tmpl, nil, filter.Filter{Mode: filter.AllowList}, time.Second, 20*time.Millisecond, testLogger())

	f := r.Resolve(ctx, Request{IP: "1.1.1.1"})
	if !f.AllowList.Contains("good.example.com") {
		t.Fatal("expected initial fetch to succeed")
	}

	server.Close() // every refresh from here on fails

	time.Sleep(150 * time.Millisecond) // let several failed refresh cycles run

	f = r.Resolve(ctx, Request{IP: "1.1.1.1"})
	if !f.AllowList.Contains("good.example.com") {
		t.Fatal("expected the last-known-good list to still be served after refresh failures")
	}
}

func TestDynamicResolverFallsBackWhenTemplateUnset(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "allowed.example.com\n")
	}))
	t.Cleanup(server.Close)

	allowTemplate, err := ParseTemplate(server.URL + "/allow.txt")
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}

	fallbackDeny, err := filter.ParseList(strings.NewReader("fallback-blocked.example.com\n"))
	if err != nil {
		t.Fatalf("ParseList: %v", err)
	}
	fallback := filter.Filter{Mode: filter.DenyList, DenyList: fallbackDeny}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	// DenyTemplate is nil: only AllowList is dynamically resolved.
	r := NewDynamicResolver(ctx, allowTemplate, nil, fallback, time.Second, time.Hour, testLogger())

	f := r.Resolve(ctx, Request{IP: "1.1.1.1"})
	if f.DenyList != fallback.DenyList {
		t.Error("expected DenyList to fall back to the static fallback list when DenyTemplate is unset")
	}
	if !f.AllowList.Contains("allowed.example.com") {
		t.Error("expected AllowList to come from the fetched template result")
	}
}

func TestDynamicResolverInitialFetchFailureFallsBack(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)

	tmpl, err := ParseTemplate(server.URL + "/allow.txt")
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}

	fallbackAllow, err := filter.ParseList(strings.NewReader("fallback.example.com\n"))
	if err != nil {
		t.Fatalf("ParseList: %v", err)
	}
	fallback := filter.Filter{Mode: filter.AllowList, AllowList: fallbackAllow}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	r := NewDynamicResolver(ctx, tmpl, nil, fallback, time.Second, time.Hour, testLogger())

	f := r.Resolve(ctx, Request{IP: "1.1.1.1"})
	if !f.AllowList.Contains("fallback.example.com") {
		t.Error("expected the fallback list to be used when the initial fetch fails")
	}
}
