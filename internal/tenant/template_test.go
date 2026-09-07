package tenant

import (
	"net/http"
	"strings"
	"testing"
)

func TestParseTemplateInvalid(t *testing.T) {
	cases := []string{
		"https://policy.internal/{unknown}/list.txt",
		"https://policy.internal/{header.}/list.txt",
		"https://policy.internal/{header.Bad Name}/list.txt",
		"https://policy.internal/{ip/list.txt",
	}
	for _, tmpl := range cases {
		if _, err := ParseTemplate(tmpl); err == nil {
			t.Errorf("ParseTemplate(%q): got nil error, want error", tmpl)
		}
	}
}

func TestTemplateResolveIP(t *testing.T) {
	tmpl, err := ParseTemplate("https://policy.internal/tenants/{ip}/allow.txt")
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}

	got, err := tmpl.Resolve(Request{IP: "10.0.0.5"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	want := "https://policy.internal/tenants/10.0.0.5/allow.txt"
	if got != want {
		t.Errorf("Resolve() = %q, want %q", got, want)
	}
}

func TestTemplateResolveHeader(t *testing.T) {
	tmpl, err := ParseTemplate("https://policy.internal/{header.X-Tenant-Id}/deny.txt")
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}

	h := http.Header{}
	h.Set("X-Tenant-Id", "acme")
	got, err := tmpl.Resolve(Request{Header: h})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	want := "https://policy.internal/acme/deny.txt"
	if got != want {
		t.Errorf("Resolve() = %q, want %q", got, want)
	}
}

func TestTemplateResolveMissingHeaderFails(t *testing.T) {
	tmpl, err := ParseTemplate("https://policy.internal/{header.X-Tenant-Id}/deny.txt")
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}

	if _, err := tmpl.Resolve(Request{}); err == nil {
		t.Fatal("Resolve with no headers: got nil error, want error")
	}
	if _, err := tmpl.Resolve(Request{Header: http.Header{}}); err == nil {
		t.Fatal("Resolve with empty headers: got nil error, want error")
	}
}

func TestTemplateResolveHeaderOnDNSRequestFails(t *testing.T) {
	// A DNS query has no headers at all; Header is nil in that case.
	tmpl, err := ParseTemplate("https://policy.internal/{header.X-Tenant-Id}/deny.txt")
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}
	if _, err := tmpl.Resolve(Request{IP: "10.0.0.5"}); err == nil {
		t.Fatal("Resolve with nil Header: got nil error, want error")
	}
}

func TestTemplateResolveEscapesValue(t *testing.T) {
	tmpl, err := ParseTemplate("https://policy.internal/tenants/{ip}/allow.txt")
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}

	// A value containing path-traversal-looking or URL-structural
	// characters must come out escaped, not interpreted.
	got, err := tmpl.Resolve(Request{IP: "../../etc/passwd"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if strings.Contains(got, "../") {
		t.Errorf("Resolve() = %q, contains unescaped path traversal", got)
	}
}

func TestTemplateResolveOversizedValueFails(t *testing.T) {
	tmpl, err := ParseTemplate("https://policy.internal/tenants/{ip}/allow.txt")
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}
	huge := strings.Repeat("a", maxPlaceholderValueLen+1)
	if _, err := tmpl.Resolve(Request{IP: huge}); err == nil {
		t.Fatal("Resolve with oversized value: got nil error, want error")
	}
}

func TestTemplateResolveLiteralOnly(t *testing.T) {
	tmpl, err := ParseTemplate("https://policy.internal/fixed/allow.txt")
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}
	got, err := tmpl.Resolve(Request{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "https://policy.internal/fixed/allow.txt" {
		t.Errorf("Resolve() = %q, want unchanged literal", got)
	}
}
