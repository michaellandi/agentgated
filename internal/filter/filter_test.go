package filter

import (
	"os"
	"path/filepath"
	"testing"
)

func loadListFromContent(t *testing.T, content string) *List {
	t.Helper()
	path := filepath.Join(t.TempDir(), "list.txt")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write list: %v", err)
	}
	l, err := LoadList(path)
	if err != nil {
		t.Fatalf("LoadList: %v", err)
	}
	return l
}

func TestListContainsSuffixMatch(t *testing.T) {
	l := loadListFromContent(t, "example.com\nsub.example.net\n")

	cases := []struct {
		name string
		want bool
	}{
		{"example.com", true},
		{"example.com.", true},         // trailing dot, as DNS query names carry
		{"EXAMPLE.COM", true},          // case-insensitive
		{"sub.example.com", true},      // direct subdomain
		{"deep.sub.example.com", true}, // multi-level subdomain
		{"notexample.com", false},      // not a real suffix match
		{"example.net", false},         // unrelated domain
		{"example.co", false},          // shorter, unrelated TLD
		{"sub.example.net", true},      // exact match on a subdomain entry
		{"other.example.net", false},   // sibling of a subdomain entry, not covered
		{"deep.sub.example.net", true}, // subdomain of a subdomain entry
	}
	for _, tc := range cases {
		if got := l.Contains(tc.name); got != tc.want {
			t.Errorf("Contains(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestListIgnoresBlankLinesAndComments(t *testing.T) {
	l := loadListFromContent(t, "# comment\n\n  \nexample.com\n   # indented comment\n")

	if l.Len() != 1 {
		t.Fatalf("Len() = %d, want 1", l.Len())
	}
	if !l.Contains("example.com") {
		t.Error("Contains(\"example.com\") = false, want true")
	}
}

func TestLoadListEmptyPathYieldsEmptyList(t *testing.T) {
	l, err := LoadList("")
	if err != nil {
		t.Fatalf("LoadList(\"\") error = %v", err)
	}
	if l.Len() != 0 {
		t.Fatalf("Len() = %d, want 0", l.Len())
	}
	if l.Contains("example.com") {
		t.Error("Contains(\"example.com\") = true, want false for empty list")
	}
}

func TestLoadListMissingFile(t *testing.T) {
	if _, err := LoadList(filepath.Join(t.TempDir(), "does-not-exist.txt")); err == nil {
		t.Fatal("LoadList on a missing file: got nil error, want non-nil")
	}
}

func TestFilterEvaluate(t *testing.T) {
	allowList := loadListFromContent(t, "good.example.com\n")
	denyList := loadListFromContent(t, "bad.example.com\n")

	cases := []struct {
		name   string
		filter Filter
		query  string
		want   Decision
	}{
		{"none mode always allows", Filter{Mode: None}, "anything.example.com", Allow},
		{"none mode allows deny-listed name too", Filter{Mode: None, DenyList: denyList}, "bad.example.com", Allow},

		{"allow mode: listed host allowed", Filter{Mode: AllowList, AllowList: allowList}, "good.example.com", Allow},
		{"allow mode: listed host's subdomain allowed", Filter{Mode: AllowList, AllowList: allowList}, "sub.good.example.com", Allow},
		{"allow mode: unlisted host blocked", Filter{Mode: AllowList, AllowList: allowList}, "other.example.com", Block},
		{"allow mode: nil list blocks everything", Filter{Mode: AllowList}, "good.example.com", Block},

		{"deny mode: listed host blocked", Filter{Mode: DenyList, DenyList: denyList}, "bad.example.com", Block},
		{"deny mode: listed host's subdomain blocked", Filter{Mode: DenyList, DenyList: denyList}, "sub.bad.example.com", Block},
		{"deny mode: unlisted host allowed", Filter{Mode: DenyList, DenyList: denyList}, "good.example.com", Allow},
		{"deny mode: nil list allows everything", Filter{Mode: DenyList}, "bad.example.com", Allow},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.filter.Evaluate(tc.query); got != tc.want {
				t.Errorf("Evaluate(%q) = %v, want %v", tc.query, got, tc.want)
			}
		})
	}
}
