// Package tenant resolves a per-request allow/deny policy: either a fixed
// Filter (StaticResolver), or one whose allow/deny list source URLs are
// built by substituting request-derived values into a configured template
// (DynamicResolver). Templates and substitution are opaque to identity:
// the package treats a client IP or header value purely as a string to
// place in a URL — it does not authenticate that the value is genuine.
// Ensuring the identifying value can't be spoofed (e.g. pairing a header
// placeholder with real upstream authentication) is the deploying admin's
// responsibility.
package tenant

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// maxPlaceholderValueLen caps a single substituted placeholder value,
// guarding against degenerate URLs built from oversized values.
const maxPlaceholderValueLen = 256

// Request carries the request-derived values a Template may reference.
// Header is nil for DNS callers, which have no headers.
type Request struct {
	IP     string
	Header http.Header
}

type partKind int

const (
	literalPart partKind = iota
	ipPart
	headerPart
)

type part struct {
	kind partKind
	text string // literal text, or the header name for headerPart
}

// Template is a parsed URL template containing {ip} and {header.Name}
// placeholders.
type Template struct {
	parts []part
}

// ParseTemplate parses s into a Template, validating placeholder syntax.
// Supported placeholders: {ip} and {header.Name}.
func ParseTemplate(s string) (*Template, error) {
	var parts []part
	for len(s) > 0 {
		start := strings.IndexByte(s, '{')
		if start == -1 {
			parts = append(parts, part{kind: literalPart, text: s})
			break
		}
		if start > 0 {
			parts = append(parts, part{kind: literalPart, text: s[:start]})
		}
		rest := s[start:]
		end := strings.IndexByte(rest, '}')
		if end == -1 {
			return nil, fmt.Errorf("template %q: unterminated placeholder", s)
		}
		token := rest[1:end]
		p, err := parsePlaceholder(token)
		if err != nil {
			return nil, fmt.Errorf("template %q: %w", s, err)
		}
		parts = append(parts, p)
		s = rest[end+1:]
	}
	return &Template{parts: parts}, nil
}

func parsePlaceholder(token string) (part, error) {
	if token == "ip" {
		return part{kind: ipPart}, nil
	}
	if name, ok := strings.CutPrefix(token, "header."); ok && isValidHeaderName(name) {
		return part{kind: headerPart, text: name}, nil
	}
	return part{}, fmt.Errorf("unknown placeholder %q (supported: {ip}, {header.Name})", token)
}

func isValidHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for _, c := range name {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-':
		default:
			return false
		}
	}
	return true
}

// Resolve substitutes each placeholder in t with the corresponding value
// from req, URL-path-escaping every substituted value. It returns an error
// if a referenced header is missing on req, or a substituted value is
// empty or exceeds maxPlaceholderValueLen.
func (t *Template) Resolve(req Request) (string, error) {
	var b strings.Builder
	for _, p := range t.parts {
		switch p.kind {
		case literalPart:
			b.WriteString(p.text)
		case ipPart:
			v, err := validatedValue(req.IP)
			if err != nil {
				return "", fmt.Errorf("{ip}: %w", err)
			}
			b.WriteString(url.PathEscape(v))
		case headerPart:
			var v string
			if req.Header != nil {
				v = req.Header.Get(p.text)
			}
			v, err := validatedValue(v)
			if err != nil {
				return "", fmt.Errorf("{header.%s}: %w", p.text, err)
			}
			b.WriteString(url.PathEscape(v))
		}
	}
	return b.String(), nil
}

func validatedValue(v string) (string, error) {
	if v == "" {
		return "", fmt.Errorf("value is empty")
	}
	if len(v) > maxPlaceholderValueLen {
		return "", fmt.Errorf("value exceeds %d bytes", maxPlaceholderValueLen)
	}
	return v, nil
}
