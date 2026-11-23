package main

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestValidSubpath(t *testing.T) {
	ok := []string{"/", "/v1/messages", "/v1/messages/", "/v1/models/claude-x"}
	bad := []string{"/v1/../files", "/v1/./x", "//v1", "/v1//x", "/v1/%2e%2e/x", "/v1%2Ffiles", "/a\\b", "/x%00"}
	for _, p := range ok {
		if _, good := validSubpath(p); !good {
			t.Errorf("expected ok: %q", p)
		}
	}
	for _, p := range bad {
		if _, good := validSubpath(p); good {
			t.Errorf("expected reject: %q", p)
		}
	}
}

func TestAllowedPath(t *testing.T) {
	allow := []string{"/v1/messages", "/v1/models/"}
	cases := map[string]bool{
		"/v1/messages": true, "/v1/messages/count_tokens": true, "/v1/messagesX": false,
		"/v1/models": true, "/v1/models/x": true, "/v1/files": false, "/": false,
	}
	for p, want := range cases {
		if got := allowedPath(allow, p); got != want {
			t.Errorf("allowedPath(%q)=%v want %v", p, got, want)
		}
	}
	if !allowedPath(nil, "/anything") {
		t.Error("empty allow list must allow all")
	}
}

func TestScrubResponse(t *testing.T) {
	key := "sk-live-SECRET-abcdef"
	req, _ := http.NewRequest("POST", "http://x/v1/messages", nil)
	req = req.WithContext(context.WithValue(context.Background(), ctxKey{}, &reqInfo{key: key}))
	resp := &http.Response{
		StatusCode: 401, Request: req, Header: http.Header{"Content-Type": {"application/json"}, "Set-Cookie": {"a=b"}},
		Body: io.NopCloser(strings.NewReader(`{"error":"Incorrect API key provided: ` + key + `", "m1":"sk-live-*************cdef", "m2":"****cdef"}`)),
	}
	if err := (&llmGateway{}).scrubResponse(resp); err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(b), key) || strings.Contains(string(b), "cdef") || strings.Count(string(b), "[REDACTED]") != 3 {
		t.Fatalf("key not scrubbed: %s", b)
	}
	if resp.Header.Get("Set-Cookie") != "" {
		t.Fatal("Set-Cookie not removed")
	}
}

func TestEgressAllowed(t *testing.T) {
	p := newEgressProxy("pypi.org, *.pythonhosted.org, .github.com", "")
	cases := map[string]bool{
		"pypi.org:443": true, "files.pythonhosted.org:443": true, "pythonhosted.org:443": true,
		"evilpypi.org:443": false, "pypi.org:22": false, "1.2.3.4:443": false, "api.github.com:443": true,
		"github.com.evil.io:443": false,
	}
	for hp, want := range cases {
		if _, got := p.allowed(hp, "443"); got != want {
			t.Errorf("allowed(%q)=%v want %v", hp, got, want)
		}
	}
}

func TestPublicOnly(t *testing.T) {
	for _, a := range []string{"127.0.0.1:443", "10.1.2.3:443", "0.250.250.254:80", "192.168.1.5:443", "169.254.169.254:80", "[::1]:443", "[fd07::1]:443", "[::ffff:10.0.0.1]:443"} {
		if publicOnly("tcp", a, nil) == nil {
			t.Errorf("expected block: %s", a)
		}
	}
	for _, a := range []string{"1.1.1.1:443", "[2606:4700::1111]:443"} {
		if err := publicOnly("tcp", a, nil); err != nil {
			t.Errorf("expected allow: %s: %v", a, err)
		}
	}
}

func TestParseForwards(t *testing.T) {
	f, err := parseForwards("9000=host.docker.internal:7000, 31337=10.0.0.5:31337")
	if err != nil || len(f) != 2 || f[0].port != 9000 || f[1].target != "10.0.0.5:31337" {
		t.Fatalf("got %+v %v", f, err)
	}
	for _, bad := range []string{"x=1.2.3.4:1", "9000=nohostport", "9000=a:1,9000=b:2", "70000=a:1"} {
		if _, err := parseForwards(bad); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}
