// re-gateway: the trusted side of the sandbox.
//
//	-mode llm    Reverse proxy for LLM APIs. The ONLY process that can read the
//	             real credentials (/run/secrets). Strips whatever auth the
//	             sandbox sends, injects the real key, forwards to a fixed
//	             upstream, and only for allow-listed API paths.
//	-mode relay  Holds no secrets. Fixed TCP port forwards (RE_FORWARDS) and an
//	             HTTP/CONNECT egress proxy restricted to RE_EGRESS_DOMAINS.
//
// Standard library only.
package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

//go:embed routes.json
var embeddedRoutes []byte

const maxRequestBody = 128 << 20

func main() {
	mode := flag.String("mode", "llm", "llm | relay")
	listen := flag.String("listen", ":8080", "llm: listen address")
	routesPath := flag.String("routes", "", "llm: routes.json override (default: embedded)")
	secretsDir := flag.String("secrets", "/run/secrets", "llm: directory holding one file per credential")
	proxyListen := flag.String("proxy-listen", ":3128", "relay: egress proxy listen address")
	healthcheck := flag.String("healthcheck", "", "probe this URL and exit 0/1 (for container healthchecks)")
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.LUTC)

	if *healthcheck != "" {
		c := &http.Client{Timeout: 3 * time.Second}
		resp, err := c.Get(*healthcheck)
		if err != nil || resp.StatusCode != http.StatusOK {
			os.Exit(1)
		}
		os.Exit(0)
	}

	switch *mode {
	case "llm":
		runLLM(*listen, *routesPath, *secretsDir)
	case "relay":
		runRelay(*proxyListen)
	default:
		log.Fatalf("unknown mode %q", *mode)
	}
}

// ---------------------------------------------------------------------------
// LLM gateway
// ---------------------------------------------------------------------------

type Credential struct {
	Secret        string            `json:"secret"`         // file name under the secrets dir
	Header        string            `json:"header"`         // header to set upstream
	Format        string            `json:"format"`         // value template, "{key}" is replaced
	AppendHeaders map[string]string `json:"append_headers"` // comma-appended (e.g. anthropic-beta)
}

type Route struct {
	Name        string            `json:"name"`
	Upstream    string            `json:"upstream"`
	Credentials []Credential      `json:"credentials"` // first one whose secret file exists wins
	AllowPaths  []string          `json:"allow_paths"` // prefix match on segment boundary; empty = all
	SetHeaders  map[string]string `json:"set_headers"`
	target      *url.URL
}

type routesFile struct {
	Routes []*Route `json:"routes"`
}

// Headers that may carry credentials or client identity. Always removed from
// what the sandbox sends; the gateway sets the real one itself.
var strippedRequestHeaders = []string{
	"Authorization", "Proxy-Authorization", "X-Api-Key", "Api-Key", "X-Goog-Api-Key",
	"Cookie", "OpenAI-Organization", "OpenAI-Project", "ChatGPT-Account-Id", "Anthropic-Workspace-Id",
	"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Real-Ip",
	"Accept-Encoding", // let the transport negotiate + decompress so error bodies can be scrubbed
}

type ctxKey struct{}

type reqInfo struct {
	route *Route
	sub   string // escaped, validated sub-path, e.g. "/v1/messages"
	cred  *Credential
	key   string
}

type llmGateway struct {
	routes     map[string]*Route
	order      []string
	secretsDir string
	proxy      *httputil.ReverseProxy
}

func runLLM(listen, routesPath, secretsDir string) {
	raw := embeddedRoutes
	if routesPath != "" {
		b, err := os.ReadFile(routesPath)
		if err != nil {
			log.Fatalf("read routes: %v", err)
		}
		raw = b
	}
	var rf routesFile
	if err := json.Unmarshal(raw, &rf); err != nil {
		log.Fatalf("parse routes: %v", err)
	}
	g := &llmGateway{routes: map[string]*Route{}, secretsDir: secretsDir}
	nameRe := regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)
	for _, rt := range rf.Routes {
		if !nameRe.MatchString(rt.Name) {
			log.Fatalf("route %q: invalid name", rt.Name)
		}
		u, err := url.Parse(rt.Upstream)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.RawQuery != "" {
			log.Fatalf("route %q: upstream must be an https URL without query", rt.Name)
		}
		if len(rt.Credentials) == 0 {
			log.Fatalf("route %q: no credentials", rt.Name)
		}
		for _, c := range rt.Credentials {
			if !nameRe.MatchString(c.Secret) || c.Header == "" || !strings.Contains(c.Format, "{key}") {
				log.Fatalf("route %q: bad credential spec", rt.Name)
			}
		}
		rt.target = u
		g.routes[rt.Name] = rt
		g.order = append(g.order, rt.Name)
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment, // honour a corporate proxy if set on the gateway only
		DialContext:           (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          32,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	g.proxy = &httputil.ReverseProxy{
		Rewrite:        g.rewrite,
		Transport:      transport,
		FlushInterval:  -1, // stream SSE immediately
		ModifyResponse: g.scrubResponse,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("upstream error: %v", err)
			jsonError(w, http.StatusBadGateway, "gateway: upstream request failed")
		},
	}

	for _, name := range g.order {
		rt := g.routes[name]
		c, _, _ := g.credential(rt)
		state := "no credential"
		if c != nil {
			state = "credential: " + c.Secret
		}
		log.Printf("route /%s -> %s (%s)", name, rt.Upstream, state)
	}
	srv := &http.Server{Addr: listen, Handler: g, ReadHeaderTimeout: 30 * time.Second, IdleTimeout: 5 * time.Minute}
	log.Printf("llm gateway listening on %s", listen)
	log.Fatal(srv.ListenAndServe())
}

// credential returns the first configured credential whose secret file exists.
func (g *llmGateway) credential(rt *Route) (*Credential, string, error) {
	for i := range rt.Credentials {
		c := &rt.Credentials[i]
		b, err := os.ReadFile(filepath.Join(g.secretsDir, c.Secret))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, "", fmt.Errorf("read secret %s: %w", c.Secret, err)
		}
		key := strings.TrimSpace(string(b))
		if key == "" || strings.ContainsAny(key, "\r\n") {
			continue
		}
		return c, key, nil
	}
	return nil, "", nil
}

func (g *llmGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	if r.URL.Path == "/healthz" {
		g.health(w)
		return
	}
	name, rest, _ := strings.Cut(strings.TrimPrefix(r.URL.EscapedPath(), "/"), "/")
	rt := g.routes[name]
	if rt == nil {
		jsonError(w, http.StatusNotFound, "gateway: unknown route; known: /"+strings.Join(g.order, ", /"))
		log.Printf("DENY %s /%s: unknown route", r.Method, name)
		return
	}
	sub, ok := validSubpath("/" + rest)
	if !ok || !allowedPath(rt.AllowPaths, sub) {
		jsonError(w, http.StatusForbidden, "gateway: path not allowed on this route")
		log.Printf("DENY %s /%s%s: path not in allow_paths", r.Method, name, safeLogPath(sub, rest))
		return
	}
	cred, key, err := g.credential(rt)
	if err != nil {
		log.Printf("route %s: %v", name, err)
		jsonError(w, http.StatusInternalServerError, "gateway: cannot read credential")
		return
	}
	if cred == nil {
		jsonError(w, http.StatusServiceUnavailable,
			fmt.Sprintf("gateway: no credential for route %q; on the host run: ./re secret set %s", name, rt.Credentials[0].Secret))
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	ctx := context.WithValue(r.Context(), ctxKey{}, &reqInfo{route: rt, sub: sub, cred: cred, key: key})
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	g.proxy.ServeHTTP(rec, r.WithContext(ctx))
	log.Printf("%s /%s%s -> %d %dB %s", r.Method, name, sub, rec.status, rec.bytes, time.Since(start).Round(time.Millisecond))
}

func (g *llmGateway) rewrite(pr *httputil.ProxyRequest) {
	info := pr.In.Context().Value(ctxKey{}).(*reqInfo)
	t := info.route.target
	escaped := strings.TrimSuffix(t.EscapedPath(), "/") + info.sub
	unescaped, err := url.PathUnescape(escaped)
	if err != nil {
		unescaped = escaped
	}
	pr.Out.URL.Scheme = t.Scheme
	pr.Out.URL.Host = t.Host
	pr.Out.URL.Path = unescaped
	pr.Out.URL.RawPath = escaped
	pr.Out.Host = t.Host
	for _, h := range strippedRequestHeaders {
		pr.Out.Header.Del(h)
	}
	for k, v := range info.route.SetHeaders {
		pr.Out.Header.Set(k, v)
	}
	pr.Out.Header.Set(info.cred.Header, strings.ReplaceAll(info.cred.Format, "{key}", info.key))
	for k, v := range info.cred.AppendHeaders {
		if cur := pr.Out.Header.Get(k); cur != "" && !strings.Contains(cur, v) {
			pr.Out.Header.Set(k, cur+","+v)
		} else if cur == "" {
			pr.Out.Header.Set(k, v)
		}
	}
}

// scrubResponse removes cookies and makes sure a provider error message can
// never echo the credential back into the sandbox.
func (g *llmGateway) scrubResponse(resp *http.Response) error {
	resp.Header.Del("Set-Cookie")
	info, _ := resp.Request.Context().Value(ctxKey{}).(*reqInfo)
	if info == nil || resp.StatusCode < 400 || strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	resp.Body.Close()
	if err != nil {
		return err
	}
	body = bytes.ReplaceAll(body, []byte(info.key), []byte("[REDACTED]"))
	body = maskedKeyPattern(info.key).ReplaceAll(body, []byte("[REDACTED]"))
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	resp.Header.Del("Content-Encoding")
	return nil
}

// maskedKeyPattern matches the partially masked forms providers echo in auth
// errors, e.g. "sk-proj-***...***WXYZ" or "****WXYZ".
func maskedKeyPattern(key string) *regexp.Regexp {
	if len(key) < 16 {
		return regexp.MustCompile(`\*{3,}` + regexp.QuoteMeta(key[len(key)-min(4, len(key)):]))
	}
	return regexp.MustCompile(`(?:` + regexp.QuoteMeta(key[:8]) + `)?\*{3,}` + regexp.QuoteMeta(key[len(key)-4:]))
}

func (g *llmGateway) health(w http.ResponseWriter) {
	type entry struct {
		Route      string `json:"route"`
		Upstream   string `json:"upstream"`
		Configured bool   `json:"configured"`
	}
	out := []entry{}
	for _, name := range g.order {
		rt := g.routes[name]
		c, _, _ := g.credential(rt)
		out = append(out, entry{Route: "/" + name, Upstream: rt.Upstream, Configured: c != nil})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "routes": out})
}

// validSubpath rejects anything that could be normalised by the upstream into
// a different path than the one checked against allow_paths.
func validSubpath(p string) (string, bool) {
	low := strings.ToLower(p)
	for _, bad := range []string{"%2e", "%2f", "%5c", "%00", "\\"} {
		if strings.Contains(low, bad) {
			return "", false
		}
	}
	segs := strings.Split(p[1:], "/")
	for i, s := range segs {
		if s == "." || s == ".." || (s == "" && i != len(segs)-1) {
			return "", false
		}
	}
	return p, true
}

func allowedPath(allow []string, p string) bool {
	if len(allow) == 0 {
		return true
	}
	for _, a := range allow {
		a = strings.TrimSuffix(a, "/")
		if p == a || strings.HasPrefix(p, a+"/") {
			return true
		}
	}
	return false
}

func safeLogPath(sub, rest string) string {
	if sub != "" {
		return sub
	}
	if len(rest) > 80 {
		rest = rest[:80] + "..."
	}
	return "/" + strconv.Quote(rest)
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (s *statusRecorder) WriteHeader(code int) { s.status = code; s.ResponseWriter.WriteHeader(code) }
func (s *statusRecorder) Write(b []byte) (int, error) {
	n, err := s.ResponseWriter.Write(b)
	s.bytes += int64(n)
	return n, err
}
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

func jsonError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"type": "error", "error": map[string]string{"type": "gateway_error", "message": msg}})
}

// ---------------------------------------------------------------------------
// Relay: fixed TCP forwards + allow-listed egress proxy. No secrets here.
// ---------------------------------------------------------------------------

func runRelay(proxyListen string) {
	fwds, err := parseForwards(os.Getenv("RE_FORWARDS"))
	if err != nil {
		log.Fatalf("RE_FORWARDS: %v", err)
	}
	_, proxyPort, _ := net.SplitHostPort(proxyListen)
	for _, f := range fwds {
		if strconv.Itoa(f.port) == proxyPort {
			log.Fatalf("RE_FORWARDS: port %d collides with the egress proxy", f.port)
		}
		go f.serve()
	}

	ep := newEgressProxy(os.Getenv("RE_EGRESS_DOMAINS"), os.Getenv("RE_EGRESS_PORTS"))
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		list := []string{}
		for _, f := range fwds {
			list = append(list, fmt.Sprintf("%d=%s", f.port, f.target))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "forwards": list, "egress_domains": ep.domains})
	})
	srv := &http.Server{
		Addr:              proxyListen,
		ReadHeaderTimeout: 30 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodConnect && !r.URL.IsAbs() {
				mux.ServeHTTP(w, r)
				return
			}
			ep.ServeHTTP(w, r)
		}),
	}
	log.Printf("relay: egress proxy on %s, allowed domains: %v", proxyListen, ep.domains)
	log.Fatal(srv.ListenAndServe())
}

type forward struct {
	port   int
	target string
}

func parseForwards(s string) ([]forward, error) {
	var out []forward
	seen := map[int]bool{}
	for _, item := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' }) {
		lp, target, ok := strings.Cut(item, "=")
		port, err := strconv.Atoi(lp)
		if !ok || err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("bad entry %q (want LISTEN_PORT=HOST:PORT)", item)
		}
		if _, _, err := net.SplitHostPort(target); err != nil {
			return nil, fmt.Errorf("bad target in %q: %v", item, err)
		}
		if seen[port] {
			return nil, fmt.Errorf("duplicate listen port %d", port)
		}
		seen[port] = true
		out = append(out, forward{port: port, target: target})
	}
	return out, nil
}

func (f forward) serve() {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", f.port))
	if err != nil {
		log.Fatalf("forward %d: %v", f.port, err)
	}
	log.Printf("forward relay:%d -> %s", f.port, f.target)
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("forward %d: accept: %v", f.port, err)
			time.Sleep(200 * time.Millisecond)
			continue
		}
		go func() {
			defer c.Close()
			up, err := net.DialTimeout("tcp", f.target, 10*time.Second)
			if err != nil {
				log.Printf("forward %d -> %s: %v", f.port, f.target, err)
				return
			}
			defer up.Close()
			start := time.Now()
			in, out := pipe(c, up)
			log.Printf("forward %d -> %s closed: up %dB down %dB %s", f.port, f.target, in, out, time.Since(start).Round(time.Millisecond))
		}()
	}
}

// pipe copies both directions until both sides are done; returns a->b, b->a byte counts.
func pipe(a, b net.Conn) (int64, int64) {
	var wg sync.WaitGroup
	var ab, ba int64
	cp := func(dst, src net.Conn, n *int64) {
		defer wg.Done()
		*n, _ = io.Copy(dst, src)
		if tc, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = tc.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}
	wg.Add(2)
	go cp(b, a, &ab)
	go cp(a, b, &ba)
	wg.Wait()
	return ab, ba
}

type egressProxy struct {
	domains   []string
	ports     map[string]bool
	dialer    *net.Dialer
	transport *http.Transport
	rp        *httputil.ReverseProxy
}

func newEgressProxy(domains, ports string) *egressProxy {
	p := &egressProxy{ports: map[string]bool{}, domains: []string{}}
	for _, d := range strings.FieldsFunc(strings.ToLower(domains), func(r rune) bool { return r == ',' || r == ' ' || r == '\n' }) {
		d = strings.TrimSuffix(strings.TrimPrefix(d, "*"), ".")
		if d != "" && d != "." {
			p.domains = append(p.domains, d)
		}
	}
	sort.Strings(p.domains)
	if strings.TrimSpace(ports) == "" {
		ports = "443,80"
	}
	for _, pt := range strings.Split(ports, ",") {
		p.ports[strings.TrimSpace(pt)] = true
	}
	p.dialer = &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second, Control: publicOnly}
	p.transport = &http.Transport{Proxy: nil, DialContext: p.dialer.DialContext, ForceAttemptHTTP2: false,
		TLSHandshakeTimeout: 15 * time.Second, IdleConnTimeout: 60 * time.Second}
	p.rp = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL = pr.In.URL
			pr.Out.Host = pr.In.URL.Host
			pr.Out.Header.Del("Proxy-Authorization")
			pr.Out.Header.Del("Proxy-Connection")
		},
		Transport:     p.transport,
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, "relay: "+err.Error(), http.StatusBadGateway)
		},
	}
	return p
}

func (p *egressProxy) allowed(hostport, defPort string) (string, bool) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		host, port = hostport, defPort
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if !p.ports[port] || net.ParseIP(host) != nil {
		return host, false // ports are allow-listed; raw IPs are never allowed
	}
	for _, d := range p.domains {
		if strings.HasPrefix(d, ".") {
			if strings.HasSuffix(host, d) || host == d[1:] {
				return host, true
			}
		} else if host == d {
			return host, true
		}
	}
	return host, false
}

func (p *egressProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		host, ok := p.allowed(r.Host, "443")
		if !ok {
			log.Printf("egress DENY CONNECT %s", r.Host)
			http.Error(w, "relay: destination not in RE_EGRESS_DOMAINS", http.StatusForbidden)
			return
		}
		up, err := p.dialer.DialContext(r.Context(), "tcp", r.Host)
		if err != nil {
			log.Printf("egress CONNECT %s: %v", host, err)
			http.Error(w, "relay: "+err.Error(), http.StatusBadGateway)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			up.Close()
			http.Error(w, "relay: hijack unsupported", http.StatusInternalServerError)
			return
		}
		c, buf, err := hj.Hijack()
		if err != nil {
			up.Close()
			return
		}
		_, _ = c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		if n := buf.Reader.Buffered(); n > 0 {
			_, _ = io.CopyN(up, buf, int64(n))
		}
		log.Printf("egress CONNECT %s", r.Host)
		go func() {
			defer c.Close()
			defer up.Close()
			pipe(c, up)
		}()
		return
	}
	if r.URL.Scheme != "http" {
		http.Error(w, "relay: only CONNECT and plain http:// proxy requests", http.StatusBadRequest)
		return
	}
	if _, ok := p.allowed(r.URL.Host, "80"); !ok {
		log.Printf("egress DENY %s %s", r.Method, r.URL.Host)
		http.Error(w, "relay: destination not in RE_EGRESS_DOMAINS", http.StatusForbidden)
		return
	}
	log.Printf("egress %s http://%s%s", r.Method, r.URL.Host, r.URL.Path)
	p.rp.ServeHTTP(w, r)
}

var nonPublicNets = func() []*net.IPNet {
	var out []*net.IPNet
	for _, c := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
		"198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3",
		"::/128", "::1/128", "64:ff9b::/96", "100::/64", "2001:db8::/32", "fc00::/7", "fe80::/10", "ff00::/8",
	} {
		_, n, _ := net.ParseCIDR(c)
		out = append(out, n)
	}
	return out
}()

// publicOnly runs on the resolved address right before connect(), so DNS
// rebinding cannot steer an allow-listed name to the host or the LAN.
func publicOnly(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("unparseable address %q", host)
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	for _, n := range nonPublicNets {
		if n.Contains(ip) {
			return fmt.Errorf("egress to non-public address %s blocked", ip)
		}
	}
	return nil
}
