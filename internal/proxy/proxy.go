// Package proxy implements the GhostKey transparent MITM proxy.
//
// The proxy intercepts both plain HTTP and HTTPS (via CONNECT) traffic from AI agents,
// rewrites GHOST:: placeholder tokens with real credentials, and forwards the request
// to the upstream server — all transparently.
//
// Security properties:
//   - The AI agent only ever sees ghost tokens in its environment, logs, and context.
//   - Real credentials are substituted in-flight, never stored anywhere the agent can read.
//   - Every substitution is recorded in the tamper-evident audit log.
//
// Limitations (documented honestly):
//   - An attacker with OS-level access to this process can read real credentials.
//   - The GhostKey binary itself must be trusted.
//   - HTTP/2 push is not supported (connections are proxied as HTTP/1.1).
//   - Request bodies larger than 10 MB are not inspected for echoed tokens.
package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/jhaji2911/GhostKey/internal/audit"
	"github.com/jhaji2911/GhostKey/internal/config"
	"github.com/jhaji2911/GhostKey/internal/vault"
)

// Proxy is the core GhostKey MITM proxy server.
type Proxy struct {
	cfg             *config.Config
	vault           vault.Vault
	ca              *CAManager
	auditor         *audit.Auditor
	logger          *zap.Logger
	server          *http.Server
	upstreamTLSConf *tls.Config // nil uses system defaults; override in tests
}

// New creates a Proxy with the given dependencies.
func New(cfg *config.Config, v vault.Vault, ca *CAManager, a *audit.Auditor, logger *zap.Logger) *Proxy {
	p := &Proxy{
		cfg:     cfg,
		vault:   v,
		ca:      ca,
		auditor: a,
		logger:  logger,
	}
	p.server = &http.Server{
		Addr:         cfg.Proxy.ListenAddr,
		Handler:      p,
		ReadTimeout:  time.Duration(cfg.Proxy.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(cfg.Proxy.WriteTimeout) * time.Second,
	}
	return p
}

// Start begins accepting proxy connections. It blocks until the server is stopped.
func (p *Proxy) Start() error {
	p.logger.Info("ghostkey proxy starting", zap.String("addr", p.cfg.Proxy.ListenAddr))
	if err := p.server.ListenAndServe(); err != http.ErrServerClosed {
		return fmt.Errorf("proxy: listen: %w", err)
	}
	return nil
}

// Shutdown gracefully stops the proxy, waiting for in-flight requests to complete.
func (p *Proxy) Shutdown(ctx context.Context) error {
	p.logger.Info("ghostkey proxy shutting down")
	return p.server.Shutdown(ctx)
}

// ServeHTTP dispatches to handleCONNECT (HTTPS) or handleHTTP (plain HTTP).
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleCONNECT(w, r)
	} else {
		p.handleHTTP(w, r)
	}
}

// handleCONNECT intercepts HTTPS tunnels with full TLS MITM.
//
// Flow:
//  1. Receive CONNECT hostname:443 from agent.
//  2. Respond 200 Connection Established.
//  3. Hijack the TCP connection.
//  4. Generate/retrieve a leaf TLS cert for the hostname.
//  5. Wrap hijacked conn as TLS server (agent-side TLS session).
//  6. Dial upstream TLS connection.
//  7. For each HTTP/1.1 request from the agent:
//     a. Rewrite GHOST:: tokens.
//     b. Forward to upstream.
//     c. Scrub any echoed tokens from the response.
//     d. Emit audit event.
func (p *Proxy) handleCONNECT(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}

	// Send 200 before hijacking — this is the CONNECT tunnel established signal.
	w.WriteHeader(http.StatusOK)
	conn, brw, err := hijacker.Hijack()
	if err != nil {
		p.logger.Error("proxy: hijack", zap.String("host", host), zap.Error(err))
		return
	}
	defer func() { _ = conn.Close() }()
	// Flush any bytes buffered by the ResponseWriter (the 200 status line)
	// before we hand the raw conn to the TLS layer.
	if err := brw.Flush(); err != nil {
		p.logger.Error("proxy: flush hijack buffer", zap.Error(err))
		return
	}

	// Get a short-lived leaf cert for this hostname.
	leafCert, err := p.ca.CertForHost(hostWithoutPort(host))
	if err != nil {
		p.logger.Error("proxy: leaf cert", zap.String("host", host), zap.Error(err))
		return
	}

	// Agent-side TLS: the agent connects to GhostKey and trusts our CA.
	agentTLS := tls.Server(conn, &tls.Config{
		Certificates: []tls.Certificate{*leafCert},
		MinVersion:   tls.VersionTLS12,
	})
	if err := agentTLS.Handshake(); err != nil {
		p.logger.Debug("proxy: agent TLS handshake", zap.String("host", host), zap.Error(err))
		return
	}
	defer func() { _ = agentTLS.Close() }()

	// Server-side TLS: GhostKey connects to the real upstream.
	upConf := &tls.Config{
		ServerName: hostWithoutPort(host),
		MinVersion: tls.VersionTLS12,
	}
	if p.upstreamTLSConf != nil {
		upConf.InsecureSkipVerify = p.upstreamTLSConf.InsecureSkipVerify //nolint:gosec
		upConf.RootCAs = p.upstreamTLSConf.RootCAs
	}
	upstream, err := tls.Dial("tcp", ensureDefaultPort(host, "443"), upConf)
	if err != nil {
		p.logger.Error("proxy: upstream dial", zap.String("host", host), zap.Error(err))
		return
	}
	defer func() { _ = upstream.Close() }()

	// Process one HTTP/1.1 request at a time over the intercepted TLS session.
	agentReader := bufio.NewReader(agentTLS)
	for {
		req, readErr := http.ReadRequest(agentReader)
		if readErr != nil {
			if readErr != io.EOF {
				p.logger.Debug("proxy: read request", zap.String("host", host), zap.Error(readErr))
			}
			return
		}
		req.URL.Host = host
		req.URL.Scheme = "https"

		rewritten, reqEvts, rwErr := RewriteRequest(req, p.vault)
		if rwErr != nil {
			p.logger.Error("proxy: rewrite request", zap.Error(rwErr))
			return
		}

		if writeErr := rewritten.Write(upstream); writeErr != nil {
			p.logger.Error("proxy: write upstream", zap.Error(writeErr))
			return
		}

		resp, respErr := http.ReadResponse(bufio.NewReader(upstream), rewritten)
		if respErr != nil {
			p.logger.Error("proxy: read response", zap.Error(respErr))
			return
		}

		resp, respEvts, scrubErr := RewriteResponse(resp, p.vault)
		if scrubErr != nil {
			p.logger.Error("proxy: scrub response", zap.Error(scrubErr))
			_ = resp.Body.Close()
			return
		}

		// Audit BEFORE writing the response to the client so the log entry is
		// durable by the time client.Do() returns (avoids a race in tests and
		// ensures events are recorded even if the write-back fails).
		all := append(reqEvts, respEvts...)
		p.emitAudit(req, host, all)

		if writeErr := resp.Write(agentTLS); writeErr != nil {
			p.logger.Debug("proxy: write agent", zap.Error(writeErr))
			_ = resp.Body.Close()
			return
		}
		_ = resp.Body.Close()
	}
}

// handleHTTP forwards plain HTTP (port 80 or already-decrypted) requests.
func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	rewritten, reqEvts, err := RewriteRequest(r, p.vault)
	if err != nil {
		p.logger.Error("proxy: rewrite HTTP request", zap.Error(err))
		http.Error(w, "internal proxy error", http.StatusInternalServerError)
		return
	}

	// Sanitize request for forwarding
	rewritten.RequestURI = ""
	if rewritten.URL.Scheme == "" {
		rewritten.URL.Scheme = "http"
	}
	if rewritten.URL.Host == "" {
		rewritten.URL.Host = r.Host
	}

	rp := &httputil.ReverseProxy{
		Director: func(*http.Request) {}, // already configured above
		ModifyResponse: func(resp *http.Response) error {
			resp, respEvts, scrubErr := RewriteResponse(resp, p.vault)
			if scrubErr != nil {
				return scrubErr
			}
			all := append(reqEvts, respEvts...)
			p.emitAudit(r, r.Host, all)
			_ = resp
			return nil
		},
		ErrorHandler: func(rw http.ResponseWriter, req *http.Request, e error) {
			p.logger.Error("proxy: HTTP reverse proxy", zap.Error(e))
			http.Error(rw, "bad gateway", http.StatusBadGateway)
		},
	}
	rp.ServeHTTP(w, rewritten)
}

// emitAudit logs an interception event with ghost tokens (never real tokens).
func (p *Proxy) emitAudit(req *http.Request, upstream string, rewrites []RewriteEvent) {
	ghosts := make([]string, 0, len(rewrites))
	locs := make([]string, 0, len(rewrites))
	seen := make(map[string]bool, len(rewrites))
	for _, e := range rewrites {
		if !seen[e.GhostToken] {
			ghosts = append(ghosts, e.GhostToken)
			seen[e.GhostToken] = true
		}
		locs = append(locs, e.Location)
	}
	p.auditor.Log(audit.Event{
		EventType:   audit.EventIntercept,
		GhostTokens: ghosts,
		Upstream:    upstream,
		Method:      req.Method,
		Path:        req.URL.Path,
		Locations:   locs,
		Rewrites:    len(rewrites),
	})
}

// hostWithoutPort strips the port from a host:port string.
func hostWithoutPort(hostport string) string {
	h, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	return h
}

// ensureDefaultPort appends defaultPort if host has no port component.
func ensureDefaultPort(host, defaultPort string) string {
	if strings.Contains(host, ":") {
		return host
	}
	return host + ":" + defaultPort
}
