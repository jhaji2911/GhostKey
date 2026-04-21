package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/jhaji2911/GhostKey/internal/audit"
	"github.com/jhaji2911/GhostKey/internal/config"
	"github.com/jhaji2911/GhostKey/internal/vault"
)

// TestEndToEndHTTPSInterception is the primary integration test.
//
// It:
//  1. Starts a test HTTPS server.
//  2. Starts GhostKey with a test CA that trusts that server.
//  3. Creates an HTTP client that routes through the GhostKey proxy.
//  4. Issues a request with Authorization: Bearer GHOST::test-key.
//  5. Asserts the upstream received the real token.
//  6. Asserts the audit log contains the ghost token.
//  7. Asserts the real token never appears in the audit log.
func TestEndToEndHTTPSInterception(t *testing.T) {
	// ------------------------------------------------------------------
	// 1. Upstream test server: records what Authorization header it sees.
	// ------------------------------------------------------------------
	receivedAuth := make(chan string, 1)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case receivedAuth <- r.Header.Get("Authorization"):
		default:
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer upstream.Close()

	// ------------------------------------------------------------------
	// 2. GhostKey CA and vault.
	// ------------------------------------------------------------------
	caCert, caKey, err := GenerateSelfSignedCA()
	if err != nil {
		t.Fatal(err)
	}
	ca := &CAManager{caCert: caCert, caKey: caKey}

	v := vault.NewMemoryVault()
	v.Register("GHOST::test-key", "REAL_SECRET_TEST")

	// ------------------------------------------------------------------
	// 3. Auditor writing to a temp file.
	// ------------------------------------------------------------------
	dir := t.TempDir()
	auditPath := dir + "/audit.ndjson"
	a, err := audit.New(true, auditPath)
	if err != nil {
		t.Fatal(err)
	}

	// ------------------------------------------------------------------
	// 4. Start GhostKey proxy on an ephemeral port.
	// ------------------------------------------------------------------
	cfg := &config.Config{
		Proxy: config.ProxyConfig{ListenAddr: "127.0.0.1:0", ReadTimeout: 10, WriteTimeout: 10},
		Audit: config.AuditConfig{Enabled: true, FilePath: auditPath},
	}

	logger := zap.NewNop()
	p := New(cfg, v, ca, a, logger)
	// Allow the proxy's upstream dialer to trust the httptest self-signed cert.
	p.upstreamTLSConf = &tls.Config{InsecureSkipVerify: true} //nolint:gosec

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go p.server.Serve(ln) //nolint:errcheck
	defer func() { _ = p.server.Close() }()
	proxyAddr := ln.Addr().String()

	// ------------------------------------------------------------------
	// 5. Build an HTTP client that routes through GhostKey and trusts both
	//    GhostKey's CA (for MITM) and the test server's self-signed cert.
	// ------------------------------------------------------------------
	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)
	for _, c := range upstream.TLS.Certificates {
		if leaf, parseErr := x509.ParseCertificate(c.Certificate[0]); parseErr == nil {
			caPool.AddCert(leaf)
		}
	}

	proxyURL, _ := url.Parse("http://" + proxyAddr)
	transport := &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: caPool},
	}
	client := &http.Client{Transport: transport}

	// ------------------------------------------------------------------
	// 6. Make the request with a ghost token.
	// ------------------------------------------------------------------
	req, _ := http.NewRequest("POST", upstream.URL+"/v1/chat", strings.NewReader(`{"prompt":"hello"}`))
	req.Header.Set("Authorization", "Bearer GHOST::test-key")
	req.Header.Set("Content-Type", "application/json")

	resp, doErr := client.Do(req)
	if doErr != nil {
		t.Fatalf("client.Do: %v", doErr)
	}
	defer func() { _ = resp.Body.Close() }()

	// ------------------------------------------------------------------
	// 7. Assertions.
	// ------------------------------------------------------------------
	select {
	case auth := <-receivedAuth:
		if auth != "Bearer REAL_SECRET_TEST" {
			t.Errorf("upstream got Authorization %q, want %q", auth, "Bearer REAL_SECRET_TEST")
		}
	default:
		t.Error("upstream did not receive the request")
	}

	// Flush and read audit log
	_ = a.Close()
	logBytes, readErr := os.ReadFile(auditPath) //nolint:gosec // intentional: auditPath is a temp file created by the test
	if readErr != nil {
		t.Fatalf("read audit log: %v", readErr)
	}
	logContent := string(logBytes)

	if !strings.Contains(logContent, "GHOST::test-key") {
		t.Error("audit log should contain the ghost token")
	}
	if strings.Contains(logContent, "REAL_SECRET_TEST") {
		t.Errorf("audit log must NEVER contain the real token; got: %s", logContent)
	}
}
