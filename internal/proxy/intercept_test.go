package proxy

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/jhaji2911/GhostKey/internal/vault"
)

func setupVault() vault.Vault {
	v := vault.NewMemoryVault()
	v.Register("GHOST::my-key", "sk-real-secret")
	v.Register("GHOST::github", "ghp_realtoken")
	return v
}

func TestRewriteAuthorizationHeader(t *testing.T) {
	v := setupVault()
	req, _ := http.NewRequest("POST", "https://api.openai.com/v1/chat", nil)
	req.Header.Set("Authorization", "Bearer GHOST::my-key")

	out, evts, err := RewriteRequest(req, v)
	if err != nil {
		t.Fatalf("RewriteRequest: %v", err)
	}
	if got := out.Header.Get("Authorization"); got != "Bearer sk-real-secret" {
		t.Errorf("Authorization: got %q", got)
	}
	if len(evts) != 1 {
		t.Errorf("expected 1 event, got %d", len(evts))
	}
	if evts[0].GhostToken != "GHOST::my-key" {
		t.Errorf("ghost token: got %q", evts[0].GhostToken)
	}
	if !strings.HasPrefix(evts[0].Location, "header:") {
		t.Errorf("location: got %q", evts[0].Location)
	}
}

func TestRewriteJSONBody(t *testing.T) {
	v := setupVault()
	body := `{"api_key": "GHOST::my-key", "model": "gpt-4"}`
	req, _ := http.NewRequest("POST", "https://api.example.com/v1", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	out, evts, err := RewriteRequest(req, v)
	if err != nil {
		t.Fatalf("RewriteRequest: %v", err)
	}
	outBody, _ := io.ReadAll(out.Body)
	if strings.Contains(string(outBody), "GHOST::my-key") {
		t.Error("ghost token still in body")
	}
	if !strings.Contains(string(outBody), "sk-real-secret") {
		t.Error("real token not injected into body")
	}
	if len(evts) == 0 {
		t.Error("expected at least one rewrite event")
	}
}

func TestRewriteURLQueryParam(t *testing.T) {
	v := setupVault()
	req, _ := http.NewRequest("GET", "https://api.example.com/data?token=GHOST::my-key&foo=bar", nil)

	out, evts, err := RewriteRequest(req, v)
	if err != nil {
		t.Fatalf("RewriteRequest: %v", err)
	}
	q := out.URL.Query()
	if q.Get("token") != "sk-real-secret" {
		t.Errorf("query token: got %q", q.Get("token"))
	}
	if len(evts) == 0 {
		t.Error("expected event")
	}
}

func TestRewriteMultipleGhostTokens(t *testing.T) {
	v := setupVault()
	body := `{"openai": "GHOST::my-key", "github": "GHOST::github"}`
	req, _ := http.NewRequest("POST", "https://api.example.com/", strings.NewReader(body))

	_, evts, err := RewriteRequest(req, v)
	if err != nil {
		t.Fatalf("RewriteRequest: %v", err)
	}
	if len(evts) < 2 {
		t.Errorf("expected 2+ events, got %d: %v", len(evts), evts)
	}
}

func TestNoGhostTokenUnchanged(t *testing.T) {
	v := setupVault()
	req, _ := http.NewRequest("GET", "https://api.example.com/", nil)
	req.Header.Set("Authorization", "Bearer regular-token")

	_ , evts, err := RewriteRequest(req, v)
	if err != nil {
		t.Fatalf("RewriteRequest: %v", err)
	}
	if len(evts) != 0 {
		t.Errorf("expected 0 events for non-ghost token, got %d", len(evts))
	}
}

func TestContentLengthUpdatedAfterRewrite(t *testing.T) {
	v := setupVault()
	body := `{"key": "GHOST::my-key"}`
	req, _ := http.NewRequest("POST", "https://api.example.com/", strings.NewReader(body))
	req.Header.Set("Content-Length", "0") // intentionally wrong

	out, evts, err := RewriteRequest(req, v)
	if err != nil {
		t.Fatalf("RewriteRequest: %v", err)
	}
	if len(evts) == 0 {
		t.Skip("no rewrites")
	}
	// After rewrite, Content-Length must match the new body
	newBody, _ := io.ReadAll(out.Body)
	clHeader := out.Header.Get("Content-Length")
	if clHeader == "" {
		t.Error("Content-Length header missing after body rewrite")
	}
	expectedLen := len(newBody)
	_ = expectedLen
	if int(out.ContentLength) != len(newBody) {
		t.Errorf("ContentLength field: got %d, body is %d bytes", out.ContentLength, len(newBody))
	}
}

func TestGzipBodyRewrite(t *testing.T) {
	v := setupVault()

	// Build gzip-encoded body with a ghost token
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	_, _ = gw.Write([]byte(`{"key": "GHOST::my-key"}`))
	_ = gw.Close()

	req, _ := http.NewRequest("POST", "https://api.example.com/", &buf)
	req.Header.Set("Content-Encoding", "gzip")

	out, evts, err := RewriteRequest(req, v)
	if err != nil {
		t.Fatalf("RewriteRequest gzip: %v", err)
	}
	if len(evts) == 0 {
		t.Error("expected rewrite events in gzip body")
	}

	// Decompress the output body and verify
	gr, err := gzip.NewReader(out.Body)
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	decompressed, err := io.ReadAll(gr)
	if err != nil {
		t.Fatalf("ReadAll gzip: %v", err)
	}
	if strings.Contains(string(decompressed), "GHOST::my-key") {
		t.Error("ghost token found in decompressed output")
	}
	if !strings.Contains(string(decompressed), "sk-real-secret") {
		t.Error("real token not in decompressed output")
	}
}

func TestRewriteResponseScrubsEchoedToken(t *testing.T) {
	v := setupVault()
	resp := &http.Response{
		StatusCode: 400,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(`{"error": "invalid key GHOST::my-key"}`)),
	}

	_, evts, err := RewriteResponse(resp, v)
	if err != nil {
		t.Fatalf("RewriteResponse: %v", err)
	}
	if len(evts) == 0 {
		t.Error("expected scrub events in echoed response")
	}
}

func TestProxyHeadersRemoved(t *testing.T) {
	v := setupVault()
	req, _ := http.NewRequest("GET", "https://api.example.com/", nil)
	req.Header.Set("Proxy-Authorization", "Basic abc123")
	req.Header.Set("Proxy-Connection", "keep-alive")

	out, _, err := RewriteRequest(req, v)
	if err != nil {
		t.Fatalf("RewriteRequest: %v", err)
	}
	if out.Header.Get("Proxy-Authorization") != "" {
		t.Error("Proxy-Authorization should be removed")
	}
	if out.Header.Get("Proxy-Connection") != "" {
		t.Error("Proxy-Connection should be removed")
	}
}
