package proxy

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/jhaji2911/GhostKey/internal/vault"
)

// maxBodyInspectSize is the maximum body size that will be inspected for ghost tokens.
// Bodies larger than this are passed through unmodified to avoid unbounded memory use.
const maxBodyInspectSize = 10 * 1024 * 1024 // 10 MB

// RewriteEvent records a single token substitution. The real token is intentionally
// absent — this struct is only used for audit logging.
type RewriteEvent struct {
	// Location describes where the token was found, e.g.:
	//   "header:Authorization", "body", "url:query:api_key", "url:path"
	Location string
	// GhostToken is the ghost token that was replaced.
	GhostToken string
}

// RewriteRequest rewrites all ghost tokens in an outbound *http.Request.
// It inspects: URL path, URL query parameters, all request headers, and the body.
// A cloned request (with updated Content-Length) and a list of rewrite events are returned.
//
// The original request is not modified.
func RewriteRequest(req *http.Request, v vault.Vault) (*http.Request, []RewriteEvent, error) {
	var events []RewriteEvent
	out := req.Clone(req.Context())

	// --- URL query parameters ---
	q := out.URL.Query()
	queryChanged := false
	for key, vals := range q {
		for i, val := range vals {
			if rewritten, evts := rewriteString(val, v, "url:query:"+key); len(evts) > 0 {
				q[key][i] = rewritten
				events = append(events, evts...)
				queryChanged = true
			}
		}
	}
	if queryChanged {
		out.URL.RawQuery = q.Encode()
	}

	// --- URL path ---
	if rewritten, evts := rewriteString(out.URL.Path, v, "url:path"); len(evts) > 0 {
		out.URL.Path = rewritten
		events = append(events, evts...)
	}

	// --- Headers ---
	// Scan all headers, but scrub proxy control headers unconditionally.
	out.Header.Del("Proxy-Authorization")
	out.Header.Del("Proxy-Connection")

	for hdr, vals := range out.Header {
		if isHopByHopHeader(hdr) {
			continue
		}
		for i, val := range vals {
			if rewritten, evts := rewriteString(val, v, "header:"+hdr); len(evts) > 0 {
				out.Header[hdr][i] = rewritten
				events = append(events, evts...)
			}
		}
	}

	// --- Body ---
	if out.Body != nil && out.Body != http.NoBody {
		bodyEvents, newBody, newLen, err := rewriteBody(out.Body, out.Header.Get("Content-Encoding"), v)
		if err != nil {
			return nil, nil, fmt.Errorf("intercept: request body: %w", err)
		}
		out.Body = io.NopCloser(newBody)
		if len(bodyEvents) > 0 {
			out.ContentLength = int64(newLen)
			out.Header.Set("Content-Length", fmt.Sprintf("%d", newLen))
			events = append(events, bodyEvents...)
		}
	}

	return out, events, nil
}

// RewriteResponse scrubs any ghost tokens echoed back in a *http.Response.
// Some APIs echo the Authorization header in error responses.
//
// The response is modified in place; a list of rewrite events is returned.
func RewriteResponse(resp *http.Response, v vault.Vault) (*http.Response, []RewriteEvent, error) {
	var events []RewriteEvent

	// --- Response headers ---
	for hdr, vals := range resp.Header {
		for i, val := range vals {
			if rewritten, evts := rewriteString(val, v, "resp:header:"+hdr); len(evts) > 0 {
				resp.Header[hdr][i] = rewritten
				events = append(events, evts...)
			}
		}
	}

	// --- Response body ---
	if resp.Body != nil {
		bodyEvents, newBody, newLen, err := rewriteBody(resp.Body, resp.Header.Get("Content-Encoding"), v)
		if err != nil {
			return nil, nil, fmt.Errorf("intercept: response body: %w", err)
		}
		resp.Body = io.NopCloser(newBody)
		if len(bodyEvents) > 0 {
			resp.ContentLength = int64(newLen)
			resp.Header.Set("Content-Length", fmt.Sprintf("%d", newLen))
			events = append(events, bodyEvents...)
		}
	}

	return resp, events, nil
}

// rewriteString replaces all GHOST:: tokens in s with their real values from v.
// Returns the rewritten string and one RewriteEvent per substitution.
func rewriteString(s string, v vault.Vault, location string) (string, []RewriteEvent) {
	var events []RewriteEvent
	var b strings.Builder
	b.Grow(len(s))

	remaining := s
	for {
		loc := vault.GhostTokenScanRE.FindStringIndex(remaining)
		if loc == nil {
			b.WriteString(remaining)
			break
		}
		b.WriteString(remaining[:loc[0]])
		ghost := remaining[loc[0]:loc[1]]
		if real, ok := v.Resolve(ghost); ok {
			b.WriteString(real)
			events = append(events, RewriteEvent{Location: location, GhostToken: ghost})
		} else {
			// Unknown ghost token — pass through unchanged.
			b.WriteString(ghost)
		}
		remaining = remaining[loc[1]:]
	}

	if len(events) == 0 {
		return s, nil // no alloc if nothing changed
	}
	return b.String(), events
}

// rewriteBody reads the body, optionally decompresses it, rewrites ghost tokens,
// and returns a new *bytes.Reader along with the new byte length.
//
// If the body exceeds maxBodyInspectSize, it is passed through without inspection
// to avoid unbounded memory use. Content-Length is still updated to match.
//
// Gzip-encoded bodies are decompressed before scanning and recompressed afterward
// if any token is found.
func rewriteBody(body io.ReadCloser, encoding string, v vault.Vault) ([]RewriteEvent, *bytes.Reader, int, error) {
	defer func() { _ = body.Close() }()

	// Read up to maxBodyInspectSize+1 bytes to detect oversized bodies.
	limited := io.LimitReader(body, maxBodyInspectSize+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("intercept: read body: %w", err)
	}

	// Too large — skip inspection, return as-is.
	if len(raw) > maxBodyInspectSize {
		return nil, bytes.NewReader(raw), len(raw), nil
	}

	isGzip := strings.EqualFold(encoding, "gzip")

	var content []byte
	if isGzip {
		gr, gzErr := gzip.NewReader(bytes.NewReader(raw))
		if gzErr != nil {
			// Cannot decompress — pass through without inspection.
			return nil, bytes.NewReader(raw), len(raw), nil
		}
		content, err = io.ReadAll(gr)
		_ = gr.Close()
		if err != nil {
			return nil, bytes.NewReader(raw), len(raw), nil
		}
	} else {
		content = raw
	}

	rewritten, evts := rewriteString(string(content), v, "body")
	if len(evts) == 0 {
		return nil, bytes.NewReader(raw), len(raw), nil
	}

	var out []byte
	if isGzip {
		var buf bytes.Buffer
		gw := gzip.NewWriter(&buf)
		if _, gzErr := gw.Write([]byte(rewritten)); gzErr != nil {
			return nil, bytes.NewReader(raw), len(raw), nil
		}
		if gzErr := gw.Close(); gzErr != nil {
			return nil, bytes.NewReader(raw), len(raw), nil
		}
		out = buf.Bytes()
	} else {
		out = []byte(rewritten)
	}

	return evts, bytes.NewReader(out), len(out), nil
}

// isHopByHopHeader returns true for headers that must not be forwarded upstream.
func isHopByHopHeader(hdr string) bool {
	switch strings.ToLower(hdr) {
	case "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
		"proxy-connection", "te", "trailers", "transfer-encoding", "upgrade":
		return true
	}
	return false
}
