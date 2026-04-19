// Package proxy implements GhostKey's TLS MITM certificate authority.
//
// GhostKey acts as a transparent man-in-the-middle proxy. When an AI agent
// issues an HTTPS CONNECT request, GhostKey:
//  1. Dynamically generates a leaf TLS certificate for the target hostname.
//  2. Presents this leaf cert to the agent (agent-side TLS).
//  3. Simultaneously establishes a fresh TLS connection to the real upstream.
//
// The agent must trust GhostKey's CA. Run 'ghostkey ca install' to install it.
//
// Security note:
//   - This MITM only works for agents that trust GhostKey's CA.
//   - GhostKey does NOT protect against OS-level attackers who can read the
//     GhostKey process memory.
//   - Use mTLS between GhostKey and upstream servers for additional protection.
package proxy

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CAManager handles dynamic certificate generation for MITM TLS interception.
// Generated leaf certificates are cached by hostname to avoid expensive regeneration
// on every request.
type CAManager struct {
	caCert *x509.Certificate
	caKey  crypto.PrivateKey
	cache  sync.Map // hostname (string) -> *tls.Certificate
}

// NewCAManager creates a CAManager.
// If certFile and keyFile are both non-empty, the CA is loaded from those files.
// If both are empty, a self-signed CA is generated and saved to ~/.ghostkey/ca.{crt,key}.
func NewCAManager(certFile, keyFile string) (*CAManager, error) {
	if certFile != "" && keyFile != "" {
		return loadCA(certFile, keyFile)
	}
	return generateAndSaveCA()
}

func loadCA(certFile, keyFile string) (*CAManager, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("tls: read CA cert %q: %w", certFile, err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("tls: read CA key %q: %w", keyFile, err)
	}

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("tls: parse CA key pair: %w", err)
	}
	caCert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("tls: parse CA cert DER: %w", err)
	}
	return &CAManager{caCert: caCert, caKey: tlsCert.PrivateKey}, nil
}

func generateAndSaveCA() (*CAManager, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("tls: home dir: %w", err)
	}
	dir := filepath.Join(home, ".ghostkey")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("tls: mkdir %q: %w", dir, err)
	}

	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	// Reuse existing CA if present and parseable
	if _, statErr := os.Stat(certPath); statErr == nil {
		if mgr, loadErr := loadCA(certPath, keyPath); loadErr == nil {
			return mgr, nil
		}
	}

	caCert, caKey, err := GenerateSelfSignedCA()
	if err != nil {
		return nil, fmt.Errorf("tls: generate CA: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return nil, fmt.Errorf("tls: write CA cert: %w", err)
	}

	keyBytes, err := x509.MarshalPKCS8PrivateKey(caKey)
	if err != nil {
		return nil, fmt.Errorf("tls: marshal CA key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return nil, fmt.Errorf("tls: write CA key: %w", err)
	}

	fmt.Printf("\n=== GhostKey CA Certificate Generated ===\n")
	fmt.Printf("Location: %s\n", certPath)
	fmt.Printf("Run 'ghostkey ca install' to add it to your system trust store.\n\n")

	return &CAManager{caCert: caCert, caKey: caKey}, nil
}

// GenerateSelfSignedCA creates a new RSA-2048 self-signed CA certificate valid 10 years.
// RSA-2048 is used for the CA for broad compatibility; leaf certs use ECDSA P-256.
func GenerateSelfSignedCA() (*x509.Certificate, crypto.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("tls: generate RSA-2048 key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("tls: generate serial: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "GhostKey CA",
			Organization: []string{"GhostKey"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("tls: create CA cert: %w", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("tls: parse generated CA cert: %w", err)
	}
	return cert, key, nil
}

// CertForHost returns a *tls.Certificate for the given hostname, valid for 24 hours.
// Certificates are cached by hostname; the cache entry is invalidated when the cert
// nears expiry (within 1 minute).
func (m *CAManager) CertForHost(host string) (*tls.Certificate, error) {
	if cached, ok := m.cache.Load(host); ok {
		cert := cached.(*tls.Certificate)
		if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
			if time.Now().Add(time.Minute).Before(leaf.NotAfter) {
				return cert, nil
			}
		}
		m.cache.Delete(host)
	}

	cert, err := m.generateLeaf(host)
	if err != nil {
		return nil, err
	}
	m.cache.Store(host, cert)
	return cert, nil
}

// generateLeaf creates an ECDSA P-256 leaf certificate for the given host, signed by the CA.
func (m *CAManager) generateLeaf(host string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("tls: generate ECDSA key for %q: %w", host, err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("tls: generate leaf serial: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	// Set SAN correctly — required for modern TLS/SNI
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, m.caCert, &key.PublicKey, m.caKey)
	if err != nil {
		return nil, fmt.Errorf("tls: sign leaf cert for %q: %w", host, err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("tls: marshal leaf key: %w", err)
	}

	tlsCert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		return nil, fmt.Errorf("tls: assemble leaf cert: %w", err)
	}
	return &tlsCert, nil
}

// CACertPEM returns the CA certificate encoded as PEM (for trust store installation).
func (m *CAManager) CACertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: m.caCert.Raw})
}

// CACertPath returns the default path where the auto-generated CA cert is saved.
func CACertPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".ghostkey", "ca.crt"), nil
}
