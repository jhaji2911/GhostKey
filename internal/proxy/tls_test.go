package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"
)

func TestGenerateSelfSignedCA(t *testing.T) {
	cert, key, err := GenerateSelfSignedCA()
	if err != nil {
		t.Fatalf("GenerateSelfSignedCA: %v", err)
	}
	if cert == nil {
		t.Fatal("cert is nil")
	}
	if key == nil {
		t.Fatal("key is nil")
	}
	if !cert.IsCA {
		t.Error("cert should be a CA")
	}
	if time.Now().Before(cert.NotBefore) || time.Now().After(cert.NotAfter) {
		t.Error("cert is not currently valid")
	}
}

func TestCAManagerCertForHost(t *testing.T) {
	caCert, caKey, err := GenerateSelfSignedCA()
	if err != nil {
		t.Fatalf("GenerateSelfSignedCA: %v", err)
	}
	mgr := &CAManager{caCert: caCert, caKey: caKey}

	cert, err := mgr.CertForHost("api.openai.com")
	if err != nil {
		t.Fatalf("CertForHost: %v", err)
	}
	if cert == nil {
		t.Fatal("cert is nil")
	}

	// Parse and verify the leaf cert
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if leaf.Subject.CommonName != "api.openai.com" {
		t.Errorf("CN: got %q", leaf.Subject.CommonName)
	}
	if len(leaf.DNSNames) == 0 || leaf.DNSNames[0] != "api.openai.com" {
		t.Errorf("SAN DNSNames: %v", leaf.DNSNames)
	}

	// Leaf must be signed by our CA
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	if _, verErr := leaf.Verify(x509.VerifyOptions{
		DNSName: "api.openai.com",
		Roots:   pool,
	}); verErr != nil {
		t.Errorf("leaf cert verify: %v", verErr)
	}
}

func TestCAManagerCertCached(t *testing.T) {
	caCert, caKey, err := GenerateSelfSignedCA()
	if err != nil {
		t.Fatalf("GenerateSelfSignedCA: %v", err)
	}
	mgr := &CAManager{caCert: caCert, caKey: caKey}

	first, err := mgr.CertForHost("example.com")
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	second, err := mgr.CertForHost("example.com")
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	// Same pointer — cached result
	if first != second {
		t.Error("expected cached cert to be returned on second call")
	}
}

func TestCAManagerLeafValidFor24h(t *testing.T) {
	caCert, caKey, err := GenerateSelfSignedCA()
	if err != nil {
		t.Fatalf("GenerateSelfSignedCA: %v", err)
	}
	mgr := &CAManager{caCert: caCert, caKey: caKey}
	cert, err := mgr.CertForHost("test.example.com")
	if err != nil {
		t.Fatalf("CertForHost: %v", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	duration := leaf.NotAfter.Sub(leaf.NotBefore)
	if duration < 23*time.Hour || duration > 25*time.Hour {
		t.Errorf("leaf validity: got %v, want ~24h", duration)
	}
}

func TestCACertPEM(t *testing.T) {
	caCert, caKey, err := GenerateSelfSignedCA()
	if err != nil {
		t.Fatalf("GenerateSelfSignedCA: %v", err)
	}
	mgr := &CAManager{caCert: caCert, caKey: caKey}
	pem := mgr.CACertPEM()
	if len(pem) == 0 {
		t.Error("CACertPEM should not be empty")
	}

	// Should be parseable
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Error("CACertPEM: not valid PEM cert")
	}

	// Suppress unused variable warning
	_ = caKey
	_ = tls.Certificate{}
}
