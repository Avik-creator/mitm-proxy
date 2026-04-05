package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync"
	"time"
)

// CA holds the root certificate authority used to sign per-host certificates.
type CA struct {
	cert     *x509.Certificate
	key      *ecdsa.PrivateKey
	tlsCert  tls.Certificate
	certPool *x509.CertPool

	mu    sync.RWMutex
	cache map[string]*tls.Certificate
}

// New creates a CA by loading an existing cert/key pair, or generating a new one
// and persisting it to certFile/keyFile.
func New(certFile, keyFile string) (*CA, error) {
	if _, err := os.Stat(certFile); err == nil {
		return loadFromFiles(certFile, keyFile)
	}
	return generateAndSave(certFile, keyFile)
}

func loadFromFiles(certFile, keyFile string) (*CA, error) {
	tlsCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load CA keypair: %w", err)
	}
	x509Cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}
	ecKey, ok := tlsCert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("CA key is not ECDSA")
	}
	pool := x509.NewCertPool()
	pool.AddCert(x509Cert)
	return &CA{cert: x509Cert, key: ecKey, tlsCert: tlsCert, certPool: pool, cache: make(map[string]*tls.Certificate)}, nil
}

func generateAndSave(certFile, keyFile string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "MITM Proxy CA", Organization: []string{"MITM Proxy"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	if err := writePEM(certFile, "CERTIFICATE", certDER); err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := writePEM(keyFile, "EC PRIVATE KEY", keyDER); err != nil {
		return nil, err
	}
	fmt.Printf("[CA] Generated new root CA → %s\n    Trust this cert in your OS/browser to avoid TLS warnings.\n", certFile)
	return loadFromFiles(certFile, keyFile)
}

// TLSConfigForHost returns a *tls.Config with a dynamically-signed leaf cert for host.
func (ca *CA) TLSConfigForHost(host string) (*tls.Config, error) {
	cert, err := ca.leafCert(host)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"h2", "http/1.1"},
	}, nil
}

func (ca *CA) leafCert(host string) (*tls.Certificate, error) {
	ca.mu.RLock()
	if c, ok := ca.cache[host]; ok {
		ca.mu.RUnlock()
		return c, nil
	}
	ca.mu.RUnlock()

	ca.mu.Lock()
	defer ca.mu.Unlock()
	if c, ok := ca.cache[host]; ok {
		return c, nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}
	x509Cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}
	tlsCert := &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
		Leaf:        x509Cert,
	}
	ca.cache[host] = tlsCert
	return tlsCert, nil
}

// CertPool returns the CA's cert pool (useful for clients that need to trust it).
func (ca *CA) CertPool() *x509.CertPool { return ca.certPool }

func writePEM(file, pemType string, der []byte) error {
	f, err := os.Create(file)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: pemType, Bytes: der})
}
