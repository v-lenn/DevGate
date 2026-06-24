package main

import (
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
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

var (
	caCertGlobal  *x509.Certificate
	caKeyGlobal   interface{}
	leafKeyGlobal *rsa.PrivateKey
	certCache     sync.Map // host -> *tls.Certificate
)

// generates/loads the Root CA and prepares the dynamic leaf-signing private key.
func initCertificates() error {
	if err := os.MkdirAll(getConfigDir(), 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	caCertPath := filepath.Join(getConfigDir(), "ca.crt")
	caKeyPath := filepath.Join(getConfigDir(), "ca.key")

	_, err1 := os.Stat(caCertPath)
	_, err2 := os.Stat(caKeyPath)
	if os.IsNotExist(err1) || os.IsNotExist(err2) {
		if err := generateCA(caCertPath, caKeyPath); err != nil {
			return fmt.Errorf("failed to generate CA: %w", err)
		}
	}

	caCertPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return fmt.Errorf("failed to read CA certificate: %w", err)
	}

	caKeyPEM, err := os.ReadFile(caKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read CA private key: %w", err)
	}

	cert, err := tls.X509KeyPair(caCertPEM, caKeyPEM)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate/key pair: %w", err)
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("failed to parse x509 CA certificate: %w", err)
	}

	caCertGlobal = x509Cert
	caKeyGlobal = cert.PrivateKey

	// pre-generate a shared leaf private key on startup to optimize signing performance
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate shared leaf key: %w", err)
	}
	leafKeyGlobal = key

	return nil
}

// generateCA creates a self-signed X.509 Root CA certificate valid for 10 years.
func generateCA(certPath, keyPath string) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "DevGate Development CA",
			Organization: []string{"DevGate Project"},
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0), // 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	certOut, err := os.Create(certPath)
	if err != nil {
		return err
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return err
	}

	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer keyOut.Close()
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		return err
	}

	return nil
}

// getCertificateForHost dynamically signs a certificate for the host if not already cached.
func getCertificateForHost(host string) (*tls.Certificate, error) {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	if val, ok := certCache.Load(host); ok {
		return val.(*tls.Certificate), nil
	}

	if caCertGlobal == nil || caKeyGlobal == nil || leafKeyGlobal == nil {
		return nil, fmt.Errorf("certificates system is not initialized")
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   host,
			Organization: []string{"DevGate Intercepted Server"},
		},
		NotBefore: time.Now().Add(-24 * time.Hour),
		NotAfter:  time.Now().AddDate(1, 0, 0), // 1 year
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCertGlobal, &leafKeyGlobal.PublicKey, caKeyGlobal)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	privBytes, err := x509.MarshalPKCS8PrivateKey(leafKeyGlobal)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	certCache.Store(host, &tlsCert)
	return &tlsCert, nil
}

// returns whether the ca certificate is trusted in the windows current user root store.
func isCATrusted() bool {
	cmd := exec.Command("certutil", "-verifystore", "-user", "Root", "DevGate Development CA")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	err := cmd.Run()
	return err == nil
}

// adds the root ca to the windows current user root store.
func trustCA() error {
	caCertPath := filepath.Join(getConfigDir(), "ca.crt")
	cmd := exec.Command("certutil", "-addstore", "-user", "Root", caCertPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Run()
}

// deletes the root ca from the windows current user root store.
func untrustCA() error {
	cmd := exec.Command("certutil", "-delstore", "-user", "Root", "DevGate Development CA")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Run()
}
