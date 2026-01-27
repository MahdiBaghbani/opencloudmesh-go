// Package tls provides TLS certificate management for HTTP servers.
package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	cryptotls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

var (
	ErrACMENotImplemented = errors.New("tls.mode=acme is not implemented; use static or selfsigned")
	ErrInvalidTLSMode     = errors.New("invalid TLS mode")
	ErrMissingCert        = errors.New("missing certificate or key file")
)

// TLSManager handles TLS certificate loading and generation.
type TLSManager struct {
	cfg    *config.TLSConfig
	logger *slog.Logger
}

// NewTLSManager creates a new TLS manager.
func NewTLSManager(cfg *config.TLSConfig, logger *slog.Logger) *TLSManager {
	return &TLSManager{cfg: cfg, logger: logger}
}

// GetTLSConfig returns a tls.Config based on the configured mode.
// Returns nil for "off" mode.
func (m *TLSManager) GetTLSConfig(hostname string) (*cryptotls.Config, error) {
	switch m.cfg.Mode {
	case "off":
		return nil, nil

	case "static":
		return m.loadStaticCert()

	case "selfsigned":
		return m.getOrCreateSelfSigned(hostname)

	case "acme":
		return m.getACMEConfig()

	default:
		return nil, fmt.Errorf("%w: %s", ErrInvalidTLSMode, m.cfg.Mode)
	}
}

// loadStaticCert loads a certificate from files.
func (m *TLSManager) loadStaticCert() (*cryptotls.Config, error) {
	if m.cfg.CertFile == "" || m.cfg.KeyFile == "" {
		return nil, ErrMissingCert
	}

	cert, err := cryptotls.LoadX509KeyPair(m.cfg.CertFile, m.cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %w", err)
	}

	m.logger.Info("loaded static TLS certificate",
		"cert_file", m.cfg.CertFile,
		"key_file", m.cfg.KeyFile)

	return &cryptotls.Config{
		Certificates: []cryptotls.Certificate{cert},
		MinVersion:   cryptotls.VersionTLS12,
	}, nil
}

// getOrCreateSelfSigned loads or generates a self-signed certificate.
func (m *TLSManager) getOrCreateSelfSigned(hostname string) (*cryptotls.Config, error) {
	dir := m.cfg.SelfSignedDir
	if dir == "" {
		dir = ".ocm/certs"
	}

	certFile := filepath.Join(dir, "server.crt")
	keyFile := filepath.Join(dir, "server.key")

	// Try to load existing cert
	if cert, err := cryptotls.LoadX509KeyPair(certFile, keyFile); err == nil {
		m.logger.Info("loaded existing self-signed certificate",
			"cert_file", certFile)
		return &cryptotls.Config{
			Certificates: []cryptotls.Certificate{cert},
			MinVersion:   cryptotls.VersionTLS12,
		}, nil
	}

	// Generate new self-signed cert
	m.logger.Info("generating self-signed certificate", "hostname", hostname)

	cert, err := m.generateSelfSigned(hostname, certFile, keyFile)
	if err != nil {
		return nil, err
	}

	return &cryptotls.Config{
		Certificates: []cryptotls.Certificate{cert},
		MinVersion:   cryptotls.VersionTLS12,
	}, nil
}

// generateSelfSigned creates a new self-signed certificate.
func (m *TLSManager) generateSelfSigned(hostname, certFile, keyFile string) (cryptotls.Certificate, error) {
	// Generate private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return cryptotls.Certificate{}, fmt.Errorf("failed to generate key: %w", err)
	}

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return cryptotls.Certificate{}, fmt.Errorf("failed to generate serial: %w", err)
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"OpenCloudMesh Development"},
			CommonName:   hostname,
		},
		NotBefore:             now,
		NotAfter:              now.Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Add hostnames
	if ip := net.ParseIP(hostname); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	} else {
		template.DNSNames = append(template.DNSNames, hostname)
	}

	// Always add localhost for development
	template.DNSNames = append(template.DNSNames, "localhost")
	template.IPAddresses = append(template.IPAddresses, net.ParseIP("127.0.0.1"), net.ParseIP("::1"))

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return cryptotls.Certificate{}, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(certFile), 0700); err != nil {
		return cryptotls.Certificate{}, fmt.Errorf("failed to create cert directory: %w", err)
	}

	// Write certificate
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		return cryptotls.Certificate{}, fmt.Errorf("failed to write certificate: %w", err)
	}

	// Write private key
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return cryptotls.Certificate{}, fmt.Errorf("failed to marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		return cryptotls.Certificate{}, fmt.Errorf("failed to write key: %w", err)
	}

	m.logger.Info("generated self-signed certificate",
		"cert_file", certFile,
		"key_file", keyFile,
		"expires", template.NotAfter)

	return cryptotls.X509KeyPair(certPEM, keyPEM)
}

// getACMEConfig returns TLS config for ACME mode.
// This is a placeholder - full ACME implementation uses lego.
func (m *TLSManager) getACMEConfig() (*cryptotls.Config, error) {
	// For now, return a config that will be populated by the ACME manager
	// The actual certificate fetching is done by the ACMEManager
	m.logger.Info("ACME mode enabled",
		"domain", m.cfg.ACME.Domain,
		"email", m.cfg.ACME.Email,
		"staging", m.cfg.ACME.UseStaging)

	return &cryptotls.Config{
		MinVersion: cryptotls.VersionTLS12,
		// GetCertificate will be set by ACMEManager
	}, nil
}
