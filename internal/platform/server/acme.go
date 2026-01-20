package server

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/config"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

const (
	legoStagingURL    = "https://acme-staging-v02.api.letsencrypt.org/directory"
	legoProductionURL = "https://acme-v02.api.letsencrypt.org/directory"
)

// ACMEUser implements the lego User interface.
type ACMEUser struct {
	Email        string                 `json:"email"`
	Registration *registration.Resource `json:"registration"`
	key          crypto.PrivateKey
}

func (u *ACMEUser) GetEmail() string                        { return u.Email }
func (u *ACMEUser) GetRegistration() *registration.Resource { return u.Registration }
func (u *ACMEUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

// ACMEManager handles ACME certificate management using lego.
type ACMEManager struct {
	cfg           *config.ACMEConfig
	logger        *slog.Logger
	mu            sync.RWMutex
	cert          *tls.Certificate
	httpHandler   http.Handler
	legoClient    *lego.Client
	user          *ACMEUser
	challengePort int
}

// NewACMEManager creates a new ACME certificate manager.
func NewACMEManager(cfg *config.ACMEConfig, challengePort int, logger *slog.Logger) *ACMEManager {
	return &ACMEManager{
		cfg:           cfg,
		logger:        logger,
		challengePort: challengePort,
	}
}

// Init initializes the ACME client and loads or obtains a certificate.
func (m *ACMEManager) Init(ctx context.Context) error {
	if m.cfg.Domain == "" {
		return errors.New("ACME domain is required")
	}
	if m.cfg.Email == "" {
		return errors.New("ACME email is required")
	}

	// Ensure storage directory exists
	if err := os.MkdirAll(m.cfg.StorageDir, 0700); err != nil {
		return fmt.Errorf("failed to create ACME storage dir: %w", err)
	}

	// Load or create user
	user, err := m.loadOrCreateUser()
	if err != nil {
		return fmt.Errorf("failed to load/create ACME user: %w", err)
	}
	m.user = user

	// Determine ACME server URL
	serverURL := m.cfg.Directory
	if serverURL == "" {
		if m.cfg.UseStaging {
			serverURL = legoStagingURL
		} else {
			serverURL = legoProductionURL
		}
	}

	// Create lego config
	legoCfg := lego.NewConfig(user)
	legoCfg.CADirURL = serverURL
	legoCfg.Certificate.KeyType = certcrypto.EC256

	// Create lego client
	client, err := lego.NewClient(legoCfg)
	if err != nil {
		return fmt.Errorf("failed to create ACME client: %w", err)
	}
	m.legoClient = client

	// Set up HTTP-01 challenge provider
	httpProvider := http01.NewProviderServer("", fmt.Sprintf("%d", m.challengePort))
	if err := client.Challenge.SetHTTP01Provider(httpProvider); err != nil {
		return fmt.Errorf("failed to set HTTP-01 provider: %w", err)
	}

	// Register user if needed
	if user.Registration == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{
			TermsOfServiceAgreed: true,
		})
		if err != nil {
			return fmt.Errorf("failed to register ACME account: %w", err)
		}
		user.Registration = reg
		if err := m.saveUser(user); err != nil {
			m.logger.Warn("failed to save ACME user", "error", err)
		}
	}

	// Try to load existing certificate
	cert, err := m.loadCertificate()
	if err == nil {
		m.cert = cert
		m.logger.Info("loaded existing ACME certificate", "domain", m.cfg.Domain)
		return nil
	}

	// Obtain new certificate
	m.logger.Info("obtaining new ACME certificate", "domain", m.cfg.Domain)
	if err := m.obtainCertificate(); err != nil {
		return fmt.Errorf("failed to obtain certificate: %w", err)
	}

	return nil
}

// GetCertificate returns the current certificate for use with tls.Config.GetCertificate.
func (m *ACMEManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.cert == nil {
		return nil, errors.New("no certificate available")
	}
	return m.cert, nil
}

// GetTLSConfig returns a TLS config that uses this manager's certificates.
func (m *ACMEManager) GetTLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: m.GetCertificate,
		MinVersion:     tls.VersionTLS12,
	}
}

func (m *ACMEManager) loadOrCreateUser() (*ACMEUser, error) {
	userFile := filepath.Join(m.cfg.StorageDir, "account.json")
	keyFile := filepath.Join(m.cfg.StorageDir, "account.key")

	// Try to load existing user
	userData, err := os.ReadFile(userFile)
	if err == nil {
		keyData, keyErr := os.ReadFile(keyFile)
		if keyErr == nil {
			user := &ACMEUser{}
			if err := json.Unmarshal(userData, user); err == nil {
				// Parse key
				key, keyErr := certcrypto.ParsePEMPrivateKey(keyData)
				if keyErr == nil {
					user.key = key
					return user, nil
				}
			}
		}
	}

	// Create new user with new key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate account key: %w", err)
	}

	user := &ACMEUser{
		Email: m.cfg.Email,
		key:   privateKey,
	}

	return user, nil
}

func (m *ACMEManager) saveUser(user *ACMEUser) error {
	userFile := filepath.Join(m.cfg.StorageDir, "account.json")
	keyFile := filepath.Join(m.cfg.StorageDir, "account.key")

	// Save user data
	userData, err := json.MarshalIndent(user, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(userFile, userData, 0600); err != nil {
		return err
	}

	// Save key
	keyPEM := certcrypto.PEMEncode(user.key)
	return os.WriteFile(keyFile, keyPEM, 0600)
}

func (m *ACMEManager) loadCertificate() (*tls.Certificate, error) {
	certFile := filepath.Join(m.cfg.StorageDir, "cert.pem")
	keyFile := filepath.Join(m.cfg.StorageDir, "key.pem")

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

func (m *ACMEManager) obtainCertificate() error {
	request := certificate.ObtainRequest{
		Domains: []string{m.cfg.Domain},
		Bundle:  true,
	}

	certificates, err := m.legoClient.Certificate.Obtain(request)
	if err != nil {
		return err
	}

	// Save certificate
	certFile := filepath.Join(m.cfg.StorageDir, "cert.pem")
	keyFile := filepath.Join(m.cfg.StorageDir, "key.pem")

	if err := os.WriteFile(certFile, certificates.Certificate, 0644); err != nil {
		return fmt.Errorf("failed to save certificate: %w", err)
	}
	if err := os.WriteFile(keyFile, certificates.PrivateKey, 0600); err != nil {
		return fmt.Errorf("failed to save key: %w", err)
	}

	// Load the certificate
	cert, err := tls.X509KeyPair(certificates.Certificate, certificates.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	m.mu.Lock()
	m.cert = &cert
	m.mu.Unlock()

	m.logger.Info("obtained and saved ACME certificate",
		"domain", m.cfg.Domain,
		"cert_file", certFile)

	return nil
}
