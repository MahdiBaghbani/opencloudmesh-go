package tls

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	cryptotls "crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
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

// HTTP01Provider implements lego's challenge.Provider interface using an
// in-memory token store. The server owns the HTTP listener; lego never
// binds its own port.
type HTTP01Provider struct {
	tokens sync.Map // token -> keyAuthorization
}

func (p *HTTP01Provider) Present(domain, token, keyAuth string) error {
	p.tokens.Store(token, keyAuth)
	return nil
}

func (p *HTTP01Provider) CleanUp(domain, token, keyAuth string) error {
	p.tokens.Delete(token)
	return nil
}

// ACMEManager handles ACME certificate management using lego.
type ACMEManager struct {
	cfg        *config.ACMEConfig
	logger     *slog.Logger
	mu         sync.RWMutex
	cert       *cryptotls.Certificate
	legoClient *lego.Client
	user       *ACMEUser
	provider   *HTTP01Provider
	rootCAs    *x509.CertPool
}

// NewACMEManager creates a new ACME certificate manager.
// rootCAs is used for ACME directory communication; nil means system defaults.
func NewACMEManager(cfg *config.ACMEConfig, logger *slog.Logger, rootCAs *x509.CertPool) *ACMEManager {
	logger = logutil.NoopIfNil(logger)
	return &ACMEManager{
		cfg:     cfg,
		logger:  logger,
		rootCAs: rootCAs,
	}
}

// Init initializes the ACME manager: loads existing certificates without
// network calls when possible, or creates a lego client and obtains a new
// certificate from the ACME server.
func (m *ACMEManager) Init(ctx context.Context) error {
	if m.cfg.Domain == "" {
		return errors.New("ACME domain is required")
	}
	if m.cfg.Email == "" {
		return errors.New("ACME email is required")
	}

	if err := os.MkdirAll(m.cfg.StorageDir, 0700); err != nil {
		return fmt.Errorf("failed to create ACME storage dir: %w", err)
	}

	// Provider must be ready before anything else -- the challenge handler
	// may receive requests while we are still inside Init.
	m.provider = &HTTP01Provider{}

	// Fast path: existing cert means zero network calls.
	cert, err := m.loadCertificate()
	if err == nil {
		m.mu.Lock()
		m.cert = cert
		m.mu.Unlock()
		m.logger.Info("loaded existing ACME certificate", "domain", m.cfg.Domain)
		return nil
	}

	// Slow path: obtain a certificate from the ACME server.
	m.logger.Info("no existing certificate, contacting ACME server", "domain", m.cfg.Domain)

	user, err := m.loadOrCreateUser()
	if err != nil {
		return fmt.Errorf("failed to load/create ACME user: %w", err)
	}
	m.user = user

	serverURL := m.cfg.Directory
	if serverURL == "" {
		if m.cfg.UseStaging {
			serverURL = legoStagingURL
		} else {
			serverURL = legoProductionURL
		}
	}

	legoCfg := lego.NewConfig(user)
	legoCfg.CADirURL = serverURL
	legoCfg.Certificate.KeyType = certcrypto.EC256

	// Custom HTTP client so lego talks to the ACME directory through our CA pool.
	if m.rootCAs != nil {
		legoCfg.HTTPClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &cryptotls.Config{
					RootCAs:    m.rootCAs,
					MinVersion: cryptotls.VersionTLS12,
				},
			},
		}
	}

	client, err := lego.NewClient(legoCfg)
	if err != nil {
		return fmt.Errorf("failed to create ACME client: %w", err)
	}
	m.legoClient = client

	// Server-owned HTTP-01 provider (no lego-managed listener).
	if err := client.Challenge.SetHTTP01Provider(m.provider); err != nil {
		return fmt.Errorf("failed to set HTTP-01 provider: %w", err)
	}

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

	m.logger.Info("obtaining new ACME certificate", "domain", m.cfg.Domain)
	if err := m.obtainCertificate(); err != nil {
		return fmt.Errorf("failed to obtain certificate: %w", err)
	}

	return nil
}

// GetCertificate returns the current certificate for use with tls.Config.GetCertificate.
func (m *ACMEManager) GetCertificate(hello *cryptotls.ClientHelloInfo) (*cryptotls.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.cert == nil {
		return nil, errors.New("no certificate available")
	}
	return m.cert, nil
}

// GetTLSConfig returns a TLS config that uses this manager's certificates.
func (m *ACMEManager) GetTLSConfig() *cryptotls.Config {
	return &cryptotls.Config{
		GetCertificate: m.GetCertificate,
		MinVersion:     cryptotls.VersionTLS12,
	}
}

// ChallengeHandler returns an http.Handler that serves ACME HTTP-01 challenge
// responses at /.well-known/acme-challenge/{token}. Mount on the HTTP listener.
func (m *ACMEManager) ChallengeHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const prefix = "/.well-known/acme-challenge/"
		if !strings.HasPrefix(r.URL.Path, prefix) {
			http.NotFound(w, r)
			return
		}
		token := strings.TrimPrefix(r.URL.Path, prefix)
		if token == "" {
			http.NotFound(w, r)
			return
		}
		keyAuth, ok := m.provider.tokens.Load(token)
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, keyAuth.(string))
	})
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

func (m *ACMEManager) loadCertificate() (*cryptotls.Certificate, error) {
	certFile := filepath.Join(m.cfg.StorageDir, "cert.pem")
	keyFile := filepath.Join(m.cfg.StorageDir, "key.pem")

	cert, err := cryptotls.LoadX509KeyPair(certFile, keyFile)
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
	cert, err := cryptotls.X509KeyPair(certificates.Certificate, certificates.PrivateKey)
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
