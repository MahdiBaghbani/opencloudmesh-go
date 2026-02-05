// Package ca_pool tests outbound client TLS root CA pool behavior.
//
// Verifies that a client with tls_root_ca_file connects to an HTTPS server
// signed by that CA without InsecureSkipVerify. Run:
//   go test -v ./tests/ca_pool/...
package ca_pool

import (
	"context"
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
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	tlspkg "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/tls"
)

const (
	caCertAsset = "testdata/certificate-authority/dockypody.crt"
	caKeyAsset  = "testdata/certificate-authority/dockypody.key"
)

// TestOutboundClient_WithRootCA verifies that a client configured with
// tls_root_ca_file connects to an HTTPS server whose certificate is signed
// by that CA, without InsecureSkipVerify.
func TestOutboundClient_WithRootCA(t *testing.T) {
	testDir := getTestDir(t)
	caFile := filepath.Join(testDir, caCertAsset)
	caKeyFile := filepath.Join(testDir, caKeyAsset)

	rootCAPool, err := tlspkg.BuildRootCAPool(caFile, "")
	if err != nil {
		t.Fatalf("BuildRootCAPool failed: %v", err)
	}
	if rootCAPool == nil {
		t.Fatal("expected non-nil pool")
	}

	caCertPEM, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatalf("read CA cert: %v", err)
	}
	caKeyPEM, err := os.ReadFile(caKeyFile)
	if err != nil {
		t.Fatalf("read CA key: %v", err)
	}
	caCertBlock, _ := pem.Decode(caCertPEM)
	if caCertBlock == nil {
		t.Fatal("failed to decode CA cert PEM")
	}
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	caKeyBlock, _ := pem.Decode(caKeyPEM)
	if caKeyBlock == nil {
		t.Fatal("failed to decode CA key PEM")
	}
	caKeyRaw, err := x509.ParsePKCS8PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		caKeyRaw, err = x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)
		if err != nil {
			t.Fatalf("parse CA key: %v", err)
		}
	}

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverCertDER, err := createServerCert(caCert, caKeyRaw, serverKey)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}
	serverCert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCertDER}),
		pemEncodeECKey(serverKey),
	)
	if err != nil {
		t.Fatalf("load server cert: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port

	srv := &http.Server{
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			MinVersion:   tls.VersionTLS12,
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("ok"))
		}),
	}
	go srv.ServeTLS(listener, "", "")
	defer srv.Close()

	time.Sleep(50 * time.Millisecond)

	cfg := &config.OutboundHTTPConfig{
		SSRFMode:           "off",
		TimeoutMS:          5000,
		InsecureSkipVerify: false,
	}
	client := httpclient.New(cfg, rootCAPool)

	url := fmt.Sprintf("https://127.0.0.1:%d/", port)
	resp, err := client.Get(context.Background(), url)
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func getTestDir(t *testing.T) string {
	t.Helper()
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Dir(filename)
}

func createServerCert(caCert *x509.Certificate, caKey interface{}, serverKey *ecdsa.PrivateKey) ([]byte, error) {
	template := x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	return x509.CreateCertificate(rand.Reader, &template, caCert, &serverKey.PublicKey, caKey)
}

func pemEncodeECKey(key *ecdsa.PrivateKey) []byte {
	der, _ := x509.MarshalECPrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}
