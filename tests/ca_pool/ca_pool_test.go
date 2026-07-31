// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package ca_pool tests outbound client TLS root CA pool behavior.
//
// Verifies that a client with tls_root_ca_file connects to an HTTPS server
// signed by that CA without InsecureSkipVerify. Run:
//
//	go test -v ./tests/ca_pool/...
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
	"errors"
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
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
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

	caCert, caKey := loadCAKeyPair(t, caFile, caKeyFile)
	port := startCATLSServer(t, caCert, caKey)

	cfg := &config.OutboundHTTPConfig{
		SSRF:               config.SSRFConfig{Mode: "off"},
		TimeoutMS:          tshttp.TestOutboundTimeoutMS,
		InsecureSkipVerify: false,
	}
	client := httpclient.New(cfg, rootCAPool)

	url := fmt.Sprintf("https://127.0.0.1:%d/", port)

	resp, err := client.Get(context.Background(), url) //nolint:bodyclose // response body closed inside shared tshttp.MustClose SSOT helper; bodyclose cannot trace close through helper
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	defer tshttp.MustClose(t, resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

// loadCAKeyPair reads and parses the test CA certificate and private key.
func loadCAKeyPair(t *testing.T, caFile, caKeyFile string) (*x509.Certificate, any) {
	t.Helper()

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

	return caCert, caKeyRaw
}

// startCATLSServer starts a TLS server on an ephemeral port with a certificate
// signed by the test CA, and returns the port.
func startCATLSServer(t *testing.T, caCert *x509.Certificate, caKey any) int {
	t.Helper()

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	serverCertDER, err := createServerCert(caCert, caKey, serverKey)
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

	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		if closeErr := listener.Close(); closeErr != nil {
			t.Logf("close CA listener: %v", closeErr)
		}
	})

	srv := &http.Server{ //nolint:gosec // test server: short-lived, no Slowloris risk
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			MinVersion:   tls.VersionTLS12,
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			tshttp.MustWrite(t, w, []byte("ok"))
		}),
	}

	go func() {
		if err := srv.ServeTLS(listener, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Logf("CA test server: %v", err)
		}
	}()

	t.Cleanup(func() {
		if closeErr := srv.Close(); closeErr != nil {
			t.Logf("close CA server: %v", closeErr)
		}
	})

	time.Sleep(50 * time.Millisecond)

	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("CA listener address type = %T, want *net.TCPAddr", listener.Addr())
	}

	return tcpAddr.Port
}

func getTestDir(t *testing.T) string {
	t.Helper()

	_, filename, _, _ := runtime.Caller(0) //nolint:dogsled // test: discarding multiple unneeded values

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
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		panic(err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}
