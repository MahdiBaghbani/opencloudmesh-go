package tls_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	tlspkg "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/tls"
)

func mustCreateCAPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestBuildRootCAPool_NilWhenBothEmpty(t *testing.T) {
	pool, err := tlspkg.BuildRootCAPool("", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pool != nil {
		t.Error("expected nil pool when both caFile and caDir are empty")
	}
}

func TestBuildRootCAPool_FileOnly(t *testing.T) {
	tmp := t.TempDir()
	caFile := filepath.Join(tmp, "ca.pem")
	pemData := mustCreateCAPEM(t)
	if err := os.WriteFile(caFile, pemData, 0644); err != nil {
		t.Fatal(err)
	}

	pool, err := tlspkg.BuildRootCAPool(caFile, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pool == nil {
		t.Fatal("expected non-nil pool")
	}
	// Pool should contain at least the system certs plus our cert
	if len(pool.Subjects()) == 0 {
		t.Error("expected pool to contain certificates")
	}
}

func TestBuildRootCAPool_DirOnly(t *testing.T) {
	tmp := t.TempDir()
	caPath := filepath.Join(tmp, "ca.crt")
	pemData := mustCreateCAPEM(t)
	if err := os.WriteFile(caPath, pemData, 0644); err != nil {
		t.Fatal(err)
	}

	pool, err := tlspkg.BuildRootCAPool("", tmp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pool == nil {
		t.Fatal("expected non-nil pool")
	}
	if len(pool.Subjects()) == 0 {
		t.Error("expected pool to contain certificates")
	}
}

func TestBuildRootCAPool_Merged(t *testing.T) {
	tmp := t.TempDir()
	caFile := filepath.Join(tmp, "ca1.pem")
	caDir := filepath.Join(tmp, "cadir")
	if err := os.MkdirAll(caDir, 0755); err != nil {
		t.Fatal(err)
	}
	pem1 := mustCreateCAPEM(t)
	pem2 := mustCreateCAPEM(t)
	if err := os.WriteFile(caFile, pem1, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(caDir, "ca2.pem"), pem2, 0644); err != nil {
		t.Fatal(err)
	}

	pool, err := tlspkg.BuildRootCAPool(caFile, caDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pool == nil {
		t.Fatal("expected non-nil pool")
	}
	if len(pool.Subjects()) < 2 {
		t.Errorf("expected pool to contain at least 2 certs (file + dir), got %d", len(pool.Subjects()))
	}
}

func TestBuildRootCAPool_InvalidFile(t *testing.T) {
	_, err := tlspkg.BuildRootCAPool("/nonexistent/path/ca.pem", "")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestBuildRootCAPool_InvalidPEM(t *testing.T) {
	tmp := t.TempDir()
	caFile := filepath.Join(tmp, "bad.pem")
	if err := os.WriteFile(caFile, []byte("not valid PEM"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := tlspkg.BuildRootCAPool(caFile, "")
	if err == nil {
		t.Fatal("expected error for file with no valid PEM certificates")
	}
}

func TestBuildRootCAPool_DirWithNonPEMFiles(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "readme.txt"), []byte("ignore me"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "data.bin"), []byte{0x00, 0x01}, 0644); err != nil {
		t.Fatal(err)
	}
	// No .pem or .crt files - should succeed with empty additions (only system pool)
	pool, err := tlspkg.BuildRootCAPool("", tmp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Pool exists (system pool or new empty-then-no-certs-added); non-PEM files are ignored
	if pool == nil {
		t.Fatal("expected non-nil pool (system pool)")
	}
}
