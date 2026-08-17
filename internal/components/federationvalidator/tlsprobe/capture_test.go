// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package tlsprobe

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func TestCaptureTLS_HTTPSRecordsVersionCipherCertAndIP(t *testing.T) {
	t.Parallel()

	now := time.Now()
	leaf := &x509.Certificate{
		Subject:   pkix.Name{CommonName: "peer.example"},
		DNSNames:  []string{"peer.example", "alt.example"},
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(time.Hour),
	}

	state := &tls.ConnectionState{
		Version:            tls.VersionTLS13,
		CipherSuite:        tls.TLS_AES_128_GCM_SHA256,
		PeerCertificates:   []*x509.Certificate{leaf},
		ServerName:         "peer.example",
		NegotiatedProtocol: "http/1.1",
	}

	detail := CaptureTLS(Input{
		Scheme:   "https",
		TLSState: state,
		ServerIP: "203.0.113.10",
	})

	if detail.ServerIP != "203.0.113.10" {
		t.Fatalf("server IP = %q", detail.ServerIP)
	}

	if detail.TLSVersion != "TLS 1.3" {
		t.Fatalf("TLS version = %q", detail.TLSVersion)
	}

	if detail.CipherSuite == "" {
		t.Fatal("expected cipher suite label")
	}

	if !detail.CertValid {
		t.Fatal("expected valid cert window")
	}

	if detail.LeafCN != "peer.example" {
		t.Fatalf("leaf CN = %q", detail.LeafCN)
	}

	if len(detail.LeafSANs) != 2 {
		t.Fatalf("SAN count = %d, want 2", len(detail.LeafSANs))
	}
}

func TestCaptureTLS_PlainHTTPDoesNotInventTLS(t *testing.T) {
	t.Parallel()

	detail := CaptureTLS(Input{Scheme: "http", ServerIP: "203.0.113.10"})

	if detail.TLSVersion != "" || detail.CipherSuite != "" {
		t.Fatal("expected empty TLS fields on plain HTTP")
	}

	if detail.CertNotBefore != (time.Time{}) || detail.CertNotAfter != (time.Time{}) {
		t.Fatal("expected zero cert validity on plain HTTP")
	}

	grade := GradeTLS(detail, "http", nil)
	if grade != nil {
		t.Fatalf("grade = %v, want nil for plain HTTP", grade)
	}
}

func TestCaptureTLS_ErrorPathDoesNotPanic(t *testing.T) {
	t.Parallel()

	detail := CaptureTLS(Input{
		Scheme:   "https",
		FetchErr: errors.New("handshake failed"),
	})

	if len(detail.ReasonCodes) == 0 {
		t.Fatal("expected reason codes")
	}

	grade := GradeTLS(detail, "https", errors.New("handshake failed"))
	if grade == nil || *grade != validatorcore.GradeFail {
		t.Fatalf("grade = %v, want fail", grade)
	}
}

func TestGradeTLS_ExpiredCertFails(t *testing.T) {
	t.Parallel()

	now := time.Now()
	leaf := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "peer.example"},
		NotBefore:    now.Add(-48 * time.Hour),
		NotAfter:     now.Add(-24 * time.Hour),
		SerialNumber: big.NewInt(1),
	}

	state := &tls.ConnectionState{
		Version:          tls.VersionTLS12,
		CipherSuite:      tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		PeerCertificates: []*x509.Certificate{leaf},
	}

	detail := CaptureTLS(Input{Scheme: "https", TLSState: state})

	grade := GradeTLS(detail, "https", nil)
	if grade == nil || *grade != validatorcore.GradeFail {
		t.Fatalf("grade = %v, want fail", grade)
	}
}

func TestGradeTLS_ModernHTTPSPasses(t *testing.T) {
	t.Parallel()

	now := time.Now()
	leaf := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "peer.example"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		SerialNumber: big.NewInt(1),
	}

	state := &tls.ConnectionState{
		Version:          tls.VersionTLS13,
		CipherSuite:      tls.TLS_AES_128_GCM_SHA256,
		PeerCertificates: []*x509.Certificate{leaf},
	}

	detail := CaptureTLS(Input{Scheme: "https", TLSState: state})

	grade := GradeTLS(detail, "https", nil)
	if grade == nil || *grade != validatorcore.GradePass {
		t.Fatalf("grade = %v, want pass", grade)
	}
}

func TestGradeTLS_OldTLSVersionWarns(t *testing.T) {
	t.Parallel()

	now := time.Now()
	leaf := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "peer.example"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		SerialNumber: big.NewInt(1),
	}

	state := &tls.ConnectionState{
		Version:          tls.VersionTLS10,
		CipherSuite:      tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		PeerCertificates: []*x509.Certificate{leaf},
	}

	detail := CaptureTLS(Input{Scheme: "https", TLSState: state})

	grade := GradeTLS(detail, "https", nil)
	if grade == nil || *grade != validatorcore.GradeWarn {
		t.Fatalf("grade = %v, want warn", grade)
	}
}

func TestCaptureTLS_CertificateVerificationErrorClassifiesWrappedX509(t *testing.T) {
	t.Parallel()

	cert := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "peer.example"},
		SerialNumber: big.NewInt(1),
	}
	inner := x509.UnknownAuthorityError{Cert: cert}
	fetchErr := &tls.CertificateVerificationError{
		UnverifiedCertificates: []*x509.Certificate{cert},
		Err:                    inner,
	}

	detail := CaptureTLS(Input{
		Scheme:   "https",
		FetchErr: fetchErr,
	})

	if len(detail.ReasonCodes) != 1 || detail.ReasonCodes[0] != "x509_unknown_authority" {
		t.Fatalf("reason codes = %v, want x509_unknown_authority", detail.ReasonCodes)
	}

	grade := GradeTLS(detail, "https", fetchErr)
	if grade == nil || *grade != validatorcore.GradeFail {
		t.Fatalf("grade = %v, want fail", grade)
	}
}
