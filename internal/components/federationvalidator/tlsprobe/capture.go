// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package tlsprobe

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

const (
	schemeHTTP  = "http"
	schemeHTTPS = "https"
)

// ConnectionDetail holds report-only TLS connection metadata. It must not be
// copied into stats_raw rows.
type ConnectionDetail struct {
	ServerIP      string
	TLSVersion    string
	CipherSuite   string
	CertNotBefore time.Time
	CertNotAfter  time.Time
	CertValid     bool
	LeafCN        string
	LeafSANs      []string
	ReasonCodes   []string
}

// Input carries fetch-time TLS state for capture and grading.
type Input struct {
	Scheme   string
	TLSState *tls.ConnectionState
	ServerIP string
	FetchErr error
}

// CaptureTLS reads cheap TLS details from the actual connection state. Plain HTTP
// responses leave TLS fields empty and do not invent values.
func CaptureTLS(in Input) ConnectionDetail {
	detail := ConnectionDetail{
		ServerIP: in.ServerIP,
	}

	if in.Scheme != schemeHTTPS {
		if in.Scheme == schemeHTTP {
			detail.ReasonCodes = append(detail.ReasonCodes, "plain_http")
		}

		return detail
	}

	if in.TLSState == nil {
		if in.FetchErr != nil {
			detail.ReasonCodes = appendReasonFromError(detail.ReasonCodes, in.FetchErr)
		} else {
			detail.ReasonCodes = append(detail.ReasonCodes, "tls_state_missing")
		}

		return detail
	}

	detail.TLSVersion = tlsVersionLabel(in.TLSState.Version)
	detail.CipherSuite = tls.CipherSuiteName(in.TLSState.CipherSuite)

	if len(in.TLSState.PeerCertificates) > 0 {
		leaf := in.TLSState.PeerCertificates[0]
		detail.CertNotBefore = leaf.NotBefore
		detail.CertNotAfter = leaf.NotAfter
		detail.LeafCN = leaf.Subject.CommonName
		detail.LeafSANs = leaf.DNSNames

		detail.CertValid = certValidNow(leaf)
		if !detail.CertValid {
			detail.ReasonCodes = append(detail.ReasonCodes, "cert_not_valid_now")
		}
	} else {
		detail.ReasonCodes = append(detail.ReasonCodes, "peer_cert_missing")
	}

	if in.FetchErr != nil {
		detail.ReasonCodes = appendReasonFromError(detail.ReasonCodes, in.FetchErr)
	}

	return detail
}

// GradeTLS maps captured connection detail to the coarse stats grade contract.
func GradeTLS(detail ConnectionDetail, scheme string, fetchErr error) *string {
	if scheme == schemeHTTP {
		return nil
	}

	if fetchErr != nil && detail.TLSStateMissing() {
		return gradePtr(validatorcore.GradeFail)
	}

	if detail.TLSVersion == "" {
		if fetchErr != nil {
			return gradePtr(validatorcore.GradeFail)
		}

		return nil
	}

	if fetchErr != nil {
		if tlsRelatedError(fetchErr) {
			return gradePtr(validatorcore.GradeFail)
		}
	}

	if !detail.CertValid {
		return gradePtr(validatorcore.GradeFail)
	}

	if detail.TLSVersion == "TLS 1.0" || detail.TLSVersion == "TLS 1.1" {
		return gradePtr(validatorcore.GradeWarn)
	}

	if isInsecureCipher(detail.CipherSuite) {
		return gradePtr(validatorcore.GradeWarn)
	}

	return gradePtr(validatorcore.GradePass)
}

// TLSStateMissing reports whether CaptureTLS found no TLS state for an HTTPS fetch.
func (d ConnectionDetail) TLSStateMissing() bool {
	return d.TLSVersion == "" && d.CipherSuite == ""
}

func tlsVersionLabel(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("TLS 0x%04x", version)
	}
}

func certValidNow(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}

	now := time.Now()

	return !now.Before(cert.NotBefore) && !now.After(cert.NotAfter)
}

func appendReasonFromError(reasons []string, err error) []string {
	var certVerifyErr *tls.CertificateVerificationError
	if errors.As(err, &certVerifyErr) {
		if certVerifyErr != nil && certVerifyErr.Err != nil {
			return appendReasonFromError(reasons, certVerifyErr.Err)
		}

		return append(reasons, "tls_certificate_verification")
	}

	var certErr x509.CertificateInvalidError
	if errors.As(err, &certErr) {
		return append(reasons, fmt.Sprintf("x509_invalid_%d", certErr.Reason))
	}

	var unknownAuth x509.UnknownAuthorityError
	if errors.As(err, &unknownAuth) {
		return append(reasons, "x509_unknown_authority")
	}

	var hostErr x509.HostnameError
	if errors.As(err, &hostErr) {
		return append(reasons, "x509_hostname_mismatch")
	}

	var recordErr tls.RecordHeaderError
	if errors.As(err, &recordErr) {
		return append(reasons, "tls_record_header")
	}

	return append(reasons, "fetch_error")
}

func tlsRelatedError(err error) bool {
	if err == nil {
		return false
	}

	var certVerifyErr *tls.CertificateVerificationError
	if errors.As(err, &certVerifyErr) {
		return true
	}

	var certErr x509.CertificateInvalidError
	if errors.As(err, &certErr) {
		return true
	}

	var unknownAuth x509.UnknownAuthorityError
	if errors.As(err, &unknownAuth) {
		return true
	}

	var hostErr x509.HostnameError
	if errors.As(err, &hostErr) {
		return true
	}

	var recordErr tls.RecordHeaderError

	return errors.As(err, &recordErr)
}

func isInsecureCipher(name string) bool {
	if name == "" {
		return false
	}

	for _, suite := range tls.InsecureCipherSuites() {
		if tls.CipherSuiteName(suite.ID) == name {
			return true
		}
	}

	return false
}

func gradePtr(grade string) *string {
	value := grade

	return &value
}

// SchemeFromURL returns the URL scheme when present.
func SchemeFromURL(rawURL string) string {
	if rawURL == "" {
		return ""
	}

	if len(rawURL) >= 8 && rawURL[:8] == schemeHTTPS+"://" {
		return schemeHTTPS
	}

	if len(rawURL) >= 7 && rawURL[:7] == schemeHTTP+"://" {
		return schemeHTTP
	}

	return ""
}

// ConnectionReport copies report-only connection detail into validatorcore snapshot
// fields without importing probe wiring into callers.
func ConnectionReport(d ConnectionDetail) validatorcore.StatsConnectionReport {
	return validatorcore.StatsConnectionReport{
		ServerIP:      d.ServerIP,
		TLSVersion:    d.TLSVersion,
		CipherSuite:   d.CipherSuite,
		CertNotBefore: d.CertNotBefore,
		CertNotAfter:  d.CertNotAfter,
		CertValid:     d.CertValid,
		LeafCN:        d.LeafCN,
		LeafSANs:      append([]string(nil), d.LeafSANs...),
		ReasonCodes:   append([]string(nil), d.ReasonCodes...),
	}
}
