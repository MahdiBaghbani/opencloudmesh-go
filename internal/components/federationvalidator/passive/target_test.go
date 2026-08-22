// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"errors"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/hostport"
)

func TestParseTarget(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		raw          string
		wantOrigin   string
		wantHost     string
		wantStarter  string
		wantStarterP bool
		wantErr      error
	}{
		{
			name:         "ocm id mahdi at ponder",
			raw:          "mahdi@ponder.org",
			wantOrigin:   "https://ponder.org",
			wantHost:     "ponder.org",
			wantStarter:  "mahdi@ponder.org",
			wantStarterP: true,
		},
		{
			name:         "ocm id trims typed input",
			raw:          "  mahdi@ponder.org  ",
			wantOrigin:   "https://ponder.org",
			wantHost:     "ponder.org",
			wantStarter:  "mahdi@ponder.org",
			wantStarterP: true,
		},
		{
			name:         "ocm id keeps non-default port",
			raw:          "alice@peer.example:8443",
			wantOrigin:   "https://peer.example:8443",
			wantHost:     "peer.example:8443",
			wantStarter:  "alice@peer.example:8443",
			wantStarterP: true,
		},
		{
			name:         "ocm id elides default https port",
			raw:          "alice@peer.example:443",
			wantOrigin:   "https://peer.example",
			wantHost:     "peer.example",
			wantStarter:  "alice@peer.example:443",
			wantStarterP: true,
		},
		{
			name:         "ocm id keeps ipv6 brackets and port",
			raw:          "alice@[::1]:9200",
			wantOrigin:   "https://[::1]:9200",
			wantHost:     "[::1]:9200",
			wantStarter:  "alice@[::1]:9200",
			wantStarterP: true,
		},
		{
			name:         "ocm id forces https",
			raw:          "bob@Peer.Example",
			wantOrigin:   "https://peer.example",
			wantHost:     "peer.example",
			wantStarter:  "bob@Peer.Example",
			wantStarterP: true,
		},
		{
			name:       "https url success",
			raw:        "https://peer.example",
			wantOrigin: "https://peer.example",
			wantHost:   "peer.example",
		},
		{
			name:       "https url keeps non-default port",
			raw:        "https://peer.example:8443",
			wantOrigin: "https://peer.example:8443",
			wantHost:   "peer.example:8443",
		},
		{
			name:       "https url elides default port",
			raw:        "https://Peer.Example:443/path",
			wantOrigin: "https://peer.example",
			wantHost:   "peer.example",
		},
		{
			name:       "http url success",
			raw:        "http://peer.example:8080",
			wantOrigin: "http://peer.example:8080",
			wantHost:   "peer.example:8080",
		},
		{
			name:       "http url elides default port",
			raw:        "http://peer.example:80",
			wantOrigin: "http://peer.example",
			wantHost:   "peer.example",
		},
		{
			name:       "https url keeps http default port",
			raw:        "https://peer.example:80",
			wantOrigin: "https://peer.example:80",
			wantHost:   "peer.example:80",
		},
		{
			name:       "https ipv6 keeps brackets and port",
			raw:        "https://[::1]:9200",
			wantOrigin: "https://[::1]:9200",
			wantHost:   "[::1]:9200",
		},
		{
			name:       "https ipv6 elides default port",
			raw:        "https://[::1]:443",
			wantOrigin: "https://[::1]",
			wantHost:   "[::1]",
		},
		{
			name:    "https userinfo mahdi rejected",
			raw:     "https://mahdi@ponder.org",
			wantErr: errInvalidTarget,
		},
		{
			name:    "https userinfo alice rejected",
			raw:     "https://alice@peer.example",
			wantErr: errInvalidTarget,
		},
		{
			name:    "https userinfo with password rejected",
			raw:     "https://alice:secret@peer.example:8443",
			wantErr: errInvalidTarget,
		},
		{
			name:    "malformed https userinfo rejected",
			raw:     "https://alice:secret@[::1",
			wantErr: errInvalidTarget,
		},
		{
			name:    "bare schemeless host rejected",
			raw:     "peer.example",
			wantErr: errTargetForm,
		},
		{
			name:    "bare host with port rejected",
			raw:     "peer.example:8443",
			wantErr: errTargetForm,
		},
		{
			name:    "bare ipv6 host rejected",
			raw:     "[::1]:9200",
			wantErr: errTargetForm,
		},
		{
			name:    "empty target rejected",
			raw:     "   ",
			wantErr: errTargetRequired,
		},
		{
			name:    "unsupported scheme rejected",
			raw:     "ftp://peer.example",
			wantErr: errTargetScheme,
		},
		{
			name:    "empty url host rejected",
			raw:     "https://",
			wantErr: errTargetHost,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseTarget(tt.raw)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("parseTarget(%q) err = %v, want %v", tt.raw, err, tt.wantErr)
				}

				assertErrorOmitsInput(t, err, tt.raw)

				return
			}

			if err != nil {
				t.Fatalf("parseTarget(%q) unexpected error: %v", tt.raw, err)
			}

			if got.origin != tt.wantOrigin {
				t.Fatalf("origin = %q, want %q", got.origin, tt.wantOrigin)
			}

			if got.targetHost != tt.wantHost {
				t.Fatalf("targetHost = %q, want %q", got.targetHost, tt.wantHost)
			}

			assertStarterOCMID(t, got.starterOCMID, tt.wantStarterP, tt.wantStarter)
		})
	}
}

func TestParseTarget_MalformedInputs(t *testing.T) {
	t.Parallel()

	inputs := []string{
		"https://[::1",
		"mahdi@https://evil.example",
		"mahdi@ponder.org/path",
		"://peer.example",
		"@ponder.org",
		"mahdi@",
	}

	for _, raw := range inputs {
		t.Run(raw, func(t *testing.T) {
			t.Parallel()

			_, err := parseTarget(raw)
			if err == nil {
				t.Fatalf("parseTarget(%q) succeeded, want error", raw)
			}

			assertErrorOmitsInput(t, err, raw)
		})
	}
}

func TestTargetClientMessage_DropsWrappedParseText(t *testing.T) {
	t.Parallel()

	wrapped := errors.New(`parse "https://alice:secret@[::1": missing ']' in host`)

	got := targetClientMessage(wrapped)
	if got != errInvalidTarget.Error() {
		t.Fatalf("message = %q, want %q", got, errInvalidTarget.Error())
	}

	assertErrorOmitsSecrets(t, got, `https://alice:secret@[::1`)
}

func TestParseTarget_MalformedURLUserinfoDoesNotEchoSecrets(t *testing.T) {
	t.Parallel()

	const raw = "https://alice:secret@[::1"

	_, err := parseTarget(raw)
	if err == nil {
		t.Fatal("parseTarget(malformed userinfo URL) succeeded, want error")
	}

	if !errors.Is(err, errInvalidTarget) {
		t.Fatalf("err = %v, want errInvalidTarget", err)
	}

	assertErrorOmitsSecrets(t, err.Error(), raw)

	gotURL, err := parseTarget("https://peer.example:8443")
	if err != nil {
		t.Fatalf("parseTarget(https URL): %v", err)
	}

	if gotURL.origin != "https://peer.example:8443" || gotURL.targetHost != "peer.example:8443" {
		t.Fatalf("https URL = %+v, want origin and host peer.example:8443", gotURL)
	}

	if gotURL.starterOCMID != nil {
		t.Fatalf("https URL starterOCMID = %v, want nil", gotURL.starterOCMID)
	}

	gotOCM, err := parseTarget("mahdi@ponder.org")
	if err != nil {
		t.Fatalf("parseTarget(OCM id): %v", err)
	}

	if gotOCM.origin != "https://ponder.org" || gotOCM.targetHost != "ponder.org" {
		t.Fatalf("OCM id = %+v, want ponder.org", gotOCM)
	}

	if gotOCM.starterOCMID == nil || *gotOCM.starterOCMID != "mahdi@ponder.org" {
		t.Fatalf("OCM id starterOCMID = %v, want mahdi@ponder.org", gotOCM.starterOCMID)
	}
}

func TestParseTarget_TargetHostMatchesHostport(t *testing.T) {
	t.Parallel()

	cases := []struct {
		raw    string
		scheme string
		auth   string
	}{
		{raw: "https://peer.example:8443", scheme: "https", auth: "peer.example:8443"},
		{raw: "https://[::1]:9200", scheme: "https", auth: "[::1]:9200"},
		{raw: "alice@peer.example:8443", scheme: "https", auth: "peer.example:8443"},
		{raw: "alice@[::1]:9200", scheme: "https", auth: "[::1]:9200"},
		{raw: "http://peer.example:8080", scheme: "http", auth: "peer.example:8080"},
	}

	for _, tt := range cases {
		t.Run(tt.raw, func(t *testing.T) {
			t.Parallel()

			got, err := parseTarget(tt.raw)
			if err != nil {
				t.Fatalf("parseTarget(%q): %v", tt.raw, err)
			}

			want, err := hostport.Normalize(tt.auth, tt.scheme)
			if err != nil {
				t.Fatalf("hostport.Normalize(%q, %q): %v", tt.auth, tt.scheme, err)
			}

			if got.targetHost != want {
				t.Fatalf("targetHost = %q, want hostport.Normalize %q", got.targetHost, want)
			}

			if got.origin != tt.scheme+"://"+want {
				t.Fatalf("origin = %q, want %q", got.origin, tt.scheme+"://"+want)
			}
		})
	}
}

func TestParseTarget_DoesNotDiscover(t *testing.T) {
	t.Parallel()

	got, err := parseTarget("https://no-such-peer.invalid:8443")
	if err != nil {
		t.Fatalf("parseTarget(.invalid) unexpected error: %v", err)
	}

	if got.origin != "https://no-such-peer.invalid:8443" {
		t.Fatalf("origin = %q", got.origin)
	}

	if got.targetHost != "no-such-peer.invalid:8443" {
		t.Fatalf("targetHost = %q", got.targetHost)
	}

	if got.starterOCMID != nil {
		t.Fatalf("starterOCMID = %v, want nil", got.starterOCMID)
	}
}

func TestParseTarget_OCMNeverHTTP(t *testing.T) {
	t.Parallel()

	got, err := parseTarget("alice@peer.example:80")
	if err != nil {
		t.Fatalf("parseTarget: %v", err)
	}

	if got.origin != "https://peer.example:80" {
		t.Fatalf("origin = %q, want https origin", got.origin)
	}
}

func assertStarterOCMID(t *testing.T, got *string, wantSet bool, want string) {
	t.Helper()

	if !wantSet {
		if got != nil {
			t.Fatalf("starterOCMID = %v, want nil", got)
		}

		return
	}

	if got == nil || *got != want {
		t.Fatalf("starterOCMID = %v, want %q", got, want)
	}
}

func assertErrorOmitsInput(t *testing.T, err error, raw string) {
	t.Helper()

	assertErrorOmitsSecrets(t, err.Error(), raw)
}

func assertErrorOmitsSecrets(t *testing.T, got, raw string) {
	t.Helper()

	for _, leak := range []string{"secret", "alice", raw} {
		if leak != "" && strings.Contains(got, leak) {
			t.Fatalf("error leaked %q: %s", leak, got)
		}
	}
}
