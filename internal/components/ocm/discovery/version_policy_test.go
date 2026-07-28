package discovery

import (
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

func TestVersionPolicyFromConfig(t *testing.T) {
	tests := []struct {
		name  string
		cfg   config.DiscoveryConfig
		wantM APIVersionMode
		wantW WarnMode
	}{
		// valid policy x warn combinations
		{"accept-any/any-diff", config.DiscoveryConfig{PeerAPIVersionPolicy: "accept-any", PeerAPIVersionWarn: "any-diff"}, APIVersionAcceptAny, WarnAnyDiff},
		{"accept-any/lower-only", config.DiscoveryConfig{PeerAPIVersionPolicy: "accept-any", PeerAPIVersionWarn: "lower-only"}, APIVersionAcceptAny, WarnLowerOnly},
		{"accept-any/none", config.DiscoveryConfig{PeerAPIVersionPolicy: "accept-any", PeerAPIVersionWarn: "none"}, APIVersionAcceptAny, WarnNone},
		{"exact/any-diff", config.DiscoveryConfig{PeerAPIVersionPolicy: "exact", PeerAPIVersionWarn: "any-diff"}, APIVersionExact, WarnAnyDiff},
		{"exact/lower-only", config.DiscoveryConfig{PeerAPIVersionPolicy: "exact", PeerAPIVersionWarn: "lower-only"}, APIVersionExact, WarnLowerOnly},
		{"exact/none", config.DiscoveryConfig{PeerAPIVersionPolicy: "exact", PeerAPIVersionWarn: "none"}, APIVersionExact, WarnNone},
		{"at-least-1.4/any-diff", config.DiscoveryConfig{PeerAPIVersionPolicy: "at-least-1.4", PeerAPIVersionWarn: "any-diff"}, APIVersionAtLeast14, WarnAnyDiff},
		{"at-least-1.4/lower-only", config.DiscoveryConfig{PeerAPIVersionPolicy: "at-least-1.4", PeerAPIVersionWarn: "lower-only"}, APIVersionAtLeast14, WarnLowerOnly},
		{"at-least-1.4/none", config.DiscoveryConfig{PeerAPIVersionPolicy: "at-least-1.4", PeerAPIVersionWarn: "none"}, APIVersionAtLeast14, WarnNone},
		// policy defaults
		{"empty policy", config.DiscoveryConfig{PeerAPIVersionPolicy: "", PeerAPIVersionWarn: "none"}, APIVersionAcceptAny, WarnNone},
		{"unknown policy", config.DiscoveryConfig{PeerAPIVersionPolicy: "bogus", PeerAPIVersionWarn: "lower-only"}, APIVersionAcceptAny, WarnLowerOnly},
		// warn defaults
		{"empty warn", config.DiscoveryConfig{PeerAPIVersionPolicy: "exact", PeerAPIVersionWarn: ""}, APIVersionExact, WarnAnyDiff},
		{"unknown warn", config.DiscoveryConfig{PeerAPIVersionPolicy: "at-least-1.4", PeerAPIVersionWarn: "bogus"}, APIVersionAtLeast14, WarnAnyDiff},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := VersionPolicyFromConfig(tt.cfg)
			if p.Mode != tt.wantM {
				t.Fatalf("Mode = %v, want %v", p.Mode, tt.wantM)
			}

			if p.Warn != tt.wantW {
				t.Fatalf("Warn = %v, want %v", p.Warn, tt.wantW)
			}
		})
	}
}

func TestNewVersionPolicy_DefaultAcceptAnyWarnAnyDiff(t *testing.T) {
	p := NewVersionPolicy()
	if p.Mode != APIVersionAcceptAny {
		t.Fatalf("Mode = %v, want APIVersionAcceptAny", p.Mode)
	}

	if p.Warn != WarnAnyDiff {
		t.Fatalf("Warn = %v, want WarnAnyDiff", p.Warn)
	}
}

func TestCompareDotTriple_Unparseable(t *testing.T) {
	unparseable := []string{
		"1.0-proposal1",
		"v1.4.0",
		"1.4",
		"1.4.0-rc1",
		"abc",
		"",
	}
	for _, s := range unparseable {
		if _, ok := compareDotTriple(s, spec.APIVersionPin); ok {
			t.Fatalf("compareDotTriple(%q, pin) ok=true, want false", s)
		}

		if _, ok := compareDotTriple(spec.APIVersionPin, s); ok && s != "" {
			t.Fatalf("compareDotTriple(pin, %q) ok=true, want false", s)
		}
	}
}

func TestCompareDotTriple_Ordering(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.3.0", "1.4.0", -1},
		{"1.4.0", "1.4.0", 0},
		{"2.0.0", "1.4.0", 1},
		{"1.10.0", "1.9.0", 1},
	}
	for _, tt := range tests {
		cmp, ok := compareDotTriple(tt.a, tt.b)
		if !ok {
			t.Fatalf("compareDotTriple(%q, %q) ok=false", tt.a, tt.b)
		}

		if cmp != tt.want {
			t.Fatalf("compareDotTriple(%q, %q) = %d, want %d", tt.a, tt.b, cmp, tt.want)
		}
	}
}

func TestVersionPolicy_Accept(t *testing.T) {
	versions := []string{"1.1.0", "1.1.2", "1.2.0", "1.3.0", "1.4.0", "2.0.0"}

	modes := []struct {
		name   string
		mode   APIVersionMode
		accept func(string) bool
	}{
		{
			name:   "accept-any",
			mode:   APIVersionAcceptAny,
			accept: func(v string) bool { return v != "" },
		},
		{
			name:   "exact",
			mode:   APIVersionExact,
			accept: func(v string) bool { return v == spec.APIVersionPin },
		},
		{
			name:   "at-least-1.4",
			mode:   APIVersionAtLeast14,
			accept: atLeast14,
		},
	}

	warnModes := []struct {
		name       string
		warn       WarnMode
		shouldWarn func(v string) bool
	}{
		{
			name: "any-diff",
			warn: WarnAnyDiff,
			shouldWarn: func(v string) bool {
				return v != "" && v != spec.APIVersionPin
			},
		},
		{
			name: "lower-only",
			warn: WarnLowerOnly,
			shouldWarn: func(v string) bool {
				cmp, ok := compareDotTriple(v, spec.APIVersionPin)
				return ok && cmp < 0
			},
		},
		{
			name:       "none",
			warn:       WarnNone,
			shouldWarn: func(_ string) bool { return false },
		},
	}

	for _, m := range modes {
		for _, w := range warnModes {
			t.Run(m.name+"/"+w.name, func(t *testing.T) {
				p := &VersionPolicy{Mode: m.mode, Warn: w.warn}
				for _, v := range versions {
					ok, warning := p.Accept(v)
					if ok != m.accept(v) {
						t.Errorf("Accept(%q) ok=%v, want %v", v, ok, m.accept(v))
					}

					wantWarn := w.shouldWarn(v) && ok
					if wantWarn && warning == "" {
						t.Errorf("Accept(%q) warning empty, want non-empty", v)
					}

					if !wantWarn && warning != "" {
						t.Errorf("Accept(%q) warning=%q, want empty", v, warning)
					}

					if wantWarn && w.warn == WarnAnyDiff && !strings.Contains(warning, "differs from pin") {
						t.Errorf("Accept(%q) warning=%q, want differs-from-pin text", v, warning)
					}
				}
			})
		}
	}
}

func TestVersionPolicy_Accept_EmptyRejected(t *testing.T) {
	p := NewVersionPolicy()

	ok, warn := p.Accept("")
	if ok {
		t.Fatal("Accept(\"\") ok=true, want false")
	}

	if warn != "" {
		t.Fatalf("Accept(\"\") warning=%q, want empty", warn)
	}
}

func TestVersionPolicy_Accept_Unparseable(t *testing.T) {
	unparseable := []string{"1.0-proposal1", "v1.4.0", "1.4", "1.4.0-rc1", "abc"}

	t.Run("accept-any", func(t *testing.T) {
		p := &VersionPolicy{Mode: APIVersionAcceptAny, Warn: WarnAnyDiff}
		for _, v := range unparseable {
			ok, _ := p.Accept(v)
			if !ok {
				t.Fatalf("Accept(%q) ok=false under accept-any", v)
			}
		}
	})

	t.Run("exact", func(t *testing.T) {
		p := &VersionPolicy{Mode: APIVersionExact, Warn: WarnNone}
		for _, v := range unparseable {
			ok, _ := p.Accept(v)
			if ok {
				t.Fatalf("Accept(%q) ok=true under exact", v)
			}
		}
	})

	t.Run("at-least-1.4", func(t *testing.T) {
		p := &VersionPolicy{Mode: APIVersionAtLeast14, Warn: WarnNone}
		for _, v := range unparseable {
			ok, _ := p.Accept(v)
			if ok {
				t.Fatalf("Accept(%q) ok=true under at-least-1.4", v)
			}
		}
	})

	t.Run("lower-only-no-warn-unparseable", func(t *testing.T) {
		p := &VersionPolicy{Mode: APIVersionAcceptAny, Warn: WarnLowerOnly}
		for _, v := range unparseable {
			_, warn := p.Accept(v)
			if warn != "" {
				t.Fatalf("Accept(%q) warn=%q, want empty under lower-only", v, warn)
			}
		}
	})
}
