package service

import (
	"fmt"
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

// ValidatePreBootstrap runs fail-fast checks before any side-effecting bootstrap.
// It mirrors the binary and integration harness pre-bootstrap guardrails.
func ValidatePreBootstrap(cfg *config.Config) error {
	if cfg.HTTP.Services != nil {
		var names []string
		for name := range cfg.HTTP.Services {
			names = append(names, name)
		}
		if unknown, allowed := CheckServiceNames(names); len(unknown) > 0 {
			return fmt.Errorf(
				"unknown service names in [http.services]: %s (allowed: %s)",
				strings.Join(unknown, ", "),
				strings.Join(allowed, ", "),
			)
		}
	}
	if err := config.ValidateCompatibilityScopeStartupGuardrails(cfg); err != nil {
		return err
	}
	return nil
}

// ValidateBuiltServices checks built services match the descriptor table:
// counts align, every descriptor has a non-nil built service with matching
// Prefix(), and no extra built services exist without descriptors.
func ValidateBuiltServices(services map[string]Service) error {
	if len(services) < len(descriptors) {
		return fmt.Errorf(
			"built service count = %d, want %d from descriptor table",
			len(services),
			len(descriptors),
		)
	}
	for _, want := range descriptors {
		svc, ok := services[want.Name]
		if !ok {
			return fmt.Errorf("missing built service %q", want.Name)
		}
		if svc == nil {
			return fmt.Errorf("built service %q is nil", want.Name)
		}
		if got := svc.Prefix(); got != want.Prefix {
			return fmt.Errorf(
				"service %q prefix = %q, want descriptor prefix %q",
				want.Name,
				got,
				want.Prefix,
			)
		}
	}
	for name := range services {
		if _, ok := DescriptorByName(name); !ok {
			return fmt.Errorf("built service %q has no descriptor", name)
		}
	}
	return nil
}
