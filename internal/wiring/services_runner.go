// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package wiring

import (
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/active/reverseinvite"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/active/runner"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/services/api"
)

func newActiveRunner(
	cfg *config.Config,
	d *Deps,
	invites *reverseinvite.Service,
	log *slog.Logger,
) (*runner.Runner, error) {
	probeEmail, probeName := validatorProbeIdentity(cfg)

	contentDir := ""
	if cfg != nil {
		contentDir = cfg.Persistence.ContentDir
	}

	resolvedDir, err := config.ResolveContentDir(contentDir)
	if err != nil {
		return nil, fmt.Errorf("wiring: resolve validator probe file: %w", err)
	}

	activeRunner, err := runner.New(runner.Deps{
		Store:         d.ValidatorStore,
		Invites:       invites,
		Parties:       d.PartyRepo,
		LocalIdentity: d.LocalIdentity,
		ProbeEmail:    probeEmail,
		ProbeName:     probeName,
		ProbeFilePath: filepath.Join(resolvedDir, config.SeedContentFileName),
		Log:           log,
	})
	if err != nil {
		return nil, fmt.Errorf("wiring: build active runner: %w", err)
	}

	return activeRunner, nil
}

func validatorProbeIdentity(cfg *config.Config) (email, displayName string) {
	email = config.DefaultValidatorProbeEmail
	displayName = config.DefaultValidatorProbeDisplayName

	if cfg == nil {
		return email, displayName
	}

	if cfg.Validator.Probe.Email != "" {
		email = cfg.Validator.Probe.Email
	}

	if cfg.Validator.Probe.DisplayName != "" {
		displayName = cfg.Validator.Probe.DisplayName
	}

	return email, displayName
}

func bindAndStartActiveRunner(services map[string]service.Service, d *Deps, legs *validatorLegs) error {
	if legs == nil || legs.runner == nil {
		return nil
	}

	apiSvc, ok := services[string(service.BuildAPI)].(*api.Service)
	if !ok || apiSvc == nil {
		return errors.New("wiring: api service is required to bind the active runner")
	}

	outgoing := apiSvc.OutgoingShareHandler()
	if outgoing == nil {
		return errors.New("wiring: outgoing share handler is required to bind the active runner")
	}

	legs.runner.BindOutgoing(outgoing)
	legs.runner.Start()

	if d != nil && d.lateStops != nil {
		d.lateStops.Add(legs.runner.Stop)
	}

	return nil
}
