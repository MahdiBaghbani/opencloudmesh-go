// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"

const retentionClockFinishedAt = "finishedAt"

type manifestReportMeta struct {
	HTMLPath string `json:"htmlPath"`
	APIPath  string `json:"apiPath"`
}

type manifestRetentionMeta struct {
	Tiers       []string `json:"tiers"`
	DefaultTier string   `json:"defaultTier"`
	Clock       string   `json:"clock"`
	PatchPath   string   `json:"patchPath"`
	LockPath    string   `json:"lockPath"`
}

func buildManifestReportMeta(externalBasePath string) manifestReportMeta {
	return manifestReportMeta{
		HTMLPath: joinReportPath(externalBasePath, "validator", "report", "{id}"),
		APIPath:  joinReportPath(externalBasePath, "validator", "api", "report", "{id}"),
	}
}

func buildManifestRetentionMeta(externalBasePath string) manifestRetentionMeta {
	return manifestRetentionMeta{
		Tiers: []string{
			validatorcore.RetentionTierForever,
			validatorcore.RetentionTier7,
			validatorcore.RetentionTier14,
			validatorcore.RetentionTier30,
			validatorcore.RetentionTier60,
			validatorcore.RetentionTier90,
		},
		DefaultTier: validatorcore.DefaultRetentionTier,
		Clock:       retentionClockFinishedAt,
		PatchPath:   joinReportPath(externalBasePath, "validator", "api", "report", "{id}", "retention"),
		LockPath:    joinReportPath(externalBasePath, "validator", "api", "report", "{id}", "lock"),
	}
}
