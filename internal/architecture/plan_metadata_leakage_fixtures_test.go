// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package architecture

type planMetadataLeakCase struct {
	name string
	text string
}

var planMetadataLeakPositiveCoords = []planMetadataLeakCase{
	{name: "paren letter suffix", text: "reason-coded failure (T7a)."},
	{name: "paren bare digits", text: "see (F2) for details"},
	{name: "bare token suffix", text: "covers M1a edge case"},
	{name: "slog-style message", text: "discovery failed (F2b)"},
	{name: "appendix adjacent coordinate", text: "See Appendix C (T7a) for the failure path."},
	{name: "token T17", text: "blocked by T17 gate before merge"},
	{name: "token K6", text: "see K6 checklist item"},
	{name: "token P4", text: "P4 scope covers federation"},
	{name: "token F2a", text: "F2a regression noted in review"},
	{name: "token T-SCHEMA", text: "schema drift from T-SCHEMA task"},
	{name: "token T-PURGE", text: "run T-PURGE cleanup before ship"},
	{name: "wave 9", text: "Wave 9 federation validator lands next"},
	{name: "wave 10", text: "Wave 10 follows Wave 9"},
	{name: "gate D", text: "Gate D review blocked merge"},
	{name: "gate E", text: "Gate E judge returned FAIL"},
	{name: "round 4", text: "Round 4 design artifacts only"},
	{name: "interlaced research", text: "interlaced research summary attached"},
	{name: "lowercase q5", text: "fix q5 before continuing"},
	{name: "lowercase t3", text: "t3 owns the schema slice"},
	{name: "lowercase p7", text: "p7 verification pending"},
	{name: "lowercase w2", text: "w2 wave checkpoint"},
}

var planMetadataLeakNegativeLegitimate = []planMetadataLeakCase{
	{name: "rfc reference", text: "See RFC 9383 for the OCM discovery profile."},
	{name: "ietf appendix", text: "Defined in Appendix A.1 of the IETF OCM draft."},
	{name: "plain appendix", text: "See Appendix C for the discovery profile."},
	{name: "digitless paren T", text: "retry helper (T) after timeout"},
	{name: "digitless paren F", text: "fallback path (F) when upstream is down"},
	{name: "non coordinate token", text: "retry the Class helper after timeout"},
	{name: "plain prose", text: "upstream discovery succeeded without invite dialog"},
	{name: "crypto alg identifier", text: "RFC 9421 native names such as ecdsa-p256-sha256 are not valid JWK alg values"},
	{name: "crypto alg constant", text: `allowed algs include "ecdsa-p256-sha256" and rsa-v1_5-sha256`},
	{name: "hyphen wrapped coordinate", text: "compat-p7-hash is a legitimate hyphenated identifier"},
}

const planMetadataScanPositiveSlogSrc = `package sample

import "log/slog"

// helper returns a reason-coded failure (T7a).
func helper(log *slog.Logger) {
	log.InfoContext(nil, "discovery failed (F2b)")
}
`

const planMetadataScanNegativeRFCSrc = `package sample

// See RFC 9383 and Appendix A.1 for discovery requirements.
func helper() string {
	return "compat with github.com/cs3org/OCM-API schema"
}
`

type planMetadataScanCase struct {
	name string
	src  string
	want string
}

var planMetadataScanPositiveNew = []planMetadataScanCase{
	{
		name: "comment T-SCHEMA",
		src:  "package sample\n\n// schema drift from T-SCHEMA task\n",
		want: "T-SCHEMA",
	},
	{
		name: "string T-PURGE",
		src:  "package sample\n\nfunc f() string { return \"run T-PURGE cleanup\" }\n",
		want: "T-PURGE",
	},
	{
		name: "comment Wave 9",
		src:  "package sample\n\n// Wave 9 federation validator\n",
		want: "Wave 9",
	},
	{
		name: "string Wave 10",
		src:  "package sample\n\nfunc f() string { return \"Wave 10 follows\" }\n",
		want: "Wave 10",
	},
	{
		name: "comment Gate D",
		src:  "package sample\n\n// Gate D review blocked merge\n",
		want: "Gate D",
	},
	{
		name: "string Gate E",
		src:  "package sample\n\nfunc f() string { return \"Gate E judge FAIL\" }\n",
		want: "Gate E",
	},
	{
		name: "comment Round 4",
		src:  "package sample\n\n// Round 4 design artifacts only\n",
		want: "Round 4",
	},
	{
		name: "string interlaced research",
		src:  "package sample\n\nfunc f() string { return \"interlaced research summary\" }\n",
		want: "interlaced research",
	},
	{
		name: "comment q5",
		src:  "package sample\n\n// fix q5 before continuing\n",
		want: "q5",
	},
	{
		name: "string t3",
		src:  "package sample\n\nfunc f() string { return \"t3 owns schema\" }\n",
		want: "t3",
	},
	{
		name: "comment p7",
		src:  "package sample\n\n// p7 verification pending\n",
		want: "p7",
	},
	{
		name: "string w2",
		src:  "package sample\n\nfunc f() string { return \"w2 wave checkpoint\" }\n",
		want: "w2",
	},
	{
		name: "slog T17",
		src:  "package sample\n\nimport \"log/slog\"\n\nfunc f(l *slog.Logger) { l.Info(\"T17 gate\") }\n",
		want: "T17",
	},
	{
		name: "string K6",
		src:  "package sample\n\nfunc f() string { return \"see K6 checklist\" }\n",
		want: "K6",
	},
	{
		name: "comment P4",
		src:  "package sample\n\n// P4 scope covers federation\n",
		want: "P4",
	},
	{
		name: "string F2a",
		src:  "package sample\n\nfunc f() string { return \"F2a regression noted\" }\n",
		want: "F2a",
	},
}

const planMetadataScanNegativeHyphenSrc = `package sample

// compat-p7-hash and ecdsa-p256-sha256 are legitimate hyphenated identifiers.
func helper() string {
	return "compat-p7-hash"
}

func alg() string {
	return "ecdsa-p256-sha256"
}
`
