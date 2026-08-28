// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"encoding/json"
	"reflect"
	"slices"
	"testing"
)

func assertRequiredScanQuery(t *testing.T, query map[string]scanQueryParam, key string) {
	t.Helper()

	param, ok := query[key]
	if !ok || !param.Required || param.Type != schemaFieldTypeString {
		t.Fatalf("scan %s query = %+v, want required string", key, param)
	}
}

func assertOptionalScanOptInQuery(t *testing.T, query map[string]scanQueryParam, key string) {
	t.Helper()

	param, ok := query[key]
	if !ok || param.Required || param.OptInValue != optInLiteralValue {
		t.Fatalf("scan %s query = %+v, want optional optInValue 1", key, param)
	}
}

func assertOptInWireKeys(t *testing.T, raw map[string]json.RawMessage) {
	t.Helper()

	permanent := mustRawObject(t, raw["permanent"], "permanent")
	assertExactKeys(t, permanent, []string{"available", "optInQuery", "optInValue"})

	optIn := mustRawObject(t, raw["optIn"], "optIn")
	assertExactKeys(t, optIn, []string{"default", "scan", "start"})
	assertExactKeys(t, mustRawObject(t, optIn["start"], "optIn start"), []string{"optInActive", "optInPermanent", "optInStats"})
	assertExactKeys(t, mustRawObject(t, optIn["scan"], "optIn scan"), []string{"optInValue", "permanentQuery", "statsQuery"})
}

func assertScanQueryPermanentKeys(t *testing.T, scanQuery map[string]json.RawMessage) {
	t.Helper()

	assertExactKeys(
		t,
		mustRawObject(t, scanQuery[optInQueryPermanent], "scan query permanent"),
		[]string{"description", "optInValue", "required", "type"},
	)
}

func assertConsentAdvertisement(t *testing.T, payload manifestRouteResponse) {
	t.Helper()

	if !payload.Contribute.Available ||
		payload.Contribute.OptInQuery != optInQueryContribute ||
		payload.Contribute.OptInValue != optInLiteralValue {
		t.Fatalf("contribute = %+v", payload.Contribute)
	}

	if !payload.Permanent.Available ||
		payload.Permanent.OptInQuery != optInQueryPermanent ||
		payload.Permanent.OptInValue != optInLiteralValue {
		t.Fatalf("permanent = %+v", payload.Permanent)
	}

	if payload.OptIn.Default != "neither" ||
		payload.OptIn.Scan.StatsQuery != optInQueryContribute ||
		payload.OptIn.Scan.PermanentQuery != optInQueryPermanent ||
		payload.OptIn.Scan.OptInValue != optInLiteralValue {
		t.Fatalf("optIn = %+v", payload.OptIn)
	}

	if payload.OptIn.Start.OptInStats.Default || payload.OptIn.Start.OptInPermanent.Default {
		t.Fatalf(
			"optIn.start defaults = stats=%v permanent=%v, want both false",
			payload.OptIn.Start.OptInStats.Default,
			payload.OptIn.Start.OptInPermanent.Default,
		)
	}
}

func mustRawObject(t *testing.T, raw json.RawMessage, label string) map[string]json.RawMessage {
	t.Helper()

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("unmarshal %s: %v", label, err)
	}

	return obj
}

func assertExactKeys(t *testing.T, raw map[string]json.RawMessage, want []string) {
	t.Helper()

	got := make([]string, 0, len(raw))
	for key := range raw {
		got = append(got, key)
	}

	slices.Sort(got)
	slices.Sort(want)

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("keys = %v, want %v", got, want)
	}
}

func assertRequiredKeys(t *testing.T, raw map[string]json.RawMessage, required []string) {
	t.Helper()

	for _, key := range required {
		if _, ok := raw[key]; !ok {
			t.Fatalf("missing required wire key %q; keys present: %v", key, sortedWireKeys(raw))
		}
	}
}

func sortedWireKeys(raw map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(raw))
	for key := range raw {
		keys = append(keys, key)
	}

	slices.Sort(keys)

	return keys
}
