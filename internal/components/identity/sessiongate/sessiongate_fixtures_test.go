// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package sessiongate

import (
	"context"
	"log/slog"
	"maps"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
)

// recordingHandler captures slog records for testing without JSON parsing.
type recordingHandler struct {
	records []slog.Record
	attrs   map[string]any
	groups  []string
}

func newRecordingHandler() *recordingHandler {
	return &recordingHandler{
		attrs: make(map[string]any),
	}
}

func (h *recordingHandler) Enabled(_ context.Context, _ slog.Level) bool {
	return true
}

func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.records = append(h.records, r)

	return nil
}

func (h *recordingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	nh := &recordingHandler{
		records: h.records,
		attrs:   make(map[string]any),
		groups:  h.groups,
	}
	maps.Copy(nh.attrs, h.attrs)

	for _, a := range attrs {
		nh.attrs[a.Key] = a.Value.Any()
	}

	return nh
}

func (h *recordingHandler) WithGroup(name string) slog.Handler {
	nh := &recordingHandler{
		records: h.records,
		attrs:   make(map[string]any),
		groups:  append(h.groups, name),
	}
	maps.Copy(nh.attrs, h.attrs)

	return nh
}

func (h *recordingHandler) getAttr(key string) (any, bool) {
	v, ok := h.attrs[key]

	return v, ok
}

// testSessionRepo is a simple session repo for testing that returns a predefined session.
type testSessionRepo struct {
	session *identity.Session
}

func (r *testSessionRepo) Create(_ context.Context, _ string, _ time.Duration) (*identity.Session, error) {
	return r.session, nil
}

func (r *testSessionRepo) Get(_ context.Context, token string) (*identity.Session, error) {
	if r.session != nil && r.session.Token == token {
		return r.session, nil
	}

	return nil, identity.ErrSessionNotFound
}

func (r *testSessionRepo) Delete(_ context.Context, _ string) error {
	return nil
}

func (r *testSessionRepo) DeleteByUser(_ context.Context, _ string) error {
	return nil
}

func (r *testSessionRepo) DeleteExpired(_ context.Context) (int, error) {
	return 0, nil
}

type expiredSessionRepo struct{}

func (expiredSessionRepo) Create(_ context.Context, _ string, _ time.Duration) (*identity.Session, error) {
	return nil, identity.ErrSessionNotFound
}

func (expiredSessionRepo) Get(_ context.Context, _ string) (*identity.Session, error) {
	return nil, identity.ErrSessionExpired
}

func (expiredSessionRepo) Delete(_ context.Context, _ string) error {
	return nil
}

func (expiredSessionRepo) DeleteByUser(_ context.Context, _ string) error {
	return nil
}

func (expiredSessionRepo) DeleteExpired(_ context.Context) (int, error) {
	return 0, nil
}

// testPartyRepo is a simple party repo for testing.
type testPartyRepo struct {
	users map[string]*identity.User
}

func newTestPartyRepo() *testPartyRepo {
	return &testPartyRepo{
		users: make(map[string]*identity.User),
	}
}

func (r *testPartyRepo) Create(_ context.Context, user *identity.User) error {
	r.users[user.ID] = user

	return nil
}

func (r *testPartyRepo) Get(_ context.Context, id string) (*identity.User, error) {
	if u, ok := r.users[id]; ok {
		return u, nil
	}

	return nil, identity.ErrUserNotFound
}

func (r *testPartyRepo) GetByUsername(_ context.Context, username string) (*identity.User, error) {
	for _, u := range r.users {
		if u.Username == username {
			return u, nil
		}
	}

	return nil, identity.ErrUserNotFound
}

func (r *testPartyRepo) GetByEmail(_ context.Context, _ string) (*identity.User, error) {
	return nil, identity.ErrUserNotFound
}

func (r *testPartyRepo) Update(_ context.Context, user *identity.User) error {
	r.users[user.ID] = user

	return nil
}

func (r *testPartyRepo) Delete(_ context.Context, id string) error {
	delete(r.users, id)

	return nil
}

func (r *testPartyRepo) List(_ context.Context, _ string) ([]*identity.User, error) {
	result := make([]*identity.User, 0, len(r.users))
	for _, u := range r.users {
		result = append(result, u)
	}

	return result, nil
}

func (r *testPartyRepo) DeleteExpired(_ context.Context) (int, error) {
	return 0, nil
}
