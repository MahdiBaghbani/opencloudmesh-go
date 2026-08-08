// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package webdav

import (
	"context"
	"errors"
	"testing"
	"time"

	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token"
)

var errNotFound = errors.New("not found")

type mockOutgoingShareRepo struct {
	shares map[string]*sharesoutgoing.OutgoingShare
}

func newMockOutgoingShareRepo() *mockOutgoingShareRepo {
	return &mockOutgoingShareRepo{shares: make(map[string]*sharesoutgoing.OutgoingShare)}
}

func (m *mockOutgoingShareRepo) Create(_ context.Context, share *sharesoutgoing.OutgoingShare) error {
	m.shares[share.ShareID] = share

	return nil
}

func (m *mockOutgoingShareRepo) GetByID(_ context.Context, shareID string) (*sharesoutgoing.OutgoingShare, error) {
	if s, ok := m.shares[shareID]; ok {
		return s, nil
	}

	return nil, errNotFound
}

func (m *mockOutgoingShareRepo) GetByProviderID(_ context.Context, providerID string) (*sharesoutgoing.OutgoingShare, error) {
	for _, s := range m.shares {
		if s.ProviderID == providerID {
			return s, nil
		}
	}

	return nil, errNotFound
}

func (m *mockOutgoingShareRepo) GetByWebDAVID(_ context.Context, webdavID string) (*sharesoutgoing.OutgoingShare, error) {
	for _, s := range m.shares {
		if s.WebDAVID == webdavID {
			return s, nil
		}
	}

	return nil, errNotFound
}

func (m *mockOutgoingShareRepo) GetBySharedSecret(_ context.Context, sharedSecret string) (*sharesoutgoing.OutgoingShare, error) {
	for _, s := range m.shares {
		if s.SharedSecret == sharedSecret {
			return s, nil
		}
	}

	return nil, errNotFound
}

func (m *mockOutgoingShareRepo) List(_ context.Context) ([]*sharesoutgoing.OutgoingShare, error) {
	result := make([]*sharesoutgoing.OutgoingShare, 0, len(m.shares))
	for _, s := range m.shares {
		result = append(result, s)
	}

	return result, nil
}

func (m *mockOutgoingShareRepo) Update(_ context.Context, share *sharesoutgoing.OutgoingShare) error {
	m.shares[share.ShareID] = share

	return nil
}

type mockTokenStore struct {
	tokens map[string]*token.IssuedToken
}

func newMockTokenStore() *mockTokenStore {
	return &mockTokenStore{tokens: make(map[string]*token.IssuedToken)}
}

func (m *mockTokenStore) Store(_ context.Context, t *token.IssuedToken) error {
	m.tokens[t.AccessToken] = t

	return nil
}

func (m *mockTokenStore) Get(_ context.Context, accessToken string) (*token.IssuedToken, error) {
	t, ok := m.tokens[accessToken]
	if !ok {
		return nil, token.ErrTokenNotFound
	}

	if t.IsExpired() {
		return nil, token.ErrTokenExpired
	}

	return t, nil
}

func (m *mockTokenStore) Delete(_ context.Context, accessToken string) error {
	delete(m.tokens, accessToken)

	return nil
}

func (m *mockTokenStore) CleanExpired(_ context.Context) error {
	return nil
}

const testWebDAVID = "11111111-1111-1111-1111-111111111111"

func unexpiredTestToken(accessToken, shareID string) *token.IssuedToken {
	return &token.IssuedToken{
		AccessToken: accessToken,
		ShareID:     shareID,
		ExpiresAt:   time.Now().Add(time.Hour),
	}
}

func seedShare(t *testing.T, repo *mockOutgoingShareRepo) *sharesoutgoing.OutgoingShare {
	t.Helper()

	return seedShareWithRequirements(t, repo, "share-1", nil)
}

func seedShareWithRequirements(t *testing.T, repo *mockOutgoingShareRepo, shareID string, requirements []string) *sharesoutgoing.OutgoingShare {
	t.Helper()

	share := &sharesoutgoing.OutgoingShare{
		ShareID:      shareID,
		SharedSecret: "secret123",
		WebDAVID:     testWebDAVID,
		ReceiverHost: "receiver.example.com",
		Requirements: requirements,
	}
	if err := repo.Create(context.Background(), share); err != nil {
		t.Fatal(err)
	}

	return share
}
