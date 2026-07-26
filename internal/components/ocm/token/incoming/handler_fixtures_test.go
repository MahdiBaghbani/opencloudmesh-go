package incoming_test

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	tokenincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token/incoming"
)

// enabledSettings returns token exchange path settings for testing.
func enabledSettings() *tokenincoming.TokenExchangeSettings {
	s := &tokenincoming.TokenExchangeSettings{}
	s.ApplyDefaults()

	return s
}

func enabledCodeFlow() *policy.CodeFlow {
	return policy.NewCodeFlow()
}
