package signature_test

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

func defaultSigTestConfig() *config.SignatureConfig {
	cfg := config.DefaultSignatureConfig()
	return &cfg
}
