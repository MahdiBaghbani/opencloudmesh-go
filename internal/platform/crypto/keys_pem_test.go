package crypto_test

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
)

func getPublicKeyPEM(km *crypto.KeyManager) string {
	key := km.GetSigningKey()
	if key == nil {
		return ""
	}

	pkix, err := x509.MarshalPKIXPublicKey(key.PublicKey)
	if err != nil {
		return ""
	}

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pkix,
	}

	return string(pem.EncodeToMemory(block))
}

func parsePublicKeyPEM(pemData string) (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, errors.New("no PEM block found")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("not an Ed25519 public key")
	}

	return edPub, nil
}
