# CA pool tests

Tests for outbound client TLS root CA pool (`tls_root_ca_file`, `tls_root_ca_dir`).

## Structure

```text
ca_pool/
  ca_pool_test.go              Unit test: client with root CA connects to TLS server
  testdata/certificate-authority/   DockyPody CA fixture (crt + key)
  configs/                     Configs for manual binary runs
    invalid.toml               Invalid path, expect startup failure
    valid.toml                 Valid CA path, expect successful startup
```

## Commands

```sh
# Run the test
go test -v ./tests/ca_pool/...

# Manual validation: invalid path fails
go run ./cmd/opencloudmesh-go -config tests/ca_pool/configs/invalid.toml

# Manual validation: valid CA starts (from repo root)
go run ./cmd/opencloudmesh-go -config tests/ca_pool/configs/valid.toml
```
