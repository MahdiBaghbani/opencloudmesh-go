#!/usr/bin/env nu

# Generate E2E TLS leaf certificate signed by the DockyPody CA.
# RSA 2048, SHA-256, 36500-day validity, SAN: localhost + 127.0.0.1 + ::1.
# Run from anywhere; paths are computed relative to the repo root.

def main [] {
    let repo_root = ($env.FILE_PWD | path dirname | path dirname)

    let ca_cert = ($repo_root | path join tests ca_pool testdata certificate-authority dockypody.crt)
    let ca_key = ($repo_root | path join tests ca_pool testdata certificate-authority dockypody.key)
    let out_cert = ($repo_root | path join tests e2e testdata tls localhost.crt)
    let out_key = ($repo_root | path join tests e2e testdata tls localhost.key)

    # Verify CA files exist
    if not ($ca_cert | path exists) {
        error make { msg: $"CA cert not found: ($ca_cert)" }
    }
    if not ($ca_key | path exists) {
        error make { msg: $"CA key not found: ($ca_key)" }
    }

    # Ensure output directory exists
    mkdir ($out_cert | path dirname)

    let tmp_csr = "/tmp/localhost-e2e.csr"
    let tmp_san = "/tmp/localhost-e2e-san.cnf"

    # Step 1: generate key and CSR
    print "Generating RSA 2048 key and CSR..."
    (^openssl req -new -nodes
        -out $tmp_csr
        -keyout $out_key
        -subj "/C=CH/ST=Geneva/L=Geneva/O=Open Cloud Mesh/CN=localhost")

    # Step 2: write SAN config
    "subjectAltName = @alt_names
[alt_names]
DNS.1 = localhost
IP.2 = 127.0.0.1
IP.3 = ::1
" | save -f $tmp_san

    # Step 3: sign with the CA
    print "Signing with DockyPody CA (36500 days)..."
    (^openssl x509 -req -days 36500
        -in $tmp_csr
        -CA $ca_cert
        -CAkey $ca_key
        -CAcreateserial
        -out $out_cert
        -extfile $tmp_san
        -sha256)

    # Step 4: clean up temp files
    rm -f $tmp_csr $tmp_san
    # Remove .srl if created next to the CA cert
    let srl = ($ca_cert | str replace '.crt' '.srl')
    if ($srl | path exists) { rm -f $srl }

    print $"Generated:"
    print $"  cert: ($out_cert)"
    print $"  key:  ($out_key)"
}
