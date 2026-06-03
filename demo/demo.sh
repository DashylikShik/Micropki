#!/bin/bash
# MicroPKI Full Demo (Sprint 1-8)
set -e

PKI_DIR="$(pwd)/pki"
SECRETS_DIR="$(pwd)/secrets"
DB_PATH="$PKI_DIR/micropki.db"

mkdir -p "$PKI_DIR"
mkdir -p "$SECRETS_DIR"
echo "rootpass123" > "$SECRETS_DIR/ca.pass"
echo "interpass123" > "$SECRETS_DIR/intermediate.pass"

# Sprint 1
micropki ca init --subject "CN=Root CA,O=Demo Org" --key-type rsa --key-size 4096 --passphrase-file "$SECRETS_DIR/ca.pass" --out-dir "$PKI_DIR" --validity-days 3650 --db-path "$DB_PATH" --force

# Sprint 2
micropki ca issue-intermediate --root-cert "$PKI_DIR/certs/ca.cert.pem" --root-key "$PKI_DIR/private/ca.key.pem" --root-pass-file "$SECRETS_DIR/ca.pass" --subject "CN=Intermediate CA" --key-type rsa --key-size 4096 --passphrase-file "$SECRETS_DIR/intermediate.pass" --out-dir "$PKI_DIR" --validity-days 365 --pathlen 0 --db-path "$DB_PATH"

# Sprint 3
micropki ca issue-cert --ca-cert "$PKI_DIR/certs/intermediate.cert.pem" --ca-key "$PKI_DIR/private/intermediate.key.pem" --ca-pass-file "$SECRETS_DIR/intermediate.pass" --template server --subject "CN=example.com" --san dns:example.com --out-dir "$PKI_DIR/certs" --validity-days 365 --db-path "$DB_PATH"

# Sprint 4
# revoke & CRL
SERIAL=$(micropki ca list-certs --db-path "$DB_PATH" --format csv | grep example.com | cut -d',' -f1)
micropki ca revoke "$SERIAL" --reason keyCompromise --db-path "$DB_PATH"
micropki ca gen-crl --ca intermediate --next-update 7 --out-dir "$PKI_DIR" --db-path "$DB_PATH"

# Sprint 5: OCSP
micropki ca issue-ocsp-cert --ca-cert "$PKI_DIR/certs/intermediate.cert.pem" --ca-key "$PKI_DIR/private/intermediate.key.pem" --ca-pass-file "$SECRETS_DIR/intermediate.pass" --subject "CN=OCSP Responder" --key-type rsa --key-size 2048 --san dns:localhost --out-dir "$PKI_DIR/certs" --validity-days 365
micropki ocsp serve --host 127.0.0.1 --port 8081 --db-path "$DB_PATH" --responder-cert "$PKI_DIR/certs/OCSP_Responder.cert.pem" --responder-key "$PKI_DIR/certs/OCSP_Responder.key.pem" --ca-cert "$PKI_DIR/certs/intermediate.cert.pem" &

# Sprint 6: Client
micropki client gen-csr --subject "CN=test-client.example.com" --san dns:test-client.example.com --out-key "$PKI_DIR/certs/client.key.pem" --out-csr "$PKI_DIR/certs/client.csr.pem"
micropki client request-cert --csr "$PKI_DIR/certs/client.csr.pem" --template client --ca-url http://127.0.0.1:8080 --out-cert "$PKI_DIR/certs/client.cert.pem" --db-path "$DB_PATH"
micropki client validate --cert "$PKI_DIR/certs/client.cert.pem" --untrusted "$PKI_DIR/certs/intermediate.cert.pem" --trusted "$PKI_DIR/certs/ca.cert.pem"
micropki client check-status --cert "$PKI_DIR/certs/client.cert.pem" --ca-cert "$PKI_DIR/certs/intermediate.cert.pem" --crl "$PKI_DIR/crl/intermediate.crl.pem"

# Sprint 7: Audit & CT log
micropki audit query
micropki audit verify
micropki audit ct-verify --cert "$PKI_DIR/certs/example.com.cert.pem"
micropki ca compromise --cert "$PKI_DIR/certs/example.com.cert.pem" --reason keyCompromise --db-path "$DB_PATH"
micropki ca list-certs --db-path "$DB_PATH" --format table

# Sprint 8: Demo certificate + TLS
micropki ca issue-cert --ca-cert "$PKI_DIR/certs/intermediate.cert.pem" --ca-key "$PKI_DIR/private/intermediate.key.pem" --ca-pass-file "$SECRETS_DIR/intermediate.pass" --template server --subject "CN=demo.example.com" --san dns:demo.example.com --out-dir "$PKI_DIR/certs" --validity-days 365 --db-path "$DB_PATH"
openssl s_server -cert "$PKI_DIR/certs/demo.example.com.cert.pem" -key "$PKI_DIR/certs/demo.example.com.key.pem" -accept 8443

echo "Demo complete! Open another terminal and run:"
echo "openssl s_client -connect localhost:8443 -CAfile $PKI_DIR/certs/ca.cert.pem"