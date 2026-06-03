#!/bin/bash
PKI_DIR=./pki
SECRETS_DIR=./secrets
DB_PATH="$PKI_DIR/micropki.db"

mkdir -p "$PKI_DIR" "$SECRETS_DIR"
echo "rootpass123" > "$SECRETS_DIR/ca.pass"
echo "interpass123" > "$SECRETS_DIR/intermediate.pass"

echo "[INFO] Инициализация базы..."
python3 -m micropki.cli db init --db-path "$DB_PATH" --force

echo "[INFO] Root CA..."
python3 -m micropki.cli ca init --subject "CN=Root CA,O=Demo Org" --key-type rsa --key-size 4096 --passphrase-file "$SECRETS_DIR/ca.pass" --out-dir "$PKI_DIR" --validity-days 3650 --db-path "$DB_PATH" --force

echo "[INFO] Intermediate CA..."
python3 -m micropki.cli ca issue-intermediate --root-cert "$PKI_DIR/certs/ca.cert.pem" --root-key "$PKI_DIR/private/ca.key.pem" --root-pass-file "$SECRETS_DIR/ca.pass" --subject "CN=Intermediate CA" --key-type rsa --key-size 4096 --passphrase-file "$SECRETS_DIR/intermediate.pass" --out-dir "$PKI_DIR" --validity-days 365 --pathlen 0 --db-path "$DB_PATH"

echo "[INFO] Серверный сертификат example.com..."
python3 -m micropki.cli ca issue-cert --ca-cert "$PKI_DIR/certs/intermediate.cert.pem" --ca-key "$PKI_DIR/private/intermediate.key.pem" --ca-pass-file "$SECRETS_DIR/intermediate.pass" --template server --subject "CN=example.com" --san dns:example.com --out-dir "$PKI_DIR/certs" --validity-days 365 --db-path "$DB_PATH"

echo "[INFO] Проверка цепочки..."
python3 -m micropki.cli ca verify-chain --leaf "$PKI_DIR/certs/example.com.cert.pem" --intermediate "$PKI_DIR/certs/intermediate.cert.pem" --root "$PKI_DIR/certs/ca.cert.pem"

echo "[INFO] Demo TLS сертификат и Code Signing будут выполнены дальше."
echo "Запусти сервер и клиент отдельно, чтобы проверить TLS и подпись."