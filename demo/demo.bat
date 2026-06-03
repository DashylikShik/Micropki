@echo off
REM ===============================
REM MicroPKI Full Demo (Sprint 1–8)
REM ===============================

REM Set paths
set PKI_DIR=%CD%\pki
set SECRETS_DIR=%CD%\secrets
set DB_PATH=%PKI_DIR%\micropki.db

REM --- Step 0: Prepare directories and secrets ---
mkdir %PKI_DIR%
mkdir %SECRETS_DIR%
echo rootpass123 > %SECRETS_DIR%\ca.pass
echo interpass123 > %SECRETS_DIR%\intermediate.pass

REM --- Sprint 1: Initialize Root CA ---
micropki ca init --subject "CN=Root CA,O=Demo Org" --key-type rsa --key-size 4096 --passphrase-file %SECRETS_DIR%\ca.pass --out-dir %PKI_DIR% --validity-days 3650 --db-path %DB_PATH% --force

REM --- Sprint 2: Intermediate CA ---
micropki ca issue-intermediate --root-cert %PKI_DIR%\certs\ca.cert.pem --root-key %PKI_DIR%\private\ca.key.pem --root-pass-file %SECRETS_DIR%\ca.pass --subject "CN=Intermediate CA" --key-type rsa --key-size 4096 --passphrase-file %SECRETS_DIR%\intermediate.pass --out-dir %PKI_DIR% --validity-days 365 --pathlen 0 --db-path %DB_PATH%

REM --- Sprint 3: Issue Server Certificate ---
micropki ca issue-cert --ca-cert %PKI_DIR%\certs\intermediate.cert.pem --ca-key %PKI_DIR%\private\intermediate.key.pem --ca-pass-file %SECRETS_DIR%\intermediate.pass --template server --subject "CN=example.com" --san dns:example.com --out-dir %PKI_DIR%\certs --validity-days 365 --db-path %DB_PATH%

REM --- Sprint 4: Revoke certificate & generate CRL ---
micropki ca revoke <INSERT_SERIAL> --reason keyCompromise --db-path %DB_PATH%
micropki ca gen-crl --ca intermediate --next-update 7 --out-dir %PKI_DIR% --db-path %DB_PATH%

REM --- Sprint 5: Issue OCSP Certificate and run OCSP server ---
micropki ca issue-ocsp-cert --ca-cert %PKI_DIR%\certs\intermediate.cert.pem --ca-key %PKI_DIR%\private\intermediate.key.pem --ca-pass-file %SECRETS_DIR%\intermediate.pass --subject "CN=OCSP Responder" --key-type rsa --key-size 2048 --san dns:localhost --out-dir %PKI_DIR%\certs --validity-days 365
start "" micropki ocsp serve --host 127.0.0.1 --port 8081 --db-path %DB_PATH% --responder-cert %PKI_DIR%\certs\OCSP_Responder.cert.pem --responder-key %PKI_DIR%\certs\OCSP_Responder.key.pem --ca-cert %PKI_DIR%\certs\intermediate.cert.pem

REM --- Sprint 6: Client CSR, request, validate ---
micropki client gen-csr --subject "CN=test-client.example.com" --san dns:test-client.example.com --out-key %PKI_DIR%\certs\client.key.pem --out-csr %PKI_DIR%\certs\client.csr.pem
micropki client request-cert --csr %PKI_DIR%\certs\client.csr.pem --template client --ca-url http://127.0.0.1:8080 --out-cert %PKI_DIR%\certs\client.cert.pem --db-path %DB_PATH%
micropki client validate --cert %PKI_DIR%\certs\client.cert.pem --untrusted %PKI_DIR%\certs\intermediate.cert.pem --trusted %PKI_DIR%\certs\ca.cert.pem
micropki client check-status --cert %PKI_DIR%\certs\client.cert.pem --ca-cert %PKI_DIR%\certs\intermediate.cert.pem --crl %PKI_DIR%\crl\intermediate.crl.pem

REM --- Sprint 7: Audit + CT Log + Compromise ---
micropki audit query
micropki audit verify
micropki audit ct-verify --cert %PKI_DIR%\certs\example.com.cert.pem
micropki ca compromise --cert %PKI_DIR%\certs\example.com.cert.pem --reason keyCompromise --db-path %DB_PATH%
micropki ca list-certs --db-path %DB_PATH% --format table

REM --- Sprint 8: Demo Certificate + TLS ---
micropki ca issue-cert --ca-cert %PKI_DIR%\certs\intermediate.cert.pem --ca-key %PKI_DIR%\private\intermediate.key.pem --ca-pass-file %SECRETS_DIR%\intermediate.pass --template server --subject "CN=demo.example.com" --san dns:demo.example.com --out-dir %PKI_DIR%\certs --validity-days 365 --db-path %DB_PATH%
start "" openssl s_server -cert %PKI_DIR%\certs\demo.example.com.cert.pem -key %PKI_DIR%\certs\demo.example.com.key.pem -accept 8443
REM Теперь открой новое окно cmd для клиента:
REM openssl s_client -connect localhost:8443 -CAfile %PKI_DIR%\certs\ca.cert.pem

echo Demo completed!
pause