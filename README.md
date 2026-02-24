# MicroPKI

A minimal Public Key Infrastructure (PKI) implementation for educational purposes.

## Description

MicroPKI is a command-line tool that creates a self-signed Root Certificate Authority (CA) with secure key storage, certificate generation, and audit logging.

## Dependencies

- Python 3.8 or higher
- cryptography >= 3.0

## Project Structure
project_root/
├── micropki/ # Main package
│ ├── init.py
│ ├── cli.py # Command-line interface
│ ├── ca.py # CA operations
│ ├── certificates.py # X.509 handling
│ ├── crypto_utils.py # Cryptographic utilities
│ └── logger.py # Logging setup
├── tests/ # Test suite
│ ├── test_ca.py
│ ├── test_certificates.py
│ └── test_crypto_utils.py
├── requirements.txt # Dependencies
├── setup.py # Package configuration
└── README.md

## Build Instructions

1. Clone the repository:
   ```bash
   git clone https://github.com/DashylikShik/micropki.git
   cd micropki

2. Create and activate virtual environment:
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/Mac
python3 -m venv venv
source venv/bin/activate

3. Install dependencies:
pip install -r requirements.txt
pip install -e .

4. Создание файла с паролем
mkdir secrets
echo my-strong-password-123 > secrets\ca.pass

5. Создание корневого CA
micropki ca init --subject "CN=Test Root CA,O=Test Organization" --key-type rsa --key-size 4096 --passphrase-file secrets\ca.pass --out-dir pki --validity-days 3650 --log-file logs\ca-init.log

Что происходит:
--subject "CN=Test Root CA,O=Test Organization" - имя вашего CA
--key-type rsa - используем RSA алгоритм
--key-size 4096 - очень длинный ключ (безопасно)
--passphrase-file - файл с паролем
--out-dir pki - папка для результатов
--validity-days 3650 - сертификат на 10 лет
--log-file - куда писать логи

6. Проверка результатов
# Посмотреть созданные файлы
dir pki
dir pki\private
dir pki\certs

# Посмотреть политику
type pki\policy.txt

# Посмотреть логи
type logs\ca-init.log

7. Верификация сертификата
micropki ca verify --cert pki\certs\ca.cert.pem

8. Проверка соответствия ключа и сертификата
micropki ca verify-key --key pki\private\ca.key.pem --passphrase-file secrets\ca.pass --cert pki\certs\ca.cert.pem

9. Запуск тестов
pytest tests -v
