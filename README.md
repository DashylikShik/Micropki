# MicroPKI

A minimal Public Key Infrastructure (PKI) implementation for educational purposes.

## Description

MicroPKI is a command-line tool that creates a self-signed Root Certificate Authority (CA) with secure key storage, certificate generation, and audit logging.

## Dependencies

- Python 3.8 or higher
- cryptography >= 3.0

## Project Structure
project_root/
├── micropki/                     # Основной пакет
│   ├── __init__.py
│   ├── ca.py                     # Операции с CA
│   ├── certificates.py           # Работа с X.509 сертификатами
│   ├── crypto_utils.py           # Криптографические утилиты
│   ├── logger.py                 # Логирование
│   ├── csr.py                    # Генерация и обработка CSR
│   ├── templates.py              # Шаблоны сертификатов
│   ├── san.py                    # Парсинг Subject Alternative Names
│   ├── chain.py                  # Валидация цепочек сертификатов
│   └── cli.py                    # Интерфейс командной строки
├── tests/                        # Тесты
│   ├── test_ca.py                # Тесты CA
│   ├── test_certificates.py      # Тесты сертификатов
│   ├── test_crypto_utils.py      # Тесты крипто-утилит
│   ├── test_negative_scenarios.py # Негативные сценарии
│   └── test_sprint2.py           # Тесты Sprint 2
├── secrets/                      # Файлы с паролями (не в Git)
├── logs/                         # Лог-файлы
├── pki/                          # Сгенерированные сертификаты и ключи
├── requirements.txt              # Зависимости
├── setup.py                      # Установка пакета
└── README.md                     # Этот файл

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
pip install flask

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


# sprint 2
# 1. Создание Root CA
micropki ca init --subject "CN=Root CA" --key-type rsa --key-size 4096 --passphrase-file secrets\ca.pass --out-dir pki --validity-days 365 --force

# 2. Создание Intermediate CA
micropki ca issue-intermediate --root-cert pki\certs\ca.cert.pem --root-key pki\private\ca.key.pem --root-pass-file secrets\ca.pass --subject "CN=Intermediate CA" --key-type rsa --key-size 4096 --passphrase-file secrets\intermediate.pass --out-dir pki --validity-days 365 --pathlen 0

# 3. Выпуск сертификата (out-dir = pki/certs)
micropki ca issue-cert --ca-cert pki\certs\intermediate.cert.pem --ca-key pki\private\intermediate.key.pem --ca-pass-file secrets\intermediate.pass --template server --subject "CN=example.com" --san dns:example.com --san dns:www.example.com --out-dir pki\certs --validity-days 365

# 4. Проверка файлов
dir pki\certs\*.cert.pem
# Должны увидеть: ca.cert.pem, intermediate.cert.pem, example.com.cert.pem

# 5. Проверка цепочки
micropki ca verify-chain --leaf pki\certs\example.com.cert.pem --intermediate pki\certs\intermediate.cert.pem --root pki\certs\ca.cert.pem

# 6. Запуск тестов:
pytest tests/test_sprint2.py -v


# sprint 3
# 1. Удалить старую БД
del pki\micropki.db

# 2. Инициализировать новую БД
micropki db init --db-path ./pki/micropki.db --force

# 3. Создать Root CA
micropki ca init --subject "CN=Root CA" --key-type rsa --key-size 4096 --passphrase-file secrets\ca.pass --out-dir pki --validity-days 365 --force --db-path ./pki/micropki.db

# 4. Создать Intermediate CA
micropki ca issue-intermediate --root-cert pki\certs\ca.cert.pem --root-key pki\private\ca.key.pem --root-pass-file secrets\ca.pass --subject "CN=Intermediate CA" --key-type rsa --key-size 4096 --passphrase-file secrets\intermediate.pass --out-dir pki --validity-days 365 --pathlen 0 --db-path ./pki/micropki.db

# 5. Выпустить сертификат
micropki ca issue-cert --ca-cert pki\certs\intermediate.cert.pem --ca-key pki\private\intermediate.key.pem --ca-pass-file secrets\intermediate.pass --template server --subject "CN=example.com" --san dns:example.com --out-dir pki\certs --validity-days 365 --db-path ./pki/micropki.db

# 6. Проверить список
micropki ca list-certs --db-path ./pki/micropki.db --format table

# 7. Показать сертификат по серийному номеру
micropki ca show-cert BC807B10E7655CD --db-path ./pki/micropki.db

# 8. Список в формате JSON
micropki ca list-certs --db-path ./pki/micropki.db --format json

# 9. Список в формате CSV
micropki ca list-certs --db-path ./pki/micropki.db --format csv

# 10. Фильтр по статусу
micropki ca list-certs --db-path ./pki/micropki.db --status valid --format table

# 11. Запустите HTTP сервер
В этом же окне (сервер будет работать):
micropki repo serve --host 127.0.0.1 --port 8080 --db-path ./pki/micropki.db --cert-dir ./pki/certs

# 12. В другом окне терминала проверка API:

cd C:\Users\Пользователь\Desktop\project_root
venv\Scripts\activate

# Проверка здоровья
curl http://127.0.0.1:8080/health

# Получить корневой сертификат
curl http://127.0.0.1:8080/ca/root

# Получить промежуточный сертификат
curl http://127.0.0.1:8080/ca/intermediate

# Получить сертификат по серийному номеру
curl http://127.0.0.1:8080/certificate/BC807B10E7655CD

# Проверить CRL (плейсхолдер для Sprint 4)
curl http://127.0.0.1:8080/crl