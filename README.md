# OSINT Web Platform

Максимальная версия веб-платформы для OSINT (Open Source Intelligence) исследований с умным определением типа ввода, кэшированием, историей поиска и корреляцией данных.

## Возможности

### Умная система
- **Автоопределение типа ввода** - автоматически распознает IP, домен, email, телефон, username, MAC, hash
- **Кэширование** - результаты кэшируются на 30 минут для быстрого доступа
- **История поиска** - сохраняет историю по сессиям
- **Корреляция данных** - связывает связанные данные между собой
- **Глубокий анализ** - выполняет комплексный анализ с предложениями

### Вкладки

#### Basic
- **IP Lookup** - геолокация, ISP, организация
- **Domain Lookup** - WHOIS информация, IP, регистратор
- **Email Check** - проверка MX записей
- **Phone Lookup** - валидация, страна, оператор

#### Network
- **Reverse IP** - поиск доменов на одном IP
- **Subdomains** - перечисление поддоменов
- **Port Scanning** - сканирование открытых портов
- **ASN Lookup** - информация о автономной системе

#### Advanced
- **SSL/TLS Certificate** - информация о сертификате
- **DNS Full** - полные DNS записи (A, MX, TXT, NS, CNAME)
- **HTTP Headers** - анализ заголовков
- **Wayback Machine** - архивированные версии сайтов

#### Tools
- **MAC Address** - поиск производителя
- **Hash Analysis** - определение типа хеша
- **User Agent** - анализ браузера, ОС, устройства
- **Username Search** - поиск по социальным сетям

## Установка

1. Установите зависимости:
```bash
pip install -r requirements.txt
```

2. Запустите сервер:
```bash
python app.py
```

3. Откройте в браузере:
```
http://localhost:5000
```

## API Эндпоинты

### Basic
- `POST /api/ip` - IP поиск
- `POST /api/domain` - Domain поиск
- `POST /api/email` - Email проверка
- `POST /api/phone` - Phone поиск
- `POST /api/username` - Username поиск

### Network
- `POST /api/reverse-ip` - Reverse IP lookup
- `POST /api/subdomains` - Subdomain enumeration
- `POST /api/ports` - Port scanning
- `POST /api/asn` - ASN lookup

### Advanced
- `POST /api/ssl` - SSL сертификат
- `POST /api/dns-full` - Полные DNS записи
- `POST /api/http-headers` - HTTP заголовки
- `POST /api/wayback` - Wayback Machine

### Tools
- `POST /api/mac` - MAC адрес
- `POST /api/hash` - Hash анализ
- `POST /api/user-agent` - User Agent анализ

### Умные функции
- `POST /api/detect` - Определение типа ввода
- `POST /api/analyze` - Глубокий анализ
- `GET /api/history?session_id=xxx` - История
- `GET /api/correlations?session_id=xxx` - Корреляции

### POST /api/analyze
```json
{
  "input": "google.com",
  "session_id": "session_abc123"
}
```

### POST /api/history
```json
{
  "session_id": "session_abc123"
}
```

### POST /api/correlations
```json
{
  "session_id": "session_abc123"
}
```

### POST /api/detect
```json
{
  "input": "8.8.8.8"
}
```

## 🎨 Интерфейс

### Умный поиск
Просто введите данные - система автоматически определит тип:
- `8.8.8.8` → IP Lookup
- `google.com` → Domain Lookup
- `test@example.com` → Email Check
- `+79001234567` → Phone Lookup
- `username` → Username Search

### Быстрые действия
Кнопки для быстрого выбора типа поиска:
- IP Lookup
- Domain
- Email
- Phone

### История и корреляции
- Кнопка "История" - просмотр последних поисков
- Кнопка "Связи" - просмотр корреляций между данными
- Кнопка "Глубокий анализ" - многоуровневый анализ

## ⚠️ Предупреждение

Используйте эту платформу только в законных целях. Автор не несет ответственности за misuse.

## 📦 Зависимости

- flask - Web framework
- flask-cors - CORS support
- requests - HTTP requests
- aiohttp - Async HTTP client
- python-whois - WHOIS queries
- dnspython - DNS operations
- phonenumbers - Phone validation

## 🔒 Безопасность

- Данные хранятся в памяти (не персистентны)
- Сессии генерируются случайно
- Кэш очищается через 30 минут

## 📄 Лицензия

MIT License
