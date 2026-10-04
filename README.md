# OSINT Intelligence Platform

Современная веб-платформа для OSINT-разведки с интеллектуальным анализом данных.

## 🚀 Возможности

### Базовые функции
- **IP Lookup** - Геолокация, ISP, организация
- **Domain Lookup** - IP, регистратор, даты регистрации
- **WHOIS** - Полная WHOIS информация
- **DNS Lookup** - DNS записи домена
- **Email Check** - Проверка валидности email
- **Phone Lookup** - Информация о номере телефона
- **Username Search** - Поиск в социальных сетях

### Умные функции
- 🧠 **Автоматическое определение типа** - система сама распознает что вы ищете
- ⚡ **Кэширование** - результаты сохраняются на 30 минут
- 📜 **История поиска** - сохранение последних 20 поисков
- 🔗 **Корреляция данных** - автоматическое нахождение связей
- 🧠 **Глубокий анализ** - многоуровневый анализ с корреляцией

## 📋 Требования

- Python 3.8+
- pip

## 🔧 Установка

1. Установите зависимости:
```bash
pip install -r requirements.txt
```

## 🎯 Запуск

Запустите Flask сервер:
```bash
python app.py
```

Сервер запустится на `http://localhost:5000`

Откройте `index.html` в браузере или используйте:
```bash
start index.html
```

## 📝 API Эндпоинты

### POST /api/ip
```json
{
  "ip": "8.8.8.8",
  "session_id": "session_abc123"
}
```

### POST /api/domain
```json
{
  "domain": "google.com",
  "session_id": "session_abc123"
}
```

### POST /api/whois
```json
{
  "domain": "example.com",
  "session_id": "session_abc123"
}
```

### POST /api/dns
```json
{
  "domain": "google.com",
  "session_id": "session_abc123"
}
```

### POST /api/email
```json
{
  "email": "test@example.com",
  "session_id": "session_abc123"
}
```

### POST /api/phone
```json
{
  "phone": "+79001234567",
  "session_id": "session_abc123"
}
```

### POST /api/username
```json
{
  "username": "testuser",
  "session_id": "session_abc123"
}
```

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
