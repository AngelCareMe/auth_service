# Auth Service

Это сервис аутентификации, реализованный на Go с использованием PostgreSQL и Docker. Сервис предоставляет API для получения токенов, их обновления, получения GUID пользователя и выхода из системы.

## Технологии
- **Go** (1.18)
- **PostgreSQL** (13)
- **Docker** и **Docker Compose**
- Зависимости:
  - `github.com/golang-jwt/jwt/v4` для JWT-токенов
  - `golang.org/x/crypto/bcrypt` для хеширования refresh-токенов
  - `github.com/lib/pq` для работы с PostgreSQL

## Установка и запуск

### Требования
- Установлены Docker и Docker Compose
- Go 1.18+ (для локальной разработки)

### Запуск через Docker
1. Склонируй репозиторий:
   ```bash
   git clone <your-repo-url>
   cd <your-repo-dir>
   ```
2. Убедись, что файл `.env` существует в корне проекта. Пример:
   ```
   DB_USER=postgres
   DB_PASSWORD=password
   DB_NAME=authdb
   JWT_SECRET=mysecretkey
   WEBHOOK_URL=http://example.com/webhook
   ```
3. Запусти сервис:
   ```bash
   docker-compose -f docker-compose.yml up -d
   ```
   Это развернёт приложение и базу данных. Сервис будет доступен на `http://localhost:8080`.

4. Проверь логи, если что-то не работает:
   ```bash
   docker-compose logs
   ```

### Локальная разработка
1. Инициализируй Go-модуль и установи зависимости:
   ```bash
   go mod init auth-service
   go get github.com/golang-jwt/jwt/v4
   go get golang.org/x/crypto/bcrypt
   go get github.com/lib/pq
   ```
2. Убедись, что PostgreSQL запущен локально, и обнови `.env` с нужными параметрами.
3. Запусти приложение:
   ```bash
   go run main.go
   ```

## API
API описано в `swagger.yaml`. Основные эндпоинты:
- **GET /tokens?guid=<guid>** — Получить access и refresh токены.
  - Пример: `curl "http://localhost:8080/tokens?guid=550e8400-e29b-41d4-a716-446655440000"`
- **POST /refresh** — Обновить токены.
  - Пример: `curl -X POST "http://localhost:8080/refresh" -d '{"access_token":"...","refresh_token":"..."}'`
- **GET /user** — Получить GUID текущего пользователя (требуется Bearer-токен).
  - Пример: `curl -H "Authorization: Bearer <token>" "http://localhost:8080/user"`
- **POST /logout** — Выйти из системы (требуется Bearer-токен).
  - Пример: `curl -X POST -H "Authorization: Bearer <token>" "http://localhost:8080/logout"`

Для полной документации используй `swagger.yaml` с инструментами вроде Swagger UI.

## Структура проекта
```
.
├── Dockerfile        # Docker-образ для приложения
├── docker-compose.yml # Конфигурация Docker Compose
├── .env              # Переменные окружения
├── go.mod            # Зависимости Go
├── main.go           # Основной файл с логикой сервера
└── swagger.yaml      # Swagger-документация API
```

## Особенности
- **Access токен**: JWT с алгоритмом SHA512, срок действия 15 минут.
- **Refresh токен**: Хранится как bcrypt-хеш, передаётся в base64, защищён от повторного использования.
- Проверка User-Agent и IP при обновлении токенов.
- Уведомление через webhook при смене IP.

## Тестирование
1. Запусти сервис через Docker.
2. Используй тестовый GUID: `550e8400-e29b-41d4-a716-446655440000`.
3. Выполни запросы через `curl` или Postman, следуя примерам выше.

## Примечания
- Сервис запускается одной командой: `docker-compose -f docker-compose.yml up -d`.
- Логика реализована максимально просто для демонстрации навыков Junior-разработчика.
- Для production рекомендуется добавить HTTPS и более сложный ключ для JWT.