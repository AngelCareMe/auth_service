package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

// Это структура для пользователя
type User struct {
	ID   int
	GUID string
}

// Это структура для сессии, где храним refresh токен и данные
type Session struct {
	ID               int
	UserID           int
	SessionID        string
	RefreshTokenHash string
	UserAgent        string
	IPAddress        string
	ExpiresAt        time.Time
}

// Глобальная переменная для базы данных
var db *sql.DB

// Загружаем настройки из .env
func loadEnv() {
	// Тут я вручную загружаю переменные, чтобы было просто
	os.Setenv("DB_HOST", getEnvOrDefault("DB_HOST", "db"))
	os.Setenv("DB_PORT", getEnvOrDefault("DB_PORT", "5432"))
	os.Setenv("DB_USER", getEnvOrDefault("DB_USER", "postgres"))
	os.Setenv("DB_PASSWORD", getEnvOrDefault("DB_PASSWORD", "password"))
	os.Setenv("DB_NAME", getEnvOrDefault("DB_NAME", "authdb"))
	os.Setenv("JWT_SECRET", getEnvOrDefault("JWT_SECRET", "mysecretkey"))
	os.Setenv("WEBHOOK_URL", getEnvOrDefault("WEBHOOK_URL", "http://example.com/webhook"))
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// Подключаемся к базе с попытками, если она не готова
func connectDB() error {
	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		os.Getenv("DB_HOST"), os.Getenv("DB_PORT"), os.Getenv("DB_USER"), os.Getenv("DB_PASSWORD"), os.Getenv("DB_NAME"))
	var err error
	for i := 0; i < 10; i++ {
		db, err = sql.Open("postgres", connStr)
		if err == nil && db.Ping() == nil {
			return nil
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("не удалось подключиться к базе: %v", err)
}

// Создаём таблицы, если их нет
func initDB() error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id SERIAL PRIMARY KEY,
			guid TEXT UNIQUE NOT NULL
		);
		CREATE TABLE IF NOT EXISTS sessions (
			id SERIAL PRIMARY KEY,
			user_id INT REFERENCES users(id),
			session_id TEXT UNIQUE NOT NULL,
			refresh_token_hash TEXT NOT NULL,
			user_agent TEXT NOT NULL,
			ip_address TEXT NOT NULL,
			expires_at TIMESTAMP NOT NULL
		);
		-- Добавляю тестового пользователя для проверки
		INSERT INTO users (guid) VALUES ('550e8400-e29b-41d4-a716-446655440000')
		ON CONFLICT (guid) DO NOTHING;
	`)
	return err
}

// Генерируем access токены
func generateAccessToken(guid, sessionID string) (string, error) {
	claims := jwt.MapClaims{
		"guid":       guid,
		"session_id": sessionID,
		"exp":        time.Now().Add(15 * time.Minute).Unix(), // Токен живёт 15 минут
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	return token.SignedString([]byte(os.Getenv("JWT_SECRET")))
}

// Проверяем access токен
func validateAccessToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_SECRET")), nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, fmt.Errorf("токен недействителен")
}

// Генерируем refresh токен
func generateRefreshToken() (string, string, error) {
	bytes := make([]byte, 32) // 32 байта для безопасности
	_, err := rand.Read(bytes)
	if err != nil {
		return "", "", err
	}
	hash, err := bcrypt.GenerateFromPassword(bytes, bcrypt.DefaultCost)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(bytes), string(hash), nil
}

// Эндпоинт для выдачи токенов
func getTokens(w http.ResponseWriter, r *http.Request) {
	guid := r.URL.Query().Get("guid")
	if guid == "" {
		http.Error(w, "нужен guid", http.StatusBadRequest)
		return
	}

	// Ищем пользователя
	var user User
	err := db.QueryRow("SELECT id, guid FROM users WHERE guid = $1", guid).Scan(&user.ID, &user.GUID)
	if err == sql.ErrNoRows {
		http.Error(w, "пользователь не найден", http.StatusUnauthorized)
		return
	} else if err != nil {
		http.Error(w, "ошибка базы", http.StatusInternalServerError)
		return
	}

	// Создаём сессию
	sessionID := fmt.Sprintf("%d-%d", time.Now().Unix(), user.ID) // Простой session_id
	refreshToken, refreshHash, err := generateRefreshToken()
	if err != nil {
		http.Error(w, "ошибка генерации токена", http.StatusInternalServerError)
		return
	}

	_, err = db.Exec(`
		INSERT INTO sessions (user_id, session_id, refresh_token_hash, user_agent, ip_address, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		user.ID, sessionID, refreshHash, r.UserAgent(), r.RemoteAddr, time.Now().Add(7*24*time.Hour))
	if err != nil {
		http.Error(w, "ошибка создания сессии", http.StatusInternalServerError)
		return
	}

	// Генерируем access токен
	accessToken, err := generateAccessToken(user.GUID, sessionID)
	if err != nil {
		http.Error(w, "ошибка генерации токена", http.StatusInternalServerError)
		return
	}

	// Отправляем токены
	json.NewEncoder(w).Encode(map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}

// Эндпоинт для обновления токенов
func refreshTokens(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "неверный запрос", http.StatusBadRequest)
		return
	}

	// Проверяем access токен
	token, err := jwt.Parse(req.AccessToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_SECRET")), nil
	})
	if err != nil {
		http.Error(w, "неверный access токен", http.StatusUnauthorized)
		return
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		http.Error(w, "неверные данные токена", http.StatusUnauthorized)
		return
	}
	guid := claims["guid"].(string)
	sessionID := claims["session_id"].(string)

	// Ищем сессию
	var session Session
	err = db.QueryRow(`
		SELECT id, user_id, session_id, refresh_token_hash, user_agent, ip_address, expires_at
		FROM sessions WHERE session_id = $1`, sessionID).Scan(
		&session.ID, &session.UserID, &session.SessionID, &session.RefreshTokenHash,
		&session.UserAgent, &session.IPAddress, &session.ExpiresAt)
	if err == sql.ErrNoRows {
		http.Error(w, "сессия не найдена", http.StatusUnauthorized)
		return
	} else if err != nil {
		http.Error(w, "ошибка базы", http.StatusInternalServerError)
		return
	}

	// Проверяем, не истекла ли сессия
	if time.Now().After(session.ExpiresAt) {
		http.Error(w, "сессия истекла", http.StatusUnauthorized)
		return
	}

	// Проверяем refresh токен
	refreshBytes, err := base64.StdEncoding.DecodeString(req.RefreshToken)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(session.RefreshTokenHash), refreshBytes) != nil {
		http.Error(w, "неверный токен", http.StatusUnauthorized)
		return
	}

	// Проверяем User агент
	if session.UserAgent != r.UserAgent() {
		db.Exec("DELETE FROM sessions WHERE session_id = $1", sessionID)
		http.Error(w, "User-Agent изменился", http.StatusForbidden)
		return
	}

	// Проверяем IP и отправляем уведомление, если надо
	if session.IPAddress != r.RemoteAddr {
		go func() {
			data := map[string]string{"guid": guid, "new_ip": r.RemoteAddr}
			jsonData, _ := json.Marshal(data)
			http.Post(os.Getenv("WEBHOOK_URL"), "application/json", strings.NewReader(string(jsonData)))
		}()
		db.Exec("UPDATE sessions SET ip_address = $1 WHERE session_id = $2", r.RemoteAddr, sessionID)
	}

	// Генерируем новые токены
	newRefreshToken, newRefreshHash, err := generateRefreshToken()
	if err != nil {
		http.Error(w, "ошибка генерации токена", http.StatusInternalServerError)
		return
	}
	newAccessToken, err := generateAccessToken(guid, sessionID)
	if err != nil {
		http.Error(w, "ошибка генерации токена", http.StatusInternalServerError)
		return
	}

	// Обновляем сессию
	_, err = db.Exec("UPDATE sessions SET refresh_token_hash = $1 WHERE session_id = $2", newRefreshHash, sessionID)
	if err != nil {
		http.Error(w, "ошибка обновления сессии", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"access_token":  newAccessToken,
		"refresh_token": newRefreshToken,
	})
}

// Middleware для проверки токена
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, "нужен токен", http.StatusUnauthorized)
			return
		}
		tokenString := strings.TrimPrefix(auth, "Bearer ")
		claims, err := validateAccessToken(tokenString)
		if err != nil {
			http.Error(w, "неверный токен", http.StatusUnauthorized)
			return
		}
		r.Header.Set("guid", claims["guid"].(string))
		r.Header.Set("session_id", claims["session_id"].(string))
		next(w, r)
	}
}

// Эндпоинт для получения гуид
func getUser(w http.ResponseWriter, r *http.Request) {
	guid := r.Header.Get("guid")
	json.NewEncoder(w).Encode(map[string]string{"guid": guid})
}

// Эндпоинт для выхода
func logout(w http.ResponseWriter, r *http.Request) {
	sessionID := r.Header.Get("session_id")
	_, err := db.Exec("DELETE FROM sessions WHERE session_id = $1", sessionID)
	if err != nil {
		http.Error(w, "ошибка выхода", http.StatusInternalServerError)
		return
	}
	w.Write([]byte("успешный выход"))
}

func main() {
	loadEnv()
	if err := connectDB(); err != nil {
		log.Fatal(err)
	}
	if err := initDB(); err != nil {
		log.Fatal(err)
	}

	// Настраиваем маршруты
	http.HandleFunc("/tokens", getTokens)
	http.HandleFunc("/refresh", refreshTokens)
	http.HandleFunc("/user", authMiddleware(getUser))
	http.HandleFunc("/logout", authMiddleware(logout))

	log.Println("Сервер запущен на :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
