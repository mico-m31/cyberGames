package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
	"github.com/joho/godotenv"
	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)


type User struct {
	ID           int    `json:"id"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	CaptchaToken string `json:"captchaToken"`
}

type Response struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type Session struct {
	UserID    int
	Username  string
	ExpiresAt time.Time
}

var (
	db        *sql.DB
	templates *template.Template
	sessions  = make(map[string]*Session) 
	sessionMu sync.RWMutex                
)

func init() {
	err_env := godotenv.Load("../.env")
	if err_env != nil {
		log.Fatal("Error loading .env file")
	}
	DB_HOST := os.Getenv("DB_HOST")
	DB_USER := os.Getenv("DB_USER")
	DB_PASSWORD := os.Getenv("DB_PASSWORD")
	DB_NAME := os.Getenv("DB_NAME")
	var err error
	db, err = sql.Open("mysql", DB_USER+":"+DB_PASSWORD+"@tcp("+DB_HOST+":3306)/"+DB_NAME+"?parseTime=true")
	if err != nil {
		log.Fatal(err)
	}

	createTable := `
        CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL
        );`
	_, err = db.Exec(createTable)
	if err != nil {
		log.Fatal(err)
	}

	createProgressTable := `
        CREATE TABLE IF NOT EXISTS game_progress (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                game_name VARCHAR(255) NOT NULL,
                completed BOOLEAN NOT NULL DEFAULT FALSE,
                completed_at DATETIME,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );`
	_, err = db.Exec(createProgressTable)
	if err != nil {
		log.Fatal(err)
	}

	go cleanupExpiredSessions()

	templates = template.Must(template.ParseGlob("templates/*.html"))
}

func generateSessionToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func createSession(userID int, username string) (string, error) {
	token, err := generateSessionToken()
	if err != nil {
		return "", err
	}

	sessionMu.Lock()
	defer sessionMu.Unlock()

	sessions[token] = &Session{
		UserID:    userID,
		Username:  username,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	return token, nil
}

func getSession(token string) (*Session, bool) {
	sessionMu.RLock()
	defer sessionMu.RUnlock()

	session, exists := sessions[token]
	if !exists || time.Now().After(session.ExpiresAt) {
		return nil, false
	}
	return session, true
}

func deleteSession(token string) {
	sessionMu.Lock()
	defer sessionMu.Unlock()
	delete(sessions, token)
}

func cleanupExpiredSessions() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		sessionMu.Lock()
		now := time.Now()
		for token, session := range sessions {
			if now.After(session.ExpiresAt) {
				delete(sessions, token)
			}
		}
		sessionMu.Unlock()
	}
}

func requireAuth(w http.ResponseWriter, r *http.Request) (*Session, bool) {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "Not authenticated",
		})
		return nil, false
	}

	session, valid := getSession(cookie.Value)
	if !valid {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "Invalid or expired session",
		})
		return nil, false
	}

	return session, true
}

func main() {
	err := godotenv.Load("../.env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	noCache := func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
			w.Header().Set("Pragma", "no-cache")
			w.Header().Set("Expires", "0")
			h.ServeHTTP(w, r)
		})
	}

	http.Handle("/level_1/", http.StripPrefix("/level_1/", http.FileServer(http.Dir("../level_1"))))
	http.Handle("/level_2/", noCache(http.StripPrefix("/level_2/", http.FileServer(http.Dir("../level_2_v2")))))
	http.Handle("/level_3/", http.StripPrefix("/level_3/", http.FileServer(http.Dir("../level_3"))))
	http.Handle("/level_4/", http.StripPrefix("/level_4/", http.FileServer(http.Dir("../level_4"))))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		http.ServeFile(w, r, "../index.html")
	})

	http.HandleFunc("/guide", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "../userManualGuide.html")
	})

	http.HandleFunc("/login", handleLoginPage)
	http.HandleFunc("/register", handleRegisterPage)
	http.HandleFunc("/api/register", handleRegister)
	http.HandleFunc("/api/login", handleLogin)
	http.HandleFunc("/api/logout", handleLogout)
	http.HandleFunc("/api/check-auth", handleCheckAuth)
	http.HandleFunc("/api/complete-level", handleCompleteLevel)
	http.HandleFunc("/game", handlegame)
	http.HandleFunc("/api/progress", handleProgress)

	log.Println("Server starting on :80...")
	port := os.Getenv("PORT")
	if port == "" {
		port = "80"
	}
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func handleProgress(w http.ResponseWriter, r *http.Request) {
	session, authenticated := requireAuth(w, r)
	if !authenticated {
		return
	}

	rows, err := db.Query(`
                SELECT game_name, completed, completed_at
                FROM game_progress
                WHERE user_id = ?`, session.UserID)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "Database error",
		})
		return
	}
	defer rows.Close()

	progress := []map[string]interface{}{}
	for rows.Next() {
		var gameName string
		var completed bool
		var completedAt sql.NullTime

		err := rows.Scan(&gameName, &completed, &completedAt)
		if err != nil {
			continue
		}

		progress = append(progress, map[string]interface{}{
			"game_name": gameName,
			"completed": completed,
			"completed_at": func() string {
				if completedAt.Valid {
					return completedAt.Time.Format("2006-01-02 15:04:05")
				}
				return ""
			}(),
		})
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":  true,
		"progress": progress,
	})
}

func handlegame(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("../index.html"))
	tmpl.Execute(w, nil)
}

func handleLoginPage(w http.ResponseWriter, r *http.Request) {
	templates.ExecuteTemplate(w, "login.html", nil)
}

func handleRegisterPage(w http.ResponseWriter, r *http.Request) {
	templates.ExecuteTemplate(w, "register.html", nil)
}

func verifyCaptcha(token string) bool {
	secret := os.Getenv("RECAPTCHA_SECRET_KEY")
	resp, err := http.PostForm("https://www.google.com/recaptcha/api/siteverify",
		url.Values{"secret": {secret}, "response": {token}})
	if err != nil {
		log.Println("CAPTCHA verification failed:", err)
		return false
	}
	defer resp.Body.Close()

	var result struct {
		Success bool `json:"success"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Println("Error decoding CAPTCHA response:", err)
		return false
	}
	return result.Success
}

func validatePassword(password string) (bool, string) {
	if len(password) < 8 {
		return false, "Password must be at least 8 characters long"
	}

	hasUpper := false
	hasSymbol := false

	for _, char := range password {
		if char >= 'A' && char <= 'Z' {
			hasUpper = true
		}
		if (char >= '!' && char <= '/') || (char >= ':' && char <= '@') || (char >= '[' && char <= '`') || (char >= '{' && char <= '~') {
			hasSymbol = true
		}
	}

	if !hasUpper {
		return false, "Password must contain at least one uppercase letter"
	}
	if !hasSymbol {
		return false, "Password must contain at least one special symbol"
	}

	return true, ""
}

func handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if valid, message := validatePassword(user.Password); !valid {
		response := Response{
			Success: false,
			Message: message,
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error processing password", http.StatusInternalServerError)
		return
	}

	_, err = db.Exec("INSERT INTO users (username, password) VALUES (?, ?)",
		user.Username, string(hashedPassword))
	if err != nil {
		response := Response{
			Success: false,
			Message: "Username already exists",
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	response := Response{
		Success: true,
		Message: "Registration successful",
	}
	json.NewEncoder(w).Encode(response)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if !verifyCaptcha(user.CaptchaToken) {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "CAPTCHA verification failed",
		})
		return
	}

	if len(user.Username) < 3 || len(user.Username) > 50 {
		response := Response{
			Success: false,
			Message: "Invalid username length",
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	if len(user.Password) < 6 {
		response := Response{
			Success: false,
			Message: "Password too short",
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	user.Username = strings.TrimSpace(user.Username)
	user.Username = strings.ReplaceAll(user.Username, "'", "")
	user.Username = strings.ReplaceAll(user.Username, "\"", "")
	user.Username = strings.ReplaceAll(user.Username, ";", "")

	stmt, err := db.Prepare("SELECT id, username, password FROM users WHERE username = ? LIMIT 1")
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer stmt.Close()

	var storedUser User
	var hashedPassword string
	err = stmt.QueryRow(user.Username).Scan(&storedUser.ID, &storedUser.Username, &hashedPassword)
	if err != nil {
		response := Response{
			Success: false,
			Message: "Invalid username or password",
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(user.Password))
	if err != nil {
		response := Response{
			Success: false,
			Message: "Invalid username or password",
		}
		json.NewEncoder(w).Encode(response)
		return
	}
						
	sessionToken, err := createSession(storedUser.ID, storedUser.Username)
	if err != nil {
		http.Error(w, "Error creating session", http.StatusInternalServerError)
		return
	}

	cookie := http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Path:     "/",
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, &cookie)

	response := Response{
		Success: true,
		Message: "Login successful",
	}
	json.NewEncoder(w).Encode(response)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cookie, err := r.Cookie("session_token")
	if err == nil {
		deleteSession(cookie.Value)
	}

	cookie = &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Path:     "/",
		Expires:  time.Now().Add(-1 * time.Hour),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, cookie)

	response := Response{
		Success: true,
		Message: "Logged out successfully",
	}
	json.NewEncoder(w).Encode(response)
}

func handleCheckAuth(w http.ResponseWriter, r *http.Request) {
	session, authenticated := requireAuth(w, r)
	if !authenticated {
		return
	}

	response := Response{
		Success: true,
		Message: session.Username,
	}
	json.NewEncoder(w).Encode(response)
}

func handleCompleteLevel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	session, authenticated := requireAuth(w, r)
	if !authenticated {
		return
	}

	gameName := r.URL.Query().Get("game_name")
	if gameName == "" {
		http.Error(w, "Game name not specified", http.StatusBadRequest)
		return
	}
	if gameName == "Phising Detector(Level_2)" {
		gameName = "Phising Detector(Level_2)"
	}
	if gameName == "Password Game(Level_3)" {
		gameName = "Password Game(Level_3)"
	}

	if gameName == "Malware Attack(Level_4)" {
		gameName = "Malware Attack(Level_4)"
	}

	_, err := db.Exec(`
                INSERT INTO game_progress
                (user_id, game_name, completed, completed_at)
                VALUES (?, ?, TRUE, NOW())
                ON DUPLICATE KEY UPDATE
                completed = TRUE,
                completed_at = NOW()`,
		session.UserID, gameName)

	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	response := Response{
		Success: true,
		Message: "Game marked as complete",
	}
	json.NewEncoder(w).Encode(response)
}
