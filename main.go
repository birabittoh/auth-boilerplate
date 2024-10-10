package main

import (
	"context"
	"errors"
	"html/template"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/birabittoh/auth-boilerplate/auth"
	"github.com/birabittoh/auth-boilerplate/email"
	"github.com/birabittoh/myks"
	"github.com/glebarez/sqlite"
	"github.com/joho/godotenv"
	"gorm.io/gorm"
)

type key int

type User struct {
	gorm.Model
	Username     string
	Email        string
	PasswordHash string
	Salt         string
}

var (
	db *gorm.DB
	g  *auth.Auth
	m  *email.Client

	ks           = myks.New[uint](0)
	durationDay  = 24 * time.Hour
	durationWeek = 7 * durationDay
	templates    = template.Must(template.ParseGlob("templates/*.html"))
)

const userContextKey key = 0

func loadEmailConfig() *email.Client {
	address := os.Getenv("APP_SMTP_EMAIL")
	password := os.Getenv("APP_SMTP_PASSWORD")
	host := os.Getenv("APP_SMTP_HOST")
	port := os.Getenv("APP_SMTP_PORT")

	if address == "" || password == "" || host == "" {
		log.Println("Missing email configuration.")
		return nil
	}

	if port == "" {
		port = "587"
	}

	return email.NewClient(address, password, host, port)
}

func sendEmail(mail email.Email) error {
	if m == nil {
		return errors.New("email client is not initialized")
	}
	return m.Send(mail)
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Println("Error loading .env file")
	}

	// Connessione al database SQLite
	db, err = gorm.Open(sqlite.Open("database.db"), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}

	// Creazione della tabella utenti
	db.AutoMigrate(&User{})

	// Inizializzazione di gauth
	g = auth.NewAuth(os.Getenv("APP_PEPPER"))
	m = loadEmailConfig()

	// Gestione delle route
	http.HandleFunc("GET /", loginRequired(examplePage))
	http.HandleFunc("GET /register", getRegisterHandler)
	http.HandleFunc("GET /login", getLoginHandler)
	http.HandleFunc("GET /reset-password", getResetPasswordHandler)
	http.HandleFunc("GET /reset-password-confirm", getResetPasswordConfirmHandler)
	http.HandleFunc("GET /logout", logoutHandler)

	http.HandleFunc("POST /login", postLoginHandler)
	http.HandleFunc("POST /register", postRegisterHandler)
	http.HandleFunc("POST /reset-password", postResetPasswordHandler)
	http.HandleFunc("POST /reset-password-confirm", postResetPasswordConfirmHandler)

	port := ":8080"
	log.Println("Server running on port " + port)
	log.Fatal(http.ListenAndServe(port, nil))
}

// Middleware per controllare se l'utente è loggato.
func loginRequired(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_token")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		userID, err := ks.Get(cookie.Value)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		ctx := context.WithValue(r.Context(), userContextKey, *userID)
		next(w, r.WithContext(ctx))
	}
}

func getLoggedUser(r *http.Request) (user User, ok bool) {
	userID, ok := r.Context().Value(userContextKey).(uint)
	db.Find(&user, userID)
	return user, ok
}
