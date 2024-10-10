package main

import (
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
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
	Username     string `gorm:"unique"`
	Email        string `gorm:"unique"`
	PasswordHash string
	Salt         string
}

const (
	dataDir = "data"
	dbName  = "app.db"
)

var (
	db *gorm.DB
	g  *auth.Auth
	m  *email.Client

	baseUrl string
	port    string

	ks           = myks.New[uint](0)
	durationDay  = 24 * time.Hour
	durationWeek = 7 * durationDay
	templates    = template.Must(template.ParseGlob("templates/*.html"))
)

const userContextKey key = 0

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Println("Error loading .env file")
	}

	port = os.Getenv("APP_PORT")
	if port == "" {
		port = "3000"
	}

	baseUrl = os.Getenv("APP_BASE_URL")
	if baseUrl == "" {
		baseUrl = "http://localhost:" + port
	}

	// Init auth and email
	g = auth.NewAuth(os.Getenv("APP_PEPPER"))
	m = loadEmailConfig()

	os.MkdirAll(dataDir, os.ModePerm)
	dbPath := filepath.Join(dataDir, dbName) + "?_pragma=foreign_keys(1)"
	db, err = gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}

	db.AutoMigrate(&User{})

	// Handle routes
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

	// Start serving
	log.Println("Port: " + port)
	log.Println("Server started: " + baseUrl)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
