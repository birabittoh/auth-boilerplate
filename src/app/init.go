package app

import (
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/birabittoh/auth-boilerplate/src/auth"
	"github.com/birabittoh/auth-boilerplate/src/email"
	"github.com/birabittoh/myks"
	"github.com/glebarez/sqlite"
	"github.com/joho/godotenv"
	"github.com/utking/extemplate"
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
	xt *extemplate.Extemplate

	baseUrl             string
	port                string
	registrationEnabled = true

	ks           = myks.New[uint](0)
	durationDay  = 24 * time.Hour
	durationWeek = 7 * durationDay
)

const userContextKey key = 0

func Main() {
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

	e := strings.ToLower(os.Getenv("APP_REGISTRATION_ENABLED"))
	if e == "false" || e == "0" {
		registrationEnabled = false
	}

	// Init auth and email
	m = loadEmailConfig()
	g = auth.NewAuth(os.Getenv("APP_PEPPER"), auth.DefaultMaxPasswordLength)
	if g == nil {
		log.Fatal("Could not init authentication.")
	}

	os.MkdirAll(dataDir, os.ModePerm)
	dbPath := filepath.Join(dataDir, dbName) + "?_pragma=foreign_keys(1)"
	db, err = gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}

	db.AutoMigrate(&User{})

	// Init template engine
	xt = extemplate.New()
	err = xt.ParseDir("templates", []string{".tmpl"})
	if err != nil {
		log.Fatal(err)
	}

	// Handle routes
	http.HandleFunc("GET /", getIndexHandler)
	http.HandleFunc("GET /profile", loginRequired(getProfileHandler))
	http.HandleFunc("GET /register", getRegisterHandler)
	http.HandleFunc("GET /login", getLoginHandler)
	http.HandleFunc("GET /reset-password", getResetPasswordHandler)
	http.HandleFunc("GET /reset-password-confirm", getResetPasswordConfirmHandler)
	http.HandleFunc("GET /logout", logoutHandler)

	http.HandleFunc("POST /login", postLoginHandler)
	http.HandleFunc("POST /register", postRegisterHandler)
	http.HandleFunc("POST /reset-password", postResetPasswordHandler)
	http.HandleFunc("POST /reset-password-confirm", postResetPasswordConfirmHandler)

	http.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// Start serving
	log.Println("Port: " + port)
	log.Println("Server started: " + baseUrl)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
