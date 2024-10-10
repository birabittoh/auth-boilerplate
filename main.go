package main

import (
	"context"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/birabittoh/auth-boilerplate/auth"
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

	// Connessione al database SQLite
	db, err = gorm.Open(sqlite.Open("database.db"), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}

	// Creazione della tabella utenti
	db.AutoMigrate(&User{})

	// Inizializzazione di gauth
	g = auth.NewAuth(os.Getenv("APP_PEPPER"))

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
	log.Println("Server in ascolto su " + port)
	log.Fatal(http.ListenAndServe(port, nil))
}

// Middleware per controllare se l'utente è loggato
// Funzione middleware per controllare se l'utente è autenticato
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

func examplePage(w http.ResponseWriter, r *http.Request) {
	user, ok := getLoggedUser(r)
	if !ok {
		http.Error(w, "Utente non trovato nel contesto", http.StatusInternalServerError)
		return
	}

	templates.ExecuteTemplate(w, "example.html", map[string]interface{}{"User": user})
}

func getRegisterHandler(w http.ResponseWriter, r *http.Request) {
	templates.ExecuteTemplate(w, "register.html", nil)
}

func getLoginHandler(w http.ResponseWriter, r *http.Request) {
	templates.ExecuteTemplate(w, "login.html", nil)
}

func getResetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	templates.ExecuteTemplate(w, "reset_password.html", nil)
}

// Gestione della registrazione
func postRegisterHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	email := r.FormValue("email")
	password := r.FormValue("password")

	hashedPassword, salt, err := g.HashPassword(password)
	if err != nil {
		log.Printf("Error: %v", err)
		http.Error(w, "Errore durante la registrazione", http.StatusInternalServerError)
		return
	}

	user := User{
		Username:     username,
		Email:        email,
		PasswordHash: hashedPassword,
		Salt:         salt,
	}
	db.Create(&user)
	http.Redirect(w, r, "/login", http.StatusFound)
	return
}

// Gestione del login
func postLoginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")
	remember := r.FormValue("remember")

	var user User
	db.Where("username = ?", username).First(&user)

	if user.ID == 0 || !g.CheckPassword(password, user.Salt, user.PasswordHash) {
		http.Error(w, "Credenziali non valide", http.StatusUnauthorized)
		return
	}

	var duration time.Duration
	if remember == "on" {
		duration = durationWeek
	} else {
		duration = durationDay
	}

	cookie, err := g.GenerateCookie(duration)
	if err != nil {
		http.Error(w, "Errore nella generazione del token", http.StatusInternalServerError)
	}

	ks.Set(cookie.Value, user.ID, duration)
	http.SetCookie(w, cookie)
	http.Redirect(w, r, "/", http.StatusFound)
	return
}

// Logout
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, g.GenerateEmptyCookie())
	http.Redirect(w, r, "/login", http.StatusFound)
}

// Funzione per gestire la richiesta di reset password
func postResetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")

	var user User
	db.Where("email = ?", email).First(&user)

	if user.ID == 0 {
		// Non riveliamo se l'email non esiste per motivi di sicurezza
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// Genera un token di reset
	resetToken, err := g.GenerateRandomToken(32)
	if err != nil {
		http.Error(w, "Errore nella generazione del token di reset", http.StatusInternalServerError)
		return
	}

	// Imposta una scadenza di 1 ora per il reset token
	ks.Set(resetToken, user.ID, time.Hour)

	// Simula l'invio di un'email con il link di reset (in questo caso viene stampato sul log)
	resetURL := fmt.Sprintf("http://localhost:8080/reset-password-confirm?token=%s", resetToken)
	log.Printf("Invio dell'email di reset per %s: %s", user.Email, resetURL)

	http.Redirect(w, r, "/login", http.StatusFound)
	return

}

// Funzione per confermare il reset della password (usando il token)
func getResetPasswordConfirmHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	_, err := ks.Get(token)
	if err != nil {
		http.Error(w, "Token non valido o scaduto", http.StatusUnauthorized)
		return
	}

	templates.ExecuteTemplate(w, "new_password.html", nil)
}

func postResetPasswordConfirmHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	userID, err := ks.Get(token)
	if err != nil {
		http.Error(w, "Token non valido o scaduto", http.StatusUnauthorized)
		return
	}

	var user User
	db.First(&user, *userID)

	password := r.FormValue("password")

	// Hash della nuova password
	hashedPassword, salt, err := g.HashPassword(password)
	if err != nil {
		http.Error(w, "Errore nella modifica della password", http.StatusInternalServerError)
		return
	}

	// Aggiorna l'utente con la nuova password e rimuove il token di reset
	user.PasswordHash = hashedPassword
	user.Salt = salt
	db.Save(&user)
	ks.Delete(token)

	// Reindirizza alla pagina di login
	http.Redirect(w, r, "/login", http.StatusFound)
	return
}
