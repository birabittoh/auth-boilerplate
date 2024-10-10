package main

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/BiRabittoh/gauth/gauth"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

type key int

type User struct {
	gorm.Model
	Username      string
	Email         string
	PasswordHash  string
	RememberToken string
	ResetToken    *string
	ResetExpires  *time.Time
}

var (
	db           *gorm.DB
	durationDay  = 24 * time.Hour
	durationWeek = 7 * durationDay
	g            = gauth.NewGauth("superSecretPepper", durationDay, durationWeek)
	templates    = template.Must(template.ParseGlob("templates/*.html"))
)

const userContextKey key = 0

func main() {
	// Connessione al database SQLite
	var err error
	db, err = gorm.Open(sqlite.Open("database.db"), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}

	// Creazione della tabella utenti
	db.AutoMigrate(&User{})

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

		var user User
		db.Where("remember_token = ?", cookie.Value).First(&user)

		if user.ID == 0 {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		ctx := context.WithValue(r.Context(), userContextKey, user)
		next(w, r.WithContext(ctx))
	}
}

func getLoggedUser(r *http.Request) (User, bool) {
	user, ok := r.Context().Value(userContextKey).(User)
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

	hashedPassword, err := g.HashPassword(password)
	if err != nil {
		http.Error(w, "Errore durante la registrazione", http.StatusInternalServerError)
		return
	}

	user := User{Username: username, Email: email, PasswordHash: hashedPassword}
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

	if user.ID == 0 || !g.CheckPassword(password, user.PasswordHash) {
		http.Error(w, "Credenziali non valide", http.StatusUnauthorized)
		return
	}

	cookie, err := g.GenerateCookie(remember == "on")
	if err != nil {
		http.Error(w, "Errore nella generazione del token", http.StatusInternalServerError)
	}

	user.RememberToken = cookie.Value
	db.Save(&user)

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
	resetToken, err := g.GenerateRandomToken()
	if err != nil {
		http.Error(w, "Errore nella generazione del token di reset", http.StatusInternalServerError)
		return
	}

	// Imposta una scadenza di 1 ora per il reset token
	expiration := time.Now().Add(1 * time.Hour)
	user.ResetToken = &resetToken
	user.ResetExpires = &expiration
	db.Save(&user)

	// Simula l'invio di un'email con il link di reset (in questo caso viene stampato sul log)
	resetURL := fmt.Sprintf("http://localhost:8080/reset-password-confirm?token=%s", resetToken)
	log.Printf("Invio dell'email di reset per %s: %s", user.Email, resetURL)

	http.Redirect(w, r, "/login", http.StatusFound)
	return

}

func validateToken(r *http.Request) (user User, err error) {
	token := r.URL.Query().Get("token")

	db.Where("reset_token = ?", token).First(&user)

	// Verifica se il token è valido e non scaduto
	if user.ResetExpires == nil {
		err = errors.New("nil value")
		return
	}

	if user.ID == 0 || time.Now().After(*user.ResetExpires) {
		err = errors.New("not found")
	}
	return
}

// Funzione per confermare il reset della password (usando il token)
func getResetPasswordConfirmHandler(w http.ResponseWriter, r *http.Request) {
	_, err := validateToken(r)
	if err != nil {
		http.Error(w, "Token non valido o scaduto", http.StatusUnauthorized)
		return
	}

	templates.ExecuteTemplate(w, "new_password.html", nil)
}

func postResetPasswordConfirmHandler(w http.ResponseWriter, r *http.Request) {
	user, err := validateToken(r)
	if err != nil {
		http.Error(w, "Token non valido o scaduto", http.StatusUnauthorized)
		return
	}

	password := r.FormValue("password")

	// Hash della nuova password
	hashedPassword, err := g.HashPassword(password)
	if err != nil {
		http.Error(w, "Errore nella modifica della password", http.StatusInternalServerError)
		return
	}

	// Aggiorna l'utente con la nuova password e rimuove il token di reset
	user.PasswordHash = hashedPassword
	user.ResetToken = nil
	user.ResetExpires = nil
	db.Save(&user)

	// Reindirizza alla pagina di login
	http.Redirect(w, r, "/login", http.StatusFound)
	return
}
