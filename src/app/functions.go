package app

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/birabittoh/auth-boilerplate/src/email"
)

const (
	minUsernameLength = 3
	maxUsernameLength = 10
)

var (
	validUsername = regexp.MustCompile(`(?i)^[a-z0-9._-]+$`)
	validEmail    = regexp.MustCompile(`^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$`)
)

func getUserByName(username string, excluding uint) (user User, err error) {
	err = db.Model(&User{}).Where("upper(username) == upper(?) AND id != ?", username, excluding).First(&user).Error
	return
}

func sanitizeUsername(username string) (string, error) {
	if !validUsername.MatchString(username) || len(username) < minUsernameLength || len(username) > maxUsernameLength {
		return "", errors.New("invalid username")
	}

	return username, nil
}

func sanitizeEmail(email string) (string, error) {
	email = strings.ToLower(email)

	if !validEmail.MatchString(email) {
		return "", fmt.Errorf("invalid email")
	}

	return email, nil
}

func login(w http.ResponseWriter, userID uint, remember bool) {
	var duration time.Duration
	if remember {
		duration = durationWeek
	} else {
		duration = durationDay
	}

	cookie, err := g.GenerateCookie(duration)
	if err != nil {
		http.Error(w, "Could not generate session cookie.", http.StatusInternalServerError)
	}

	ks.Set("session:"+cookie.Value, userID, duration)
	http.SetCookie(w, cookie)
}

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

func sendResetEmail(address, token string) {
	resetURL := fmt.Sprintf("%s/reset-password-confirm?token=%s", baseUrl, token)
	err := sendEmail(email.Email{
		To:      []string{address},
		Subject: "Reset password",
		Body:    fmt.Sprintf("Use the following link to reset your password:\n%s", resetURL),
	})
	if err != nil {
		log.Printf("Could not send reset email for %s. Link: %s", address, resetURL)
	}
}

func readSessionCookie(r *http.Request) (userID *uint, err error) {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		return
	}
	return ks.Get("session:" + cookie.Value)
}

// Middleware to check if the user is logged in
func loginRequired(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, err := readSessionCookie(r)
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
