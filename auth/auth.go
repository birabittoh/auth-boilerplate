package auth

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type Auth struct {
	Pepper string
}

func NewAuth(pepper string) *Auth {
	return &Auth{
		Pepper: pepper,
	}
}

func (g Auth) HashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password+g.Pepper), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

func (g Auth) CheckPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password+g.Pepper))
	return err == nil
}

func (g Auth) GenerateRandomToken() (string, error) {
	token := make([]byte, 32)
	_, err := rand.Read(token)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(token), nil
}

func (g Auth) GenerateCookie(duration time.Duration) (*http.Cookie, error) {
	sessionToken, err := g.GenerateRandomToken()
	if err != nil {
		return nil, err
	}

	return &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Expires:  time.Now().Add(duration),
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
	}, nil
}

func (g Auth) GenerateEmptyCookie() *http.Cookie {
	return &http.Cookie{
		Name:    "session_token",
		Value:   "",
		Expires: time.Now().Add(-1 * time.Hour),
		Path:    "/",
	}
}
