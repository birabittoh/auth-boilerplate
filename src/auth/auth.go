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

func (g Auth) HashPassword(password string) (hashedPassword, salt string, err error) {
	salt, err = g.GenerateRandomToken(16)
	if err != nil {
		return
	}

	bytesPassword, err := bcrypt.GenerateFromPassword([]byte(password+salt+g.Pepper), bcrypt.DefaultCost)
	if err != nil {
		return
	}
	hashedPassword = string(bytesPassword)
	return
}

func (g Auth) CheckPassword(password, salt, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password+salt+g.Pepper)) == nil
}

func (g Auth) GenerateRandomToken(n int) (string, error) {
	token := make([]byte, n)
	_, err := rand.Read(token)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(token), nil
}

func (g Auth) GenerateCookie(duration time.Duration) (*http.Cookie, error) {
	sessionToken, err := g.GenerateRandomToken(32)
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
