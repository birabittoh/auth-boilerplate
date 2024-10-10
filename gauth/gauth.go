package gauth

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type Gauth struct {
	Pepper                   string
	SessionTokenDuration     time.Duration
	LongSessionTokenDuration time.Duration
}

func NewGauth(pepper string, sessionTokenDuration, longSessionTokenDuration time.Duration) *Gauth {
	return &Gauth{
		Pepper:                   pepper,
		SessionTokenDuration:     sessionTokenDuration,
		LongSessionTokenDuration: longSessionTokenDuration,
	}
}

func (g Gauth) HashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password+g.Pepper), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

func (g Gauth) CheckPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password+g.Pepper))
	return err == nil
}

func (g Gauth) GenerateRandomToken() (string, error) {
	token := make([]byte, 32)
	_, err := rand.Read(token)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(token), nil
}

func (g Gauth) GenerateCookie(long bool) (*http.Cookie, error) {
	sessionToken, err := g.GenerateRandomToken()
	if err != nil {
		return nil, err
	}

	var expiration time.Duration
	if long {
		expiration = g.LongSessionTokenDuration
	} else {
		expiration = g.SessionTokenDuration
	}

	return &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Expires:  time.Now().Add(expiration),
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
	}, nil
}

func (g Gauth) GenerateEmptyCookie() *http.Cookie {
	return &http.Cookie{
		Name:    "session_token",
		Value:   "",
		Expires: time.Now().Add(-1 * time.Hour),
		Path:    "/",
	}
}
