package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"time"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

type Auth struct {
	Pepper       string
	spicesLength int
}

const (
	minPasswordLength        = 6
	maxHashLength            = 72
	DefaultMaxPasswordLength = 56 // leaves 16 bytes for salt and pepper
)

func NewAuth(pepper string, maxPasswordLength uint) *Auth {
	if maxPasswordLength > 70 {
		return nil
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(pepper), bcrypt.DefaultCost)
	if err != nil {
		return nil
	}

	spicesLength := int(maxHashLength-maxPasswordLength) / 2
	return &Auth{
		Pepper:       hex.EncodeToString(hash)[:spicesLength],
		spicesLength: spicesLength,
	}
}

func (g Auth) HashPassword(password string) (hashedPassword, salt string, err error) {
	if !isASCII(password) || len(password) < minPasswordLength {
		err = errors.New("invalid password")
		return
	}

	salt, err = g.GenerateRandomToken(g.spicesLength)
	if err != nil {
		return
	}
	salt = salt[:g.spicesLength]

	bytesPassword, err := bcrypt.GenerateFromPassword([]byte(password+salt+g.Pepper), bcrypt.DefaultCost)
	if err != nil {
		return
	}

	hashedPassword = string(bytesPassword)
	return
}

func (g Auth) CheckPassword(password, salt, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password+salt+g.Pepper))
	return err == nil
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

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > unicode.MaxASCII {
			return false
		}
	}
	return true
}
