package app

import (
	"net/http"
	"time"
)

func examplePage(w http.ResponseWriter, r *http.Request) {
	user, ok := getLoggedUser(r)
	if !ok {
		http.Error(w, "Could not find user in context.", http.StatusInternalServerError)
		return
	}

	templates.ExecuteTemplate(w, "example.html", map[string]interface{}{"User": user})
}

func getRegisterHandler(w http.ResponseWriter, r *http.Request) {
	templates.ExecuteTemplate(w, "register.html", nil)
}

func getLoginHandler(w http.ResponseWriter, r *http.Request) {
	_, err := readSessionCookie(r)
	if err != nil {
		templates.ExecuteTemplate(w, "login.html", nil)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

func getResetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	templates.ExecuteTemplate(w, "reset_password.html", nil)
}

func postRegisterHandler(w http.ResponseWriter, r *http.Request) {
	if !registrationEnabled {
		http.Error(w, "Registration is currently disabled.", http.StatusForbidden)
		return
	}

	username, err := sanitizeUsername(r.FormValue("username"))
	if err != nil {
		http.Error(w, "Invalid username.", http.StatusBadRequest)
		return
	}

	email, err := sanitizeEmail(r.FormValue("email"))
	if err != nil {
		http.Error(w, "Invalid email.", http.StatusBadRequest)
		return
	}

	hashedPassword, salt, err := g.HashPassword(r.FormValue("password"))
	if err != nil {
		http.Error(w, "Invalid password.", http.StatusBadRequest)
		return
	}

	user := User{
		Username:     username,
		Email:        email,
		PasswordHash: hashedPassword,
		Salt:         salt,
	}

	db.Create(&user)
	if user.ID == 0 {
		http.Error(w, "Username or email already exists.", http.StatusConflict)
		return
	}

	login(w, user.ID, false)
	http.Redirect(w, r, "/login", http.StatusFound)
}

func postLoginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")
	remember := r.FormValue("remember")

	var user User
	db.Where("username = ?", username).First(&user)

	if user.ID == 0 || !g.CheckPassword(password, user.Salt, user.PasswordHash) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	login(w, user.ID, remember == "on")
	http.Redirect(w, r, "/", http.StatusFound)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, g.GenerateEmptyCookie())
	http.Redirect(w, r, "/login", http.StatusFound)
}

func postResetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	emailInput := r.FormValue("email")

	var user User
	db.Where("email = ?", emailInput).First(&user)

	if user.ID == 0 {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	resetToken, err := g.GenerateRandomToken(32)
	if err != nil {
		http.Error(w, "Could not generate reset token.", http.StatusInternalServerError)
		return
	}

	ks.Set(resetToken, user.ID, time.Hour)
	sendResetEmail(user.Email, resetToken)

	http.Redirect(w, r, "/login", http.StatusFound)

}

func getResetPasswordConfirmHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	_, err := ks.Get(token)
	if err != nil {
		http.Error(w, "Token is invalid or expired.", http.StatusUnauthorized)
		return
	}

	templates.ExecuteTemplate(w, "new_password.html", nil)
}

func postResetPasswordConfirmHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	userID, err := ks.Get(token)
	if err != nil {
		http.Error(w, "Token is invalid or expired.", http.StatusUnauthorized)
		return
	}

	var user User
	db.First(&user, *userID)

	password := r.FormValue("password")

	hashedPassword, salt, err := g.HashPassword(password)
	if err != nil {
		http.Error(w, "Invalid password.", http.StatusBadRequest)
		return
	}

	user.PasswordHash = hashedPassword
	user.Salt = salt
	db.Save(&user)
	ks.Delete(token)

	http.Redirect(w, r, "/login", http.StatusFound)
}
