package app

import (
	"net/http"
	"time"
)

func getIndexHandler(w http.ResponseWriter, r *http.Request) {
	xt.ExecuteTemplate(w, "index.tmpl", nil)
}

func getProfileHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := getLoggedUser(r)
	if !ok {
		showError(w, "Could not find user in context.", http.StatusInternalServerError)
		return
	}

	xt.ExecuteTemplate(w, "profile.tmpl", map[string]interface{}{"User": user})
}

func getRegisterHandler(w http.ResponseWriter, r *http.Request) {
	xt.ExecuteTemplate(w, "auth-register.tmpl", nil)
}

func getLoginHandler(w http.ResponseWriter, r *http.Request) {
	_, err := readSessionCookie(r)
	if err != nil {
		xt.ExecuteTemplate(w, "auth-login.tmpl", nil)
		return
	}
	http.Redirect(w, r, "/profile", http.StatusFound)
}

func getResetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	xt.ExecuteTemplate(w, "auth-reset_password.tmpl", nil)
}

func postRegisterHandler(w http.ResponseWriter, r *http.Request) {
	if !registrationEnabled {
		showError(w, "Registration is currently disabled.", http.StatusForbidden)
		return
	}

	username, err := sanitizeUsername(r.FormValue("username"))
	if err != nil {
		showError(w, "Invalid username.", http.StatusBadRequest)
		return
	}

	email, err := sanitizeEmail(r.FormValue("email"))
	if err != nil {
		showError(w, "Invalid email.", http.StatusBadRequest)
		return
	}

	_, err = getUserByName(username, 0)
	if err == nil {
		showError(w, "This username is already registered.", http.StatusConflict)
		return
	}

	_, err = getUserByEmail(email, 0)
	if err == nil {
		showError(w, "This email is already registered.", http.StatusConflict)
		return
	}

	hashedPassword, salt, err := g.HashPassword(r.FormValue("password"))
	if err != nil {
		showError(w, "Invalid password.", http.StatusBadRequest)
		return
	}

	user := User{
		Username:     username,
		Email:        email,
		PasswordHash: hashedPassword,
		Salt:         salt,
	}

	err = db.Create(&user).Error
	if err != nil {
		showError(w, "Could not create user.", http.StatusInternalServerError)
		return
	}

	login(w, user.ID, false)
	http.Redirect(w, r, "/login", http.StatusFound)
}

func postLoginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")
	remember := r.FormValue("remember")

	user, err := getUserByName(username, 0)

	if err != nil || !g.CheckPassword(password, user.Salt, user.PasswordHash) {
		showError(w, "Invalid credentials.", http.StatusUnauthorized)
		return
	}

	login(w, user.ID, remember == "on")
	http.Redirect(w, r, "/login", http.StatusFound)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, g.GenerateEmptyCookie())
	http.Redirect(w, r, "/login", http.StatusFound)
}

func postResetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	emailInput := r.FormValue("email")

	var user User
	err := db.Where("email = ?", emailInput).First(&user).Error
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	resetToken, err := g.GenerateRandomToken(32)
	if err != nil {
		showError(w, "Could not generate reset token.", http.StatusInternalServerError)
		return
	}

	ks.Set("reset:"+resetToken, user.ID, time.Hour)
	sendResetEmail(user.Email, resetToken)

	http.Redirect(w, r, "/login", http.StatusFound)

}

func getResetPasswordConfirmHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	_, err := ks.Get("reset:" + token)
	if err != nil {
		showError(w, "Token is invalid or expired.", http.StatusUnauthorized)
		return
	}

	xt.ExecuteTemplate(w, "auth-new_password.tmpl", nil)
}

func postResetPasswordConfirmHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	userID, err := ks.Get("reset:" + token)
	if err != nil {
		showError(w, "Token is invalid or expired.", http.StatusUnauthorized)
		return
	}

	var user User
	err = db.First(&user, *userID).Error
	if err != nil {
		showError(w, "Could not get user.", http.StatusInternalServerError)
	}

	password := r.FormValue("password")

	hashedPassword, salt, err := g.HashPassword(password)
	if err != nil {
		showError(w, "Invalid password.", http.StatusBadRequest)
		return
	}

	user.PasswordHash = hashedPassword
	user.Salt = salt
	err = db.Save(&user).Error
	if err != nil {
		showError(w, "Could not save user.", http.StatusInternalServerError)
	}
	ks.Delete(token)

	http.Redirect(w, r, "/login", http.StatusFound)
}
