package auth

import (
	"database/sql"
	"fmt"
	"lun-a-backend/internal/db"
	"lun-a-backend/internal/utils"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

type User struct {
	ID         int    `db:"id" json:"id"`
	Email      string `db:"email" json:"email"`
	Password   string `db:"password" json:"-"`
	IsDisabled bool   `db:"is_disabled" json:"is_disabled"`
}

type SignupRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
}

type SigninRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type ForgotPasswordRequest struct {
	Email string `json:"email" binding:"required,email"`
}

type ResetPasswordRequest struct {
	Token    string `json:"token" binding:"required"`
	Password string `json:"password" binding:"required,min=8"`
}

type GoogleSigninRequest struct {
	IDToken string `json:"id_token" binding:"required"`
}

func Signup(c *gin.Context) {
	var req SignupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hashedPassword, err := utils.HashPassword(req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not hash password"})
		return
	}

	_, err = db.DB.Exec("INSERT INTO users (email, password) VALUES (?, ?)", req.Email, hashedPassword)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "user already exists"})
		return
	}

	// Send welcome email
	go func() {
		subject := "Welcome to Lun-A!"
		body := fmt.Sprintf("Hi %s,\n\nThanks for signing up for Lun-A. We're glad to have you!", req.Email)
		utils.SendEmail(req.Email, subject, body)
	}()

	c.JSON(http.StatusCreated, gin.H{"message": "user created successfully"})
}

func Signin(c *gin.Context) {
	var req SigninRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user User
	err := db.DB.Get(&user, "SELECT * FROM users WHERE email = ?", req.Email)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database error"})
		return
	}

	if user.IsDisabled {
		c.JSON(http.StatusForbidden, gin.H{"error": "account is disabled"})
		return
	}

	if !utils.CheckPasswordHash(req.Password, user.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	token, err := utils.GenerateJWT(user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": token})
}

func ForgotPassword(c *gin.Context) {
	var req ForgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// In a real app, verify user exists first
	token := utils.GenerateRandomToken()
	expiresAt := time.Now().Add(1 * time.Hour)

	_, err := db.DB.Exec("INSERT INTO password_resets (email, token, expires_at) VALUES (?, ?, ?)", req.Email, token, expiresAt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not process request"})
		return
	}

	// Send reset email
	go func() {
		subject := "Password Reset Request"
		body := fmt.Sprintf("You requested a password reset. Use the following token to reset your password: %s\n\nThis token expires in 1 hour.", token)
		utils.SendEmail(req.Email, subject, body)
	}()

	c.JSON(http.StatusOK, gin.H{"message": "password reset email sent", "token": token})
}

func ResetPassword(c *gin.Context) {
	var req ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var email string
	var expiresAt time.Time
	err := db.DB.QueryRow("SELECT email, expires_at FROM password_resets WHERE token = ?", req.Token).Scan(&email, &expiresAt)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid token"})
		return
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database error"})
		return
	}

	if time.Now().After(expiresAt) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "token expired"})
		return
	}

	hashedPassword, err := utils.HashPassword(req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not hash password"})
		return
	}

	_, err = db.DB.Exec("UPDATE users SET password = ? WHERE email = ?", hashedPassword, email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not update password"})
		return
	}

	// Delete used token
	db.DB.Exec("DELETE FROM password_resets WHERE token = ?", req.Token)

	c.JSON(http.StatusOK, gin.H{"message": "password reset successfully"})
}

func GoogleSignin(c *gin.Context) {
	var req GoogleSigninRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	email := "google_user@example.com"
	googleID := "google_id_123"

	var user User
	err := db.DB.Get(&user, "SELECT * FROM users WHERE google_id = ?", googleID)
	if err == sql.ErrNoRows {
		// Create new user if they don't exist
		_, err = db.DB.Exec("INSERT INTO users (email, password, google_id) VALUES (?, ?, ?)", email, "google_auth_no_password", googleID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "could not create user"})
			return
		}
		db.DB.Get(&user, "SELECT * FROM users WHERE google_id = ?", googleID)
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database error"})
		return
	}

	token, err := utils.GenerateJWT(user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": token})
}

func DeleteAccount(c *gin.Context) {
	userID := c.MustGet("userID").(int)

	_, err := db.DB.Exec("DELETE FROM users WHERE id = ?", userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not delete account"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "account deleted successfully"})
}

func DisableAccount(c *gin.Context) {
	userID := c.MustGet("userID").(int)

	_, err := db.DB.Exec("UPDATE users SET is_disabled = TRUE WHERE id = ?", userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not disable account"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "account disabled successfully"})
}
