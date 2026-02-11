package main

import (
	"log"
	"lun-a-backend/internal/auth"
	"lun-a-backend/internal/db"
	"lun-a-backend/internal/middleware"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	// Load environment variables
	err := godotenv.Load()
	if err != nil {
		log.Println("Error loading .env file, using system envs")
	}

	// Initialize Database
	db.InitDB()

	r := gin.Default()

	// API v1 group
	v1 := r.Group("/api/v1")
	{
		authGroup := v1.Group("/auth")
		{
			authGroup.POST("/signup", auth.Signup)
			authGroup.POST("/signin", auth.Signin)
			authGroup.POST("/forgot-password", auth.ForgotPassword)
			authGroup.POST("/reset-password", auth.ResetPassword)
			authGroup.POST("/google", auth.GoogleSignin)

			// Protected routes
			protected := authGroup.Group("/")
			protected.Use(middleware.AuthMiddleware())
			{
				protected.DELETE("/account", auth.DeleteAccount)
				protected.POST("/disable-account", auth.DisableAccount)
			}
		}
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	r.Run(":" + port)
}
