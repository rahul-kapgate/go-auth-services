package router

import (
	"github.com/gin-gonic/gin"

	"auth-service/internal/handler"
)

func RegisterAuthRoutes(
	r *gin.Engine,
	authHandler *handler.AuthHandler,
) {
	auth := r.Group("/api/auth")

	// Registration and email verification
	auth.POST("/signup", authHandler.Signup)
	auth.POST("/email/verify", authHandler.VerifyEmail)
	auth.POST("/email/resend", authHandler.ResendOTP)

	// Authentication
	auth.POST("/login", authHandler.Login)
	auth.POST("/refresh", authHandler.Refresh)
	auth.POST("/logout", authHandler.Logout)
}
