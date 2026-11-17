package router

import (
	"auth-service/internal/handler"

	"github.com/gin-gonic/gin"
)

func RegisterAuthRoutes(
	r *gin.Engine,
	authHandler *handler.AuthHandler,
) {
	auth := r.Group("/api/v1/auth")

	{
		auth.POST("/signup", authHandler.Signup)

		auth.POST("/verify-email", authHandler.VerifyEmail)

		auth.POST("/resend-otp", authHandler.ResendOTP)

		auth.POST("/login", authHandler.Login)

		auth.POST("/refresh", authHandler.Refresh)

		auth.POST("/logout", authHandler.Logout)
	}
}
