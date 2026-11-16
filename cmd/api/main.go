package main

import (
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"

	"auth-service/internal/database"
	"auth-service/internal/email"
	"auth-service/internal/handler"
	"auth-service/internal/repository"
	"auth-service/internal/router"
	"auth-service/internal/security"
	"auth-service/internal/service"
)

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using system environment variables")
	}

	// Connect to PostgreSQL
	db := database.ConnectDB()
	defer db.Close()

	port := os.Getenv("APP_PORT")
	if port == "" {
		port = "8080"
	}

	// Initialize Gin
	r := gin.New()

	r.Use(
		gin.Logger(),
		gin.Recovery(),
	)

	// Do not trust forwarded proxy headers in local development.
	if err := r.SetTrustedProxies(nil); err != nil {
		log.Fatal(err)
	}

	// Health check
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":   "success",
			"message":  "Auth service is running",
			"database": "connected",
		})
	})

	// JWT configuration
	jwtManager := security.NewJWTManager(
		os.Getenv("JWT_SECRET"),
	)

	// Auth repository
	authRepo := repository.NewAuthRepository(db)

	// Email sender (Resend)
	emailSender, err := email.NewResendSender(
    os.Getenv("RESEND_API_KEY"),
    os.Getenv("RESEND_FROM"),
)
if err != nil {
    log.Fatalf("Failed to initialize Resend email sender: %v", err)
}

	// Auth service
	authService := service.NewAuthService(
		authRepo,
		emailSender,
		jwtManager,
		os.Getenv("OTP_PEPPER"),
		15*60*1000*1000*1000,      // Access token: 15 minutes
		7*24*60*60*1000*1000*1000, // Refresh token: 7 days
		10*60*1000*1000*1000,      // OTP expiry: 10 minutes
		60*1000*1000*1000,         // Resend cooldown: 60 seconds
		5,                         // Maximum OTP attempts
	)

	// Auth handler
	authHandler := handler.NewAuthHandler(authService)

	// Register authentication routes
	router.RegisterAuthRoutes(r, authHandler)

	// Print registered routes
	for _, route := range r.Routes() {
		log.Printf("Registered route: %s %s", route.Method, route.Path)
	}

	log.Println("Auth service running on port:", port)

	if err := r.Run(":" + port); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
