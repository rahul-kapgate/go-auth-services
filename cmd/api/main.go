package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"

	"auth-service/internal/database"
	"auth-service/internal/email"
	"auth-service/internal/handler"
	"auth-service/internal/repository"
	"auth-service/internal/router"
	"auth-service/internal/security"
	"auth-service/internal/service"

	docs "auth-service/docs"

	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// @title Go Auth Service API
// @version 1.0
// @description Authentication service with email OTP, JWT access tokens and refresh tokens.
// @host localhost:8080
// @BasePath /api/v1/auth
// @schemes http
func main() {
	// Load environment variables.
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using system environment variables")
	}

	// Application environment.
	appEnv := os.Getenv("APP_ENV")

	if appEnv == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	// Read application configuration.
	port := os.Getenv("APP_PORT")
	if port == "" {
		port = "8080"
	}

	accessTTL := mustDuration("ACCESS_TOKEN_TTL")
	refreshTTL := mustDuration("REFRESH_TOKEN_TTL")
	otpTTL := mustDuration("OTP_EXPIRY")
	otpCooldown := mustDuration("OTP_RESEND_COOLDOWN")

	otpMaxAttempts := mustInt("OTP_MAX_ATTEMPTS")
	cookieSecure := mustBool("COOKIE_SECURE")

	cookieSameSite := strings.TrimSpace(
		os.Getenv("COOKIE_SAME_SITE"),
	)
	if cookieSameSite == "" {
		cookieSameSite = "lax"
	}

	// Connect to MongoDB.
	connectCtx, connectCancel := context.WithTimeout(
		context.Background(),
		15*time.Second,
	)

	client, db, err := database.ConnectDB(connectCtx)
	connectCancel()

	if err != nil {
		log.Fatalf("MongoDB connection failed: %v", err)
	}

	// Always disconnect MongoDB on shutdown.
	defer func() {
		ctx, cancel := context.WithTimeout(
			context.Background(),
			5*time.Second,
		)
		defer cancel()

		if err := client.Disconnect(ctx); err != nil {
			log.Printf("MongoDB disconnect error: %v", err)
		}

		log.Println("MongoDB disconnected")
	}()

	log.Println("MongoDB connected successfully!")
	log.Println("Database:", db.Name())

	// Initialize indexes.
	indexCtx, indexCancel := context.WithTimeout(
		context.Background(),
		15*time.Second,
	)

	if err := database.EnsureIndexes(indexCtx, db); err != nil {
		indexCancel()
		log.Fatalf("MongoDB index initialization failed: %v", err)
	}

	indexCancel()

	log.Println("MongoDB indexes initialized successfully!")

	// Initialize Resend email sender.
	emailSender, err := email.NewResendSender(
		os.Getenv("RESEND_API_KEY"),
		os.Getenv("RESEND_FROM"),
	)

	if err != nil {
		log.Fatalf("Resend initialization failed: %v", err)
	}

	// Initialize JWT manager.
	jwtManager, err := security.NewJWTManager(
		os.Getenv("JWT_ACCESS_SECRET"),
		accessTTL,
	)

	if err != nil {
		log.Fatalf("JWT initialization failed: %v", err)
	}

	// Initialize authentication repository.
	authRepo := repository.NewAuthRepository(client, db)

	// Initialize authentication service.
	authService, err := service.NewAuthService(
		authRepo,
		emailSender,
		jwtManager,
		os.Getenv("OTP_PEPPER"),
		accessTTL,
		refreshTTL,
		otpTTL,
		otpCooldown,
		otpMaxAttempts,
	)

	if err != nil {
		log.Fatalf("Auth service initialization failed: %v", err)
	}

	// Initialize authentication handler.
	authHandler, err := handler.NewAuthHandler(
		authService,
		os.Getenv("REFRESH_COOKIE_NAME"),
		cookieSecure,
		cookieSameSite,
		refreshTTL,
	)

	if err != nil {
		log.Fatalf("Auth handler initialization failed: %v", err)
	}

	// Initialize Gin.
	r := gin.New()

	r.Use(
		gin.Logger(),
		gin.Recovery(),
	)

	if err := r.SetTrustedProxies(nil); err != nil {
		log.Fatalf("Failed to configure trusted proxies: %v", err)
	}

	// Health check.
	r.GET("/health", func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(
			c.Request.Context(),
			3*time.Second,
		)
		defer cancel()

		if err := client.Ping(ctx, nil); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"status":   "error",
				"message":  "MongoDB connection unavailable",
				"database": "disconnected",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status":   "success",
			"message":  "Auth service is running",
			"database": "connected",
		})
	})

	// Register authentication routes.
	router.RegisterAuthRoutes(r, authHandler)

	// Print registered routes.
	for _, route := range r.Routes() {
		log.Printf("Registered route: %s %s", route.Method, route.Path)
	}

	log.Println("Auth service running on port:", port)

	docs.SwaggerInfo.Host = "localhost:8080"
	docs.SwaggerInfo.BasePath = "/api/v1/auth"
	docs.SwaggerInfo.Schemes = []string{"http"}

	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	if err := r.Run(":" + port); err != nil {
		log.Printf("Server stopped: %v", err)
	}
}

// mustDuration reads and validates a duration environment variable.
func mustDuration(key string) time.Duration {
	value := strings.TrimSpace(os.Getenv(key))

	if value == "" {
		log.Fatalf("%s is required", key)
	}

	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 {
		log.Fatalf("Invalid %s: expected a positive duration", key)
	}

	return duration
}

// mustInt reads and validates an integer environment variable.
func mustInt(key string) int {
	value := strings.TrimSpace(os.Getenv(key))

	if value == "" {
		log.Fatalf("%s is required", key)
	}

	result, err := strconv.Atoi(value)
	if err != nil || result <= 0 {
		log.Fatalf("Invalid %s: expected a positive integer", key)
	}

	return result
}

// mustBool reads a boolean environment variable.
func mustBool(key string) bool {
	value := strings.TrimSpace(os.Getenv(key))

	if value == "" {
		return false
	}

	result, err := strconv.ParseBool(value)
	if err != nil {
		log.Fatalf("Invalid %s: expected true or false", key)
	}

	return result
}
