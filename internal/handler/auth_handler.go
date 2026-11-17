package handler

import (
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"auth-service/internal/repository"
	"auth-service/internal/service"

	"github.com/gin-gonic/gin"
)

const refreshCookiePath = "/api/v1/auth"

type AuthHandler struct {
	authService       *service.AuthService
	refreshCookieName string
	cookieSecure      bool
	cookieSameSite    http.SameSite
	refreshTTL        time.Duration
}

// NewAuthHandler initializes the authentication HTTP handler.
func NewAuthHandler(
	authService *service.AuthService,
	cookieName string,
	cookieSecure bool,
	cookieSameSite string,
	refreshTTL time.Duration,
) (*AuthHandler, error) {

	if authService == nil {
		return nil, errors.New("auth service is required")
	}

	if refreshTTL <= 0 {
		return nil, errors.New("refresh token TTL must be positive")
	}

	cookieName = strings.TrimSpace(cookieName)
	if cookieName == "" {
		cookieName = "refresh_token"
	}

	var sameSite http.SameSite

	switch strings.ToLower(strings.TrimSpace(cookieSameSite)) {
	case "", "lax":
		sameSite = http.SameSiteLaxMode

	case "strict":
		sameSite = http.SameSiteStrictMode

	case "none":
		if !cookieSecure {
			return nil, errors.New(
				"COOKIE_SECURE must be true when COOKIE_SAME_SITE is none",
			)
		}

		sameSite = http.SameSiteNoneMode

	default:
		return nil, errors.New("invalid COOKIE_SAME_SITE value")
	}

	return &AuthHandler{
		authService:       authService,
		refreshCookieName: cookieName,
		cookieSecure:      cookieSecure,
		cookieSameSite:    sameSite,
		refreshTTL:        refreshTTL,
	}, nil
}

// =====================================================
// REQUEST DTOs
// =====================================================

type signupRequest struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type verifyEmailRequest struct {
	Email string `json:"email"`
	OTP   string `json:"otp"`
}

type resendOTPRequest struct {
	Email string `json:"email"`
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// =====================================================
// SIGNUP
// =====================================================

// Signup godoc
// @Summary      Register a new user
// @Description  Creates a user account and sends an email verification OTP.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        request body signupRequest true "Signup details"
// @Success      202 {object} map[string]interface{} "Signup successful"
// @Failure      400 {object} map[string]interface{} "Invalid request"
// @Failure      409 {object} map[string]interface{} "Email already registered"
// @Failure      429 {object} map[string]interface{} "OTP cooldown active"
// @Router       /signup [post]
func (h *AuthHandler) Signup(c *gin.Context) {
	var req signupRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "Invalid request body")
		return
	}

	err := h.authService.Signup(
		c.Request.Context(),
		req.Name,
		req.Email,
		req.Password,
	)

	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidInput):
			respondError(c, http.StatusBadRequest, "Invalid signup details")

		case errors.Is(err, service.ErrEmailAlreadyExists):
			respondError(c, http.StatusConflict, "Email is already registered")

		case errors.Is(err, service.ErrAccountPendingVerification):
			respondError(
				c,
				http.StatusConflict,
				"Account verification is pending. Please request an OTP.",
			)

		case errors.Is(err, repository.ErrOTPCooldown):
			respondError(
				c,
				http.StatusTooManyRequests,
				"Please wait before requesting another OTP",
			)

		default:
			log.Printf("Signup failed: %v", err)
			respondError(c, http.StatusInternalServerError, "Unable to complete signup")
		}

		return
	}

	c.JSON(http.StatusAccepted, gin.H{
		"status":  "success",
		"message": "Signup successful. Please check your email for the verification code.",
	})
}

// =====================================================
// VERIFY EMAIL
// =====================================================

func (h *AuthHandler) VerifyEmail(c *gin.Context) {
	var req verifyEmailRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "Invalid request body")
		return
	}

	req.OTP = strings.TrimSpace(req.OTP)

	if len(req.OTP) != 6 {
		respondError(c, http.StatusBadRequest, "OTP must contain six digits")
		return
	}

	err := h.authService.VerifyEmail(
		c.Request.Context(),
		req.Email,
		req.OTP,
	)

	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidInput):
			respondError(c, http.StatusBadRequest, "Invalid email address")

		case errors.Is(err, service.ErrInvalidOTP):
			respondError(c, http.StatusBadRequest, "Invalid or expired OTP")

		case errors.Is(err, service.ErrEmailAlreadyVerified):
			respondError(c, http.StatusConflict, "Email is already verified")

		default:
			log.Printf("Email verification failed: %v", err)
			respondError(
				c,
				http.StatusInternalServerError,
				"Unable to verify email",
			)
		}

		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "success",
		"message": "Email verified successfully. You can now log in.",
	})
}

// =====================================================
// RESEND OTP
// =====================================================

func (h *AuthHandler) ResendOTP(c *gin.Context) {
	var req resendOTPRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "Invalid request body")
		return
	}

	err := h.authService.ResendOTP(
		c.Request.Context(),
		req.Email,
	)

	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidInput):
			respondError(c, http.StatusBadRequest, "Invalid email address")

		case errors.Is(err, repository.ErrOTPCooldown):
			respondError(
				c,
				http.StatusTooManyRequests,
				"Please wait before requesting another OTP",
			)

		default:
			log.Printf("Resend OTP failed: %v", err)
			respondError(
				c,
				http.StatusInternalServerError,
				"Unable to process OTP request",
			)
		}

		return
	}

	// Generic response avoids revealing whether an account exists.
	c.JSON(http.StatusAccepted, gin.H{
		"status":  "success",
		"message": "If the account requires verification, a verification code will be sent.",
	})
}

// =====================================================
// LOGIN
// =====================================================

func (h *AuthHandler) Login(c *gin.Context) {
	var req loginRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "Invalid request body")
		return
	}

	pair, err := h.authService.Login(
		c.Request.Context(),
		req.Email,
		req.Password,
	)

	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidCredentials):
			respondError(c, http.StatusUnauthorized, "Invalid email or password")

		case errors.Is(err, service.ErrEmailNotVerified):
			respondError(c, http.StatusForbidden, "Please verify your email first")

		default:
			log.Printf("Login failed: %v", err)
			respondError(c, http.StatusInternalServerError, "Unable to login")
		}

		return
	}

	// Refresh token is sent only through an HttpOnly cookie.
	h.setRefreshCookie(c, pair.RefreshToken)

	// TokenPair has json:"-" on RefreshToken.
	c.JSON(http.StatusOK, gin.H{
		"status":       "success",
		"message":      "Login successful",
		"access_token": pair.AccessToken,
		"token_type":   pair.TokenType,
		"expires_in":   pair.ExpiresIn,
		"user":         pair.User,
	})
}

// =====================================================
// REFRESH TOKEN
// =====================================================

func (h *AuthHandler) Refresh(c *gin.Context) {
	cookie, err := c.Request.Cookie(h.refreshCookieName)

	if err != nil || cookie.Value == "" {
		respondError(c, http.StatusUnauthorized, "Refresh token is missing")
		return
	}

	pair, err := h.authService.Refresh(
		c.Request.Context(),
		cookie.Value,
	)

	if err != nil {
		if errors.Is(err, service.ErrRefreshTokenInvalid) ||
			errors.Is(err, service.ErrRefreshTokenReuse) {

			h.clearRefreshCookie(c)

			respondError(
				c,
				http.StatusUnauthorized,
				"Refresh session is invalid. Please login again.",
			)
			return
		}

		log.Printf("Token refresh failed: %v", err)
		respondError(
			c,
			http.StatusInternalServerError,
			"Unable to refresh session",
		)
		return
	}

	// Replace old refresh cookie with the rotated token.
	h.setRefreshCookie(c, pair.RefreshToken)

	c.JSON(http.StatusOK, gin.H{
		"status":       "success",
		"message":      "Token refreshed successfully",
		"access_token": pair.AccessToken,
		"token_type":   pair.TokenType,
		"expires_in":   pair.ExpiresIn,
		"user":         pair.User,
	})
}

// =====================================================
// LOGOUT
// =====================================================

func (h *AuthHandler) Logout(c *gin.Context) {
	cookie, err := c.Request.Cookie(h.refreshCookieName)

	if err == nil && cookie.Value != "" {
		err := h.authService.Logout(
			c.Request.Context(),
			cookie.Value,
		)

		if err != nil {
			log.Printf("Logout failed: %v", err)
			respondError(c, http.StatusInternalServerError, "Unable to logout")
			return
		}
	}

	h.clearRefreshCookie(c)

	c.Status(http.StatusNoContent)
}

// =====================================================
// COOKIE HELPERS
// =====================================================

func (h *AuthHandler) setRefreshCookie(
	c *gin.Context,
	token string,
) {
	now := time.Now().UTC()

	http.SetCookie(c.Writer, &http.Cookie{
		Name:     h.refreshCookieName,
		Value:    token,
		Path:     refreshCookiePath,
		HttpOnly: true,
		Secure:   h.cookieSecure,
		SameSite: h.cookieSameSite,
		Expires:  now.Add(h.refreshTTL),
		MaxAge:   int(h.refreshTTL.Seconds()),
	})
}

func (h *AuthHandler) clearRefreshCookie(c *gin.Context) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     h.refreshCookieName,
		Value:    "",
		Path:     refreshCookiePath,
		HttpOnly: true,
		Secure:   h.cookieSecure,
		SameSite: h.cookieSameSite,
		Expires:  time.Unix(1, 0).UTC(),
		MaxAge:   -1,
	})
}

// =====================================================
// RESPONSE HELPERS
// =====================================================

func respondError(
	c *gin.Context,
	statusCode int,
	message string,
) {
	c.JSON(statusCode, gin.H{
		"status":  "error",
		"message": message,
	})
}
