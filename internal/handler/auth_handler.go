package handler

import (
	"errors"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"

	"auth-service/internal/repository"
	"auth-service/internal/service"
)

type AuthHandler struct {
	service *service.AuthService
}

func NewAuthHandler(authService *service.AuthService) *AuthHandler {
	return &AuthHandler{
		service: authService,
	}
}

// Request DTOs

type SignupRequest struct {
	Name     string `json:"name" binding:"required"`
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type VerifyEmailRequest struct {
	Email string `json:"email" binding:"required"`
	OTP   string `json:"otp" binding:"required"`
}

type ResendOTPRequest struct {
	Email string `json:"email" binding:"required"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

type LogoutRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// Signup
func (h *AuthHandler) Signup(c *gin.Context) {
	var req SignupRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Name, email and password are required",
		})
		return
	}

	email, err := h.service.Signup(
		c.Request.Context(),
		req.Name,
		req.Email,
		req.Password,
	)

	if err != nil {
		h.handleError(c, err)
		return
	}

	c.JSON(http.StatusAccepted, gin.H{
		"success": true,
		"message": "Verification OTP sent to your email",
		"data": gin.H{
			"email": email,
		},
	})
}

// Verify Email
func (h *AuthHandler) VerifyEmail(c *gin.Context) {
	var req VerifyEmailRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Email and OTP are required",
		})
		return
	}

	result, err := h.service.VerifyEmail(
		c.Request.Context(),
		req.Email,
		req.OTP,
	)

	if err != nil {
		h.handleError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Email verified successfully",
		"data":    result,
	})
}

// Resend OTP
func (h *AuthHandler) ResendOTP(c *gin.Context) {
	var req ResendOTPRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Email is required",
		})
		return
	}

	err := h.service.ResendVerification(
		c.Request.Context(),
		req.Email,
	)

	if err != nil {
		h.handleError(c, err)
		return
	}

	c.JSON(http.StatusAccepted, gin.H{
		"success": true,
		"message": "If the account requires verification, an OTP will be sent",
	})
}

// Login
func (h *AuthHandler) Login(c *gin.Context) {
	var req LoginRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Email and password are required",
		})
		return
	}

	result, err := h.service.Login(
		c.Request.Context(),
		req.Email,
		req.Password,
	)

	if err != nil {
		h.handleError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Login successful",
		"data":    result,
	})
}

// Refresh Access Token
func (h *AuthHandler) Refresh(c *gin.Context) {
	var req RefreshRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Refresh token is required",
		})
		return
	}

	result, err := h.service.Refresh(
		c.Request.Context(),
		req.RefreshToken,
	)

	if err != nil {
		h.handleError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Token refreshed successfully",
		"data":    result,
	})
}

// Logout
func (h *AuthHandler) Logout(c *gin.Context) {
	var req LogoutRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Refresh token is required",
		})
		return
	}

	err := h.service.Logout(
		c.Request.Context(),
		req.RefreshToken,
	)

	if err != nil {
		h.handleError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Logged out successfully",
	})
}

// Centralized error handling
func (h *AuthHandler) handleError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, service.ErrInvalidInput):
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Invalid request details",
		})

	case errors.Is(err, repository.ErrEmailExists):
		c.JSON(http.StatusConflict, gin.H{
			"success": false,
			"message": "Email is already registered",
		})

	case errors.Is(err, service.ErrInvalidCredentials):
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"message": "Invalid email or password",
		})

	case errors.Is(err, service.ErrEmailNotVerified):
		c.JSON(http.StatusForbidden, gin.H{
			"success": false,
			"message": "Please verify your email before logging in",
		})

	case errors.Is(err, repository.ErrInvalidEmailOTP):
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Invalid OTP",
		})

	case errors.Is(err, repository.ErrEmailVerificationExpired):
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "OTP expired. Please request a new OTP",
		})

	case errors.Is(err, repository.ErrEmailVerificationLocked):
		c.JSON(http.StatusTooManyRequests, gin.H{
			"success": false,
			"message": "Maximum OTP attempts exceeded. Request a new OTP",
		})

	case errors.Is(err, repository.ErrEmailAlreadyVerified):
		c.JSON(http.StatusConflict, gin.H{
			"success": false,
			"message": "Email is already verified",
		})

	case errors.Is(err, repository.ErrInvalidRefreshToken):
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"message": "Invalid or expired refresh token",
		})

	case errors.Is(err, service.ErrEmailDelivery):
		c.JSON(http.StatusBadGateway, gin.H{
			"success": false,
			"message": "Unable to send verification email. Please try again later",
		})

	default:
		log.Printf("Authentication error: %v", err)

		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "Something went wrong",
		})
	}
}
