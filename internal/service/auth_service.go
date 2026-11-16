package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/google/uuid"

	"auth-service/internal/email"
	"auth-service/internal/repository"
	"auth-service/internal/security"
)

var (
	ErrInvalidInput       = errors.New("invalid input")
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrEmailNotVerified   = errors.New("email not verified")
	ErrEmailDelivery      = errors.New("email delivery failed")
)

type AuthService struct {
	repo           *repository.AuthRepository
	mailer         email.VerificationMailer
	jwt            *security.JWTManager
	otpPepper      string
	accessTTL      time.Duration
	refreshTTL     time.Duration
	otpTTL         time.Duration
	resendCooldown time.Duration
	maxOTPAttempts int
}

type PublicUser struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

type AuthResult struct {
	User         PublicUser `json:"user"`
	AccessToken  string     `json:"access_token"`
	RefreshToken string     `json:"refresh_token"`
	TokenType    string     `json:"token_type"`
	ExpiresIn    int64      `json:"expires_in"`
}

func NewAuthService(
	repo *repository.AuthRepository,
	mailer email.VerificationMailer,
	jwtManager *security.JWTManager,
	otpPepper string,
	accessTTL time.Duration,
	refreshTTL time.Duration,
	otpTTL time.Duration,
	resendCooldown time.Duration,
	maxOTPAttempts int,
) *AuthService {
	return &AuthService{
		repo:           repo,
		mailer:         mailer,
		jwt:            jwtManager,
		otpPepper:      otpPepper,
		accessTTL:      accessTTL,
		refreshTTL:     refreshTTL,
		otpTTL:         otpTTL,
		resendCooldown: resendCooldown,
		maxOTPAttempts: maxOTPAttempts,
	}
}

func normalizeEmail(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))

	parsed, err := mail.ParseAddress(value)

	if err != nil || parsed.Address != value {
		return "", ErrInvalidInput
	}

	return value, nil
}

// Signup creates an unverified user and sends a verification OTP.
func (s *AuthService) Signup(
	ctx context.Context,
	name string,
	emailAddress string,
	password string,
) (string, error) {

	name = strings.TrimSpace(name)

	normalizedEmail, err := normalizeEmail(emailAddress)
	if err != nil {
		return "", err
	}

	if name == "" || len(name) > 120 {
		return "", ErrInvalidInput
	}

	// bcrypt has a maximum input length of 72 bytes.
	if len(password) < 8 || len(password) > 72 {
		return "", ErrInvalidInput
	}

	if len(s.otpPepper) < 32 {
		return "", errors.New("OTP pepper is not configured correctly")
	}

	passwordHash, err := security.HashPassword(password)
	if err != nil {
		return "", err
	}

	code, err := security.GenerateOTP()
	if err != nil {
		return "", err
	}

	codeHash := security.HashEmailOTP(
		normalizedEmail,
		code,
		s.otpPepper,
	)

	user, err := s.repo.CreatePendingUserWithOTP(
		ctx,
		name,
		normalizedEmail,
		passwordHash,
		codeHash,
		time.Now().Add(s.otpTTL),
	)

	if err != nil {
		return "", err
	}

	err = s.mailer.SendVerificationOTP(
		ctx,
		user.Email,
		user.Name,
		code,
		s.otpTTL,
	)

	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrEmailDelivery, err)
	}

	return user.Email, nil
}

// VerifyEmail validates OTP and creates an authenticated session.
func (s *AuthService) VerifyEmail(
	ctx context.Context,
	emailAddress string,
	code string,
) (*AuthResult, error) {

	normalizedEmail, err := normalizeEmail(emailAddress)
	if err != nil {
		return nil, err
	}

	if !security.IsValidOTP(code) {
		return nil, ErrInvalidInput
	}

	codeHash := security.HashEmailOTP(
		normalizedEmail,
		code,
		s.otpPepper,
	)

	user, err := s.repo.VerifyEmailOTP(
		ctx,
		normalizedEmail,
		codeHash,
		s.maxOTPAttempts,
	)

	if err != nil {
		return nil, err
	}

	return s.createSession(ctx, user)
}

// ResendVerification sends a fresh OTP when permitted.
//
// The public response intentionally does not disclose whether
// an account exists or whether it is already verified.
func (s *AuthService) ResendVerification(
	ctx context.Context,
	emailAddress string,
) error {

	normalizedEmail, err := normalizeEmail(emailAddress)
	if err != nil {
		return err
	}

	code, err := security.GenerateOTP()
	if err != nil {
		return err
	}

	codeHash := security.HashEmailOTP(
		normalizedEmail,
		code,
		s.otpPepper,
	)

	user, err := s.repo.IssueEmailVerificationOTP(
		ctx,
		normalizedEmail,
		codeHash,
		time.Now().Add(s.otpTTL),
		s.resendCooldown,
	)

	switch {
	case errors.Is(err, repository.ErrVerificationUserNotFound):
		return nil

	case errors.Is(err, repository.ErrEmailAlreadyVerified):
		return nil

	case errors.Is(err, repository.ErrVerificationResendCooldown):
		return nil

	case err != nil:
		return err
	}

	err = s.mailer.SendVerificationOTP(
		ctx,
		user.Email,
		user.Name,
		code,
		s.otpTTL,
	)

	if err != nil {
		return fmt.Errorf("%w: %v", ErrEmailDelivery, err)
	}

	return nil
}

// Login authenticates only email-verified users.
func (s *AuthService) Login(
	ctx context.Context,
	emailAddress string,
	password string,
) (*AuthResult, error) {

	normalizedEmail, err := normalizeEmail(emailAddress)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	if password == "" {
		return nil, ErrInvalidCredentials
	}

	user, err := s.repo.GetUserByEmail(
		ctx,
		normalizedEmail,
	)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrInvalidCredentials
	}

	if err != nil {
		return nil, err
	}

	if security.CheckPassword(password, user.PasswordHash) != nil {
		return nil, ErrInvalidCredentials
	}

	if !user.EmailVerified {
		return nil, ErrEmailNotVerified
	}

	return s.createSession(ctx, user)
}

// createSession generates access and refresh tokens.
func (s *AuthService) createSession(
	ctx context.Context,
	user repository.User,
) (*AuthResult, error) {

	accessToken, err := s.jwt.GenerateAccessToken(user.ID, s.accessTTL)
	if err != nil {
		return nil, err
	}

	refreshToken, err := security.GenerateRefreshToken()
	if err != nil {
		return nil, err
	}

	tokenHash := security.HashRefreshToken(refreshToken)
	familyID := uuid.NewString()

	err = s.repo.CreateRefreshSession(
		ctx,
		user.ID,
		familyID,
		tokenHash,
		time.Now().Add(s.refreshTTL),
	)

	if err != nil {
		return nil, err
	}

	return &AuthResult{
		User: PublicUser{
			ID:    user.ID,
			Name:  user.Name,
			Email: user.Email,
		},
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.accessTTL.Seconds()),
	}, nil
}

// Refresh rotates the refresh token and issues a new access token.
func (s *AuthService) Refresh(
	ctx context.Context,
	oldRefreshToken string,
) (*AuthResult, error) {

	if strings.TrimSpace(oldRefreshToken) == "" {
		return nil, repository.ErrInvalidRefreshToken
	}

	newRefreshToken, err := security.GenerateRefreshToken()
	if err != nil {
		return nil, err
	}

	user, err := s.repo.RotateRefreshToken(
		ctx,
		security.HashRefreshToken(oldRefreshToken),
		security.HashRefreshToken(newRefreshToken),
		time.Now().Add(s.refreshTTL),
	)

	if err != nil {
		return nil, err
	}

	accessToken, err := s.jwt.GenerateAccessToken(user.ID, s.accessTTL)
	if err != nil {
		return nil, err
	}

	return &AuthResult{
		User: PublicUser{
			ID:    user.ID,
			Name:  user.Name,
			Email: user.Email,
		},
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.accessTTL.Seconds()),
	}, nil
}

// Logout revokes the supplied refresh token.
func (s *AuthService) Logout(
	ctx context.Context,
	refreshToken string,
) error {

	if strings.TrimSpace(refreshToken) == "" {
		return repository.ErrInvalidRefreshToken
	}

	return s.repo.RevokeRefreshToken(
		ctx,
		security.HashRefreshToken(refreshToken),
	)
}
