package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"auth-service/internal/email"
	"auth-service/internal/model"
	"auth-service/internal/repository"
	"auth-service/internal/security"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

const signupOTPPurpose = "signup"

var (
	ErrInvalidInput = errors.New("invalid input")

	ErrEmailAlreadyExists = errors.New(
		"email is already registered",
	)

	ErrAccountPendingVerification = errors.New(
		"account exists but email verification is pending",
	)

	ErrEmailNotVerified = errors.New(
		"please verify your email before logging in",
	)

	ErrInvalidCredentials = errors.New(
		"invalid email or password",
	)

	ErrInvalidOTP = errors.New(
		"invalid or expired OTP",
	)

	ErrRefreshTokenInvalid = errors.New(
		"invalid or expired refresh token",
	)

	ErrRefreshTokenReuse = errors.New(
		"refresh token reuse detected; session revoked",
	)

	ErrEmailAlreadyVerified = errors.New(
		"email is already verified",
	)
)

type AuthService struct {
	repo           *repository.AuthRepository
	emailSender    email.Sender
	jwtManager     *security.JWTManager
	otpPepper      string
	accessTTL      time.Duration
	refreshTTL     time.Duration
	otpTTL         time.Duration
	otpCooldown    time.Duration
	maxOTPAttempts int
}

// TokenPair contains authentication tokens.
// RefreshToken must be delivered using an HttpOnly cookie by the handler.
type TokenPair struct {
	AccessToken  string      `json:"access_token"`
	RefreshToken string      `json:"-"`
	TokenType    string      `json:"token_type"`
	ExpiresIn    int64       `json:"expires_in"`
	User         *model.User `json:"user"`
}

// NewAuthService initializes the authentication service.
func NewAuthService(
	repo *repository.AuthRepository,
	emailSender email.Sender,
	jwtManager *security.JWTManager,
	otpPepper string,
	accessTTL time.Duration,
	refreshTTL time.Duration,
	otpTTL time.Duration,
	otpCooldown time.Duration,
	maxOTPAttempts int,
) (*AuthService, error) {

	if repo == nil {
		return nil, errors.New("auth repository is required")
	}

	if emailSender == nil {
		return nil, errors.New("email sender is required")
	}

	if jwtManager == nil {
		return nil, errors.New("JWT manager is required")
	}

	if len(otpPepper) < 32 {
		return nil, errors.New("OTP_PEPPER must contain at least 32 bytes")
	}

	if accessTTL <= 0 || refreshTTL <= 0 || otpTTL <= 0 {
		return nil, errors.New("token and OTP TTLs must be positive")
	}

	if otpCooldown < 0 || maxOTPAttempts <= 0 {
		return nil, errors.New("invalid OTP configuration")
	}

	return &AuthService{
		repo:           repo,
		emailSender:    emailSender,
		jwtManager:     jwtManager,
		otpPepper:      otpPepper,
		accessTTL:      accessTTL,
		refreshTTL:     refreshTTL,
		otpTTL:         otpTTL,
		otpCooldown:    otpCooldown,
		maxOTPAttempts: maxOTPAttempts,
	}, nil
}

// =====================================================
// SIGNUP
// =====================================================

// Signup creates a new user and sends an email verification OTP.
func (s *AuthService) Signup(
	ctx context.Context,
	name string,
	emailAddress string,
	password string,
) error {

	name = strings.TrimSpace(name)
	emailAddress = normalizeEmail(emailAddress)

	if name == "" || len(name) > 100 {
		return ErrInvalidInput
	}

	if err := validateEmail(emailAddress); err != nil {
		return ErrInvalidInput
	}

	// Check whether the email already exists.
	existingUser, err := s.repo.GetUserByEmail(ctx, emailAddress)

	if err == nil {
		if existingUser.IsEmailVerified {
			return ErrEmailAlreadyExists
		}

		return ErrAccountPendingVerification
	}

	if !errors.Is(err, mongo.ErrNoDocuments) {
		return fmt.Errorf("failed to check existing user: %w", err)
	}

	// Hash password.
	passwordHash, err := security.HashPassword(password)
	if err != nil {
		return err
	}

	now := time.Now().UTC()

	user := &model.User{
		ID:              bson.NewObjectID(),
		Name:            name,
		Email:           emailAddress,
		PasswordHash:    passwordHash,
		IsEmailVerified: false,
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	// Create user in MongoDB.
	if err := s.repo.CreateUser(ctx, user); err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return ErrEmailAlreadyExists
		}

		return fmt.Errorf("failed to create user: %w", err)
	}

	// Generate and send verification OTP.
	if err := s.createAndSendOTP(ctx, user); err != nil {
		return err
	}

	return nil
}

// =====================================================
// EMAIL OTP
// =====================================================

// createAndSendOTP generates, hashes, stores and emails an OTP.
func (s *AuthService) createAndSendOTP(
	ctx context.Context,
	user *model.User,
) error {

	otp, err := security.GenerateOTP()
	if err != nil {
		return fmt.Errorf("failed to generate OTP: %w", err)
	}

	otpHash, err := security.HashEmailOTP(
		user.Email,
		signupOTPPurpose,
		otp,
		s.otpPepper,
	)
	if err != nil {
		return fmt.Errorf("failed to hash OTP: %w", err)
	}

	now := time.Now().UTC()

	emailOTP := &model.EmailOTP{
		ID:                bson.NewObjectID(),
		UserID:            user.ID,
		Email:             user.Email,
		Purpose:           signupOTPPurpose,
		OTPHash:           otpHash,
		Attempts:          0,
		MaxAttempts:       s.maxOTPAttempts,
		ExpiresAt:         now.Add(s.otpTTL),
		ResendAvailableAt: now.Add(s.otpCooldown),
		CreatedAt:         now,
		UpdatedAt:         now,
	}

	// Store hashed OTP in MongoDB.
	if err := s.repo.SaveEmailOTP(ctx, emailOTP); err != nil {
		return fmt.Errorf("failed to save OTP: %w", err)
	}

	// Send original OTP through Resend.
	if err := s.emailSender.SendVerificationOTP(
		ctx,
		user.Email,
		otp,
		s.otpTTL,
	); err != nil {
		return fmt.Errorf("failed to send verification email: %w", err)
	}

	return nil
}

// ResendOTP generates and sends a new OTP for an unverified account.
func (s *AuthService) ResendOTP(
	ctx context.Context,
	emailAddress string,
) error {

	emailAddress = normalizeEmail(emailAddress)

	if validateEmail(emailAddress) != nil {
		return ErrInvalidInput
	}

	user, err := s.repo.GetUserByEmail(ctx, emailAddress)

	if errors.Is(err, mongo.ErrNoDocuments) {
		// Avoid revealing whether an account exists.
		return nil
	}

	if err != nil {
		return fmt.Errorf("failed to retrieve user: %w", err)
	}

	if user.IsEmailVerified {
		// No OTP required for an already verified account.
		return nil
	}

	return s.createAndSendOTP(ctx, user)
}

// VerifyEmail verifies the submitted email OTP.
func (s *AuthService) VerifyEmail(
	ctx context.Context,
	emailAddress string,
	otp string,
) error {

	emailAddress = normalizeEmail(emailAddress)

	if validateEmail(emailAddress) != nil {
		return ErrInvalidInput
	}

	user, err := s.repo.GetUserByEmail(ctx, emailAddress)

	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return ErrInvalidOTP
		}

		return fmt.Errorf("failed to retrieve user: %w", err)
	}

	if user.IsEmailVerified {
		return ErrEmailAlreadyVerified
	}

	emailOTP, err := s.repo.FindEmailOTP(
		ctx,
		emailAddress,
		signupOTPPurpose,
	)

	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return ErrInvalidOTP
		}

		return fmt.Errorf("failed to retrieve OTP: %w", err)
	}

	now := time.Now().UTC()

	if !emailOTP.ExpiresAt.After(now) ||
		emailOTP.Attempts >= emailOTP.MaxAttempts {
		return ErrInvalidOTP
	}

	// Verify the submitted OTP.
	valid := security.VerifyEmailOTP(
		emailAddress,
		signupOTPPurpose,
		otp,
		s.otpPepper,
		emailOTP.OTPHash,
	)

	if !valid {
		if _, err := s.repo.IncrementOTPAttempts(
			ctx,
			emailOTP.ID,
			now,
		); err != nil {
			return fmt.Errorf("failed to update OTP attempts: %w", err)
		}

		return ErrInvalidOTP
	}

	// Atomically consume OTP and verify the user.
	err = s.repo.ConsumeOTPAndVerifyUser(
		ctx,
		user.ID,
		emailOTP.ID,
		emailOTP.OTPHash,
		now,
	)

	if errors.Is(err, repository.ErrOTPInvalidOrExpired) {
		return ErrInvalidOTP
	}

	if errors.Is(err, repository.ErrUserNotEligible) {
		return ErrEmailAlreadyVerified
	}

	if err != nil {
		return fmt.Errorf("failed to complete email verification: %w", err)
	}

	return nil
}

// =====================================================
// LOGIN
// =====================================================

// Login authenticates user and creates a refresh session.
func (s *AuthService) Login(
	ctx context.Context,
	emailAddress string,
	password string,
) (*TokenPair, error) {

	emailAddress = normalizeEmail(emailAddress)

	if validateEmail(emailAddress) != nil || password == "" {
		return nil, ErrInvalidCredentials
	}

	user, err := s.repo.GetUserByEmail(ctx, emailAddress)

	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, ErrInvalidCredentials
		}

		return nil, fmt.Errorf("failed to retrieve user: %w", err)
	}

	// Compare submitted password with stored bcrypt hash.
	if err := security.ComparePassword(
		user.PasswordHash,
		password,
	); err != nil {
		return nil, ErrInvalidCredentials
	}

	if !user.IsEmailVerified {
		return nil, ErrEmailNotVerified
	}

	return s.createLoginSession(ctx, user)
}

// =====================================================
// TOKEN GENERATION
// =====================================================

// createLoginSession creates a new refresh token family.
func (s *AuthService) createLoginSession(
	ctx context.Context,
	user *model.User,
) (*TokenPair, error) {

	familyID := bson.NewObjectID()

	pair, session, err := s.buildTokenPair(user, familyID)
	if err != nil {
		return nil, err
	}

	if err := s.repo.CreateRefreshSession(ctx, session); err != nil {
		return nil, fmt.Errorf("failed to create refresh session: %w", err)
	}

	return pair, nil
}

// buildTokenPair generates an access token and a new opaque refresh token.
func (s *AuthService) buildTokenPair(
	user *model.User,
	familyID bson.ObjectID,
) (*TokenPair, *model.RefreshSession, error) {

	now := time.Now().UTC()

	// Generate access JWT.
	accessToken, _, err := s.jwtManager.GenerateAccessToken(
		user.ID.Hex(),
		user.Email,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate random refresh token.
	refreshToken, err := generateRefreshToken()
	if err != nil {
		return nil, nil, err
	}

	refreshTokenHash := hashRefreshToken(refreshToken)

	session := &model.RefreshSession{
		ID:        bson.NewObjectID(),
		UserID:    user.ID,
		TokenHash: refreshTokenHash,
		FamilyID:  familyID,
		ExpiresAt: now.Add(s.refreshTTL),
		CreatedAt: now,
	}

	pair := &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.accessTTL.Seconds()),
		User:         user,
	}

	return pair, session, nil
}

// =====================================================
// REFRESH TOKEN
// =====================================================

// Refresh validates the old refresh token and rotates it.
func (s *AuthService) Refresh(
	ctx context.Context,
	rawRefreshToken string,
) (*TokenPair, error) {

	rawRefreshToken = strings.TrimSpace(rawRefreshToken)

	if rawRefreshToken == "" {
		return nil, ErrRefreshTokenInvalid
	}

	oldTokenHash := hashRefreshToken(rawRefreshToken)

	oldSession, err := s.repo.FindRefreshSessionByHash(
		ctx,
		oldTokenHash,
	)

	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, ErrRefreshTokenInvalid
		}

		return nil, fmt.Errorf("failed to retrieve refresh session: %w", err)
	}

	// Detect reuse of an already rotated token.
	if oldSession.RevokedAt != nil {
		if oldSession.RevokedReason == "rotated" ||
			oldSession.ReplacedByTokenHash != "" {

			if err := s.repo.RevokeTokenFamily(
				ctx,
				oldSession.FamilyID,
				time.Now().UTC(),
				"token_reuse_detected",
			); err != nil {
				return nil, fmt.Errorf(
					"failed to revoke compromised token family: %w",
					err,
				)
			}

			return nil, ErrRefreshTokenReuse
		}

		return nil, ErrRefreshTokenInvalid
	}

	now := time.Now().UTC()

	if !oldSession.ExpiresAt.After(now) {
		return nil, ErrRefreshTokenInvalid
	}

	user, err := s.repo.GetUserByID(
		ctx,
		oldSession.UserID,
	)

	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, ErrRefreshTokenInvalid
		}

		return nil, fmt.Errorf("failed to retrieve session user: %w", err)
	}

	if !user.IsEmailVerified {
		return nil, ErrEmailNotVerified
	}

	// Generate replacement token in the same family.
	pair, newSession, err := s.buildTokenPair(
		user,
		oldSession.FamilyID,
	)

	if err != nil {
		return nil, err
	}

	// Atomically revoke old token and insert replacement.
	err = s.repo.RotateRefreshSession(
		ctx,
		oldTokenHash,
		newSession,
		now,
	)

	if err != nil {
		if errors.Is(err, repository.ErrRefreshSessionInactive) {
			// Another request may have rotated this token already.
			if revokeErr := s.repo.RevokeTokenFamily(
				ctx,
				oldSession.FamilyID,
				time.Now().UTC(),
				"token_reuse_detected",
			); revokeErr != nil {
				return nil, fmt.Errorf(
					"failed to revoke token family: %w",
					revokeErr,
				)
			}

			return nil, ErrRefreshTokenReuse
		}

		return nil, fmt.Errorf("failed to rotate refresh token: %w", err)
	}

	return pair, nil
}

// =====================================================
// LOGOUT
// =====================================================

// Logout revokes the entire refresh token family for this login session.
func (s *AuthService) Logout(
	ctx context.Context,
	rawRefreshToken string,
) error {

	rawRefreshToken = strings.TrimSpace(rawRefreshToken)

	if rawRefreshToken == "" {
		return nil
	}

	tokenHash := hashRefreshToken(rawRefreshToken)

	session, err := s.repo.FindRefreshSessionByHash(
		ctx,
		tokenHash,
	)

	if errors.Is(err, mongo.ErrNoDocuments) {
		// Already expired, removed or unknown token.
		return nil
	}

	if err != nil {
		return fmt.Errorf("failed to retrieve refresh session: %w", err)
	}

	// Revoke all tokens belonging to this login session.
	if err := s.repo.RevokeTokenFamily(
		ctx,
		session.FamilyID,
		time.Now().UTC(),
		"logout",
	); err != nil {
		return fmt.Errorf("failed to logout: %w", err)
	}

	return nil
}

// =====================================================
// HELPER FUNCTIONS
// =====================================================

func normalizeEmail(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func validateEmail(value string) error {
	address, err := mail.ParseAddress(value)

	if err != nil || address.Address != value {
		return errors.New("invalid email address")
	}

	if len(value) > 254 {
		return errors.New("email address is too long")
	}

	return nil
}

// generateRefreshToken creates a cryptographically secure random token.
func generateRefreshToken() (string, error) {
	randomBytes := make([]byte, 32)

	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(randomBytes), nil
}

// hashRefreshToken stores only the SHA-256 hash of refresh tokens.
func hashRefreshToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}
