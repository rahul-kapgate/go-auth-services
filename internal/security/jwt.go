package security

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const jwtIssuer = "go-auth-service"

var (
	ErrInvalidJWTSecret = errors.New(
		"JWT secret must contain at least 32 bytes",
	)

	ErrInvalidAccessToken = errors.New(
		"invalid access token",
	)
)

type JWTManager struct {
	secret []byte
	ttl    time.Duration
}

// AccessClaims represents the JWT access token claims.
type AccessClaims struct {
	Email string `json:"email"`
	jwt.RegisteredClaims
}

// NewJWTManager initializes the JWT manager.
func NewJWTManager(
	secret string,
	ttl time.Duration,
) (*JWTManager, error) {
	if len([]byte(secret)) < 32 {
		return nil, ErrInvalidJWTSecret
	}

	if ttl <= 0 {
		return nil, errors.New("access token TTL must be positive")
	}

	return &JWTManager{
		secret: []byte(secret),
		ttl:    ttl,
	}, nil
}

// GenerateAccessToken generates a signed JWT access token.
func (m *JWTManager) GenerateAccessToken(
	userID string,
	email string,
) (string, time.Time, error) {
	userID = strings.TrimSpace(userID)
	email = strings.ToLower(strings.TrimSpace(email))

	if userID == "" || email == "" {
		return "", time.Time{}, errors.New(
			"user ID and email are required",
		)
	}

	now := time.Now().UTC()
	expiresAt := now.Add(m.ttl)

	claims := AccessClaims{
		Email: email,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    jwtIssuer,
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}

	token := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		claims,
	)

	signedToken, err := token.SignedString(m.secret)
	if err != nil {
		return "", time.Time{}, fmt.Errorf(
			"failed to sign access token: %w",
			err,
		)
	}

	return signedToken, expiresAt, nil
}

// ValidateAccessToken validates and parses a JWT access token.
func (m *JWTManager) ValidateAccessToken(
	tokenString string,
) (*AccessClaims, error) {
	claims := &AccessClaims{}

	token, err := jwt.ParseWithClaims(
		tokenString,
		claims,
		func(token *jwt.Token) (interface{}, error) {
			if token.Method != jwt.SigningMethodHS256 {
				return nil, ErrInvalidAccessToken
			}

			return m.secret, nil
		},
		jwt.WithValidMethods([]string{
			jwt.SigningMethodHS256.Alg(),
		}),
		jwt.WithIssuer(jwtIssuer),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	)

	if err != nil || token == nil || !token.Valid {
		return nil, ErrInvalidAccessToken
	}

	validClaims, ok := token.Claims.(*AccessClaims)
	if !ok || validClaims.Subject == "" || validClaims.Email == "" {
		return nil, ErrInvalidAccessToken
	}

	return validClaims, nil
}
