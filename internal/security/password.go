package security

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrPasswordTooShort = errors.New("password must be at least 8 bytes")
	ErrPasswordTooLong  = errors.New("password must not exceed 72 bytes")
)

const bcryptCost = 12

// HashPassword generates a bcrypt hash.
func HashPassword(password string) (string, error) {
	if len(password) < 8 {
		return "", ErrPasswordTooShort
	}

	if len(password) > 72 {
		return "", ErrPasswordTooLong
	}

	hashedPassword, err := bcrypt.GenerateFromPassword(
		[]byte(password),
		bcryptCost,
	)

	if err != nil {
		return "", err
	}

	return string(hashedPassword), nil
}

// ComparePassword compares a plain password with its bcrypt hash.
func ComparePassword(hashedPassword, password string) error {
	if len(password) > 72 {
		return ErrPasswordTooLong
	}

	return bcrypt.CompareHashAndPassword(
		[]byte(hashedPassword),
		[]byte(password),
	)
}
