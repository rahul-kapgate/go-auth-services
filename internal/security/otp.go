package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

var ErrInvalidOTPConfiguration = errors.New(
	"OTP pepper must contain at least 32 bytes",
)

// GenerateOTP generates a cryptographically secure six-digit OTP.
func GenerateOTP() (string, error) {
	max := big.NewInt(1000000)

	number, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", fmt.Errorf("failed to generate OTP: %w", err)
	}

	return fmt.Sprintf("%06d", number.Int64()), nil
}

// HashEmailOTP generates an HMAC hash for an email OTP.
func HashEmailOTP(
	email string,
	purpose string,
	otp string,
	pepper string,
) (string, error) {
	if len(pepper) < 32 {
		return "", ErrInvalidOTPConfiguration
	}

	if len(otp) != 6 {
		return "", errors.New("OTP must contain exactly 6 digits")
	}

	for _, digit := range otp {
		if digit < '0' || digit > '9' {
			return "", errors.New("OTP must contain only digits")
		}
	}

	email = strings.ToLower(strings.TrimSpace(email))
	purpose = strings.TrimSpace(purpose)

	if email == "" || purpose == "" {
		return "", errors.New("email and OTP purpose are required")
	}

	mac := hmac.New(sha256.New, []byte(pepper))

	// Bind the OTP to the email and its purpose.
	message := email + "\x00" + purpose + "\x00" + otp

	mac.Write([]byte(message))

	return hex.EncodeToString(mac.Sum(nil)), nil
}

// VerifyEmailOTP verifies an OTP using constant-time comparison.
func VerifyEmailOTP(
	email string,
	purpose string,
	otp string,
	pepper string,
	expectedHash string,
) bool {
	actualHash, err := HashEmailOTP(
		email,
		purpose,
		otp,
		pepper,
	)

	if err != nil {
		return false
	}

	return hmac.Equal(
		[]byte(actualHash),
		[]byte(expectedHash),
	)
}
