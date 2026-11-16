package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"strings"
)

func GenerateOTP() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%06d", n.Int64()), nil
}

// HMAC makes a database-only leak insufficient to efficiently
// test all one-million possible OTP values.
func HashEmailOTP(email, code, pepper string) []byte {
	mac := hmac.New(sha256.New, []byte(pepper))

	value := strings.ToLower(strings.TrimSpace(email)) + ":" + code
	mac.Write([]byte(value))

	return mac.Sum(nil)
}

func IsValidOTP(code string) bool {
	if len(code) != 6 {
		return false
	}

	for _, ch := range code {
		if ch < '0' || ch > '9' {
			return false
		}
	}

	return true
}
