package security

import "testing"

func TestPasswordHash(t *testing.T) {
	password := "MySecurePassword123"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	if err := ComparePassword(hash, password); err != nil {
		t.Fatal("Password should match:", err)
	}

	if err := ComparePassword(hash, "WrongPassword123"); err == nil {
		t.Fatal("Wrong password should not match")
	}
}

func TestOTP(t *testing.T) {
	otp, err := GenerateOTP()
	if err != nil {
		t.Fatal(err)
	}

	if len(otp) != 6 {
		t.Fatal("OTP should contain six digits")
	}

	pepper := "01234567890123456789012345678901"

	hash, err := HashEmailOTP(
		"rahul@example.com",
		"signup",
		otp,
		pepper,
	)
	if err != nil {
		t.Fatal(err)
	}

	if !VerifyEmailOTP(
		"rahul@example.com",
		"signup",
		otp,
		pepper,
		hash,
	) {
		t.Fatal("OTP verification failed")
	}

	if VerifyEmailOTP(
		"another@example.com",
		"signup",
		otp,
		pepper,
		hash,
	) {
		t.Fatal("OTP should not work for another email")
	}
}

func TestJWT(t *testing.T) {
	manager, err := NewJWTManager(
		"01234567890123456789012345678901",
		15*60*1000000000,
	)
	if err != nil {
		t.Fatal(err)
	}

	token, _, err := manager.GenerateAccessToken(
		"user123",
		"rahul@example.com",
	)
	if err != nil {
		t.Fatal(err)
	}

	claims, err := manager.ValidateAccessToken(token)
	if err != nil {
		t.Fatal(err)
	}

	if claims.Subject != "user123" {
		t.Fatal("Unexpected user ID")
	}
}
