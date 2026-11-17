package model

import (
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

type EmailOTP struct {
	ID                bson.ObjectID `bson:"_id,omitempty"`
	UserID            bson.ObjectID `bson:"user_id"`
	Email             string        `bson:"email"`
	Purpose           string        `bson:"purpose"`
	OTPHash           string        `bson:"otp_hash"`
	Attempts          int           `bson:"attempts"`
	MaxAttempts       int           `bson:"max_attempts"`
	ExpiresAt         time.Time     `bson:"expires_at"`
	ResendAvailableAt time.Time     `bson:"resend_available_at"`
	CreatedAt         time.Time     `bson:"created_at"`
	UpdatedAt         time.Time     `bson:"updated_at"`
}
