package model

import (
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

type User struct {
	ID              bson.ObjectID `bson:"_id,omitempty" json:"id"`
	Name            string        `bson:"name" json:"name"`
	Email           string        `bson:"email" json:"email"`
	PasswordHash    string        `bson:"password_hash" json:"-"`
	IsEmailVerified bool          `bson:"is_email_verified" json:"is_email_verified"`
	EmailVerifiedAt *time.Time    `bson:"email_verified_at,omitempty" json:"-"`
	CreatedAt       time.Time     `bson:"created_at" json:"created_at"`
	UpdatedAt       time.Time     `bson:"updated_at" json:"updated_at"`
}
