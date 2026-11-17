package model

import (
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

type RefreshSession struct {
	ID                  bson.ObjectID `bson:"_id,omitempty"`
	UserID              bson.ObjectID `bson:"user_id"`
	TokenHash           string        `bson:"token_hash"`
	FamilyID            bson.ObjectID `bson:"family_id"`
	ReplacedByTokenHash string        `bson:"replaced_by_token_hash,omitempty"`
	RevokedAt           *time.Time    `bson:"revoked_at,omitempty"`
	RevokedReason       string        `bson:"revoked_reason,omitempty"`
	ExpiresAt           time.Time     `bson:"expires_at"`
	CreatedAt           time.Time     `bson:"created_at"`
	LastUsedAt          *time.Time    `bson:"last_used_at,omitempty"`
}
