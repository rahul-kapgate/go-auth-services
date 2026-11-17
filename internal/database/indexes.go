package database

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func EnsureIndexes(ctx context.Context, db *mongo.Database) error {
	// Users collection
	users := db.Collection("users")

	_, err := users.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{
			{Key: "email", Value: 1},
		},
		Options: options.Index().
			SetName("uq_users_email").
			SetUnique(true),
	})
	if err != nil {
		return fmt.Errorf("creating users email index: %w", err)
	}

	// Email OTP collection
	otps := db.Collection("email_otps")

	_, err = otps.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{
			{Key: "email", Value: 1},
			{Key: "purpose", Value: 1},
		},
		Options: options.Index().
			SetName("uq_email_otp_email_purpose").
			SetUnique(true),
	})
	if err != nil {
		return fmt.Errorf("creating OTP unique index: %w", err)
	}

	// Automatically delete expired OTP documents.
	_, err = otps.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{
			{Key: "expires_at", Value: 1},
		},
		Options: options.Index().
			SetName("ttl_email_otp_expiry").
			SetExpireAfterSeconds(0),
	})
	if err != nil {
		return fmt.Errorf("creating OTP TTL index: %w", err)
	}

	// Refresh sessions collection
	sessions := db.Collection("refresh_sessions")

	_, err = sessions.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{
			{Key: "token_hash", Value: 1},
		},
		Options: options.Index().
			SetName("uq_refresh_token_hash").
			SetUnique(true),
	})
	if err != nil {
		return fmt.Errorf("creating refresh token index: %w", err)
	}

	_, err = sessions.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{
			{Key: "family_id", Value: 1},
			{Key: "created_at", Value: -1},
		},
		Options: options.Index().
			SetName("idx_refresh_family"),
	})
	if err != nil {
		return fmt.Errorf("creating refresh family index: %w", err)
	}

	_, err = sessions.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{
			{Key: "user_id", Value: 1},
		},
		Options: options.Index().
			SetName("idx_refresh_user"),
	})
	if err != nil {
		return fmt.Errorf("creating refresh user index: %w", err)
	}

	// Automatically clean expired refresh sessions.
	_, err = sessions.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{
			{Key: "expires_at", Value: 1},
		},
		Options: options.Index().
			SetName("ttl_refresh_expiry").
			SetExpireAfterSeconds(0),
	})
	if err != nil {
		return fmt.Errorf("creating refresh TTL index: %w", err)
	}

	return nil
}
