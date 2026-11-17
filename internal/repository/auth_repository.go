package repository

import (
	"context"
	"errors"
	"strings"
	"time"

	"auth-service/internal/model"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

var (
	ErrOTPCooldown            = errors.New("OTP resend cooldown is active")
	ErrOTPInvalidOrExpired    = errors.New("OTP is invalid, expired, or already used")
	ErrRefreshSessionInactive = errors.New("refresh session is inactive or expired")
	ErrUserNotEligible        = errors.New("user does not exist or email is already verified")
)

type AuthRepository struct {
	client   *mongo.Client
	users    *mongo.Collection
	otps     *mongo.Collection
	sessions *mongo.Collection
}

func NewAuthRepository(client *mongo.Client, db *mongo.Database) *AuthRepository {
	return &AuthRepository{
		client:   client,
		users:    db.Collection("users"),
		otps:     db.Collection("email_otps"),
		sessions: db.Collection("refresh_sessions"),
	}
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// =====================================================
// USER OPERATIONS
// =====================================================

// CreateUser creates a new user.
func (r *AuthRepository) CreateUser(
	ctx context.Context,
	user *model.User,
) error {
	user.Email = normalizeEmail(user.Email)

	if user.ID.IsZero() {
		user.ID = bson.NewObjectID()
	}

	_, err := r.users.InsertOne(ctx, user)
	return err
}

// GetUserByEmail retrieves a user by email.
func (r *AuthRepository) GetUserByEmail(
	ctx context.Context,
	email string,
) (*model.User, error) {
	var user model.User

	err := r.users.FindOne(
		ctx,
		bson.D{{Key: "email", Value: normalizeEmail(email)}},
	).Decode(&user)

	if err != nil {
		return nil, err
	}

	return &user, nil
}

// GetUserByID retrieves a user by MongoDB ObjectID.
func (r *AuthRepository) GetUserByID(
	ctx context.Context,
	userID bson.ObjectID,
) (*model.User, error) {
	var user model.User

	err := r.users.FindOne(
		ctx,
		bson.D{{Key: "_id", Value: userID}},
	).Decode(&user)

	if err != nil {
		return nil, err
	}

	return &user, nil
}

// MarkUserEmailVerified marks a user's email as verified.
func (r *AuthRepository) MarkUserEmailVerified(
	ctx context.Context,
	userID bson.ObjectID,
	now time.Time,
) (bool, error) {
	result, err := r.users.UpdateOne(
		ctx,
		bson.D{
			{Key: "_id", Value: userID},
			{Key: "is_email_verified", Value: false},
		},
		bson.D{
			{
				Key: "$set",
				Value: bson.D{
					{Key: "is_email_verified", Value: true},
					{Key: "email_verified_at", Value: now},
					{Key: "updated_at", Value: now},
				},
			},
		},
	)

	if err != nil {
		return false, err
	}

	return result.ModifiedCount == 1, nil
}

// =====================================================
// EMAIL OTP OPERATIONS
// =====================================================

// FindEmailOTP retrieves an OTP by email and purpose.
func (r *AuthRepository) FindEmailOTP(
	ctx context.Context,
	email string,
	purpose string,
) (*model.EmailOTP, error) {
	var otp model.EmailOTP

	err := r.otps.FindOne(
		ctx,
		bson.D{
			{Key: "email", Value: normalizeEmail(email)},
			{Key: "purpose", Value: purpose},
		},
	).Decode(&otp)

	if err != nil {
		return nil, err
	}

	return &otp, nil
}

// SaveEmailOTP inserts a new OTP or updates an existing OTP
// after the resend cooldown has elapsed.
func (r *AuthRepository) SaveEmailOTP(
	ctx context.Context,
	otp *model.EmailOTP,
) error {
	otp.Email = normalizeEmail(otp.Email)

	if otp.ID.IsZero() {
		otp.ID = bson.NewObjectID()
	}

	filter := bson.D{
		{Key: "email", Value: otp.Email},
		{Key: "purpose", Value: otp.Purpose},
	}

	var existing model.EmailOTP

	err := r.otps.FindOne(ctx, filter).Decode(&existing)

	if errors.Is(err, mongo.ErrNoDocuments) {
		_, err = r.otps.InsertOne(ctx, otp)

		if mongo.IsDuplicateKeyError(err) {
			return r.updateExistingOTP(ctx, otp)
		}

		return err
	}

	if err != nil {
		return err
	}

	if otp.CreatedAt.Before(existing.ResendAvailableAt) {
		return ErrOTPCooldown
	}

	return r.updateExistingOTP(ctx, otp)
}

// updateExistingOTP updates an OTP only when its resend cooldown has elapsed.
func (r *AuthRepository) updateExistingOTP(
	ctx context.Context,
	otp *model.EmailOTP,
) error {
	result, err := r.otps.UpdateOne(
		ctx,
		bson.D{
			{Key: "email", Value: otp.Email},
			{Key: "purpose", Value: otp.Purpose},
			{
				Key: "resend_available_at",
				Value: bson.D{
					{Key: "$lte", Value: otp.CreatedAt},
				},
			},
		},
		bson.D{
			{
				Key: "$set",
				Value: bson.D{
					{Key: "user_id", Value: otp.UserID},
					{Key: "otp_hash", Value: otp.OTPHash},
					{Key: "attempts", Value: 0},
					{Key: "max_attempts", Value: otp.MaxAttempts},
					{Key: "expires_at", Value: otp.ExpiresAt},
					{Key: "resend_available_at", Value: otp.ResendAvailableAt},
					{Key: "created_at", Value: otp.CreatedAt},
					{Key: "updated_at", Value: otp.UpdatedAt},
				},
			},
		},
	)

	if err != nil {
		return err
	}

	if result.ModifiedCount == 0 {
		return ErrOTPCooldown
	}

	return nil
}

// IncrementOTPAttempts increments the failed verification attempts.
// It never increments beyond the configured maximum.
func (r *AuthRepository) IncrementOTPAttempts(
	ctx context.Context,
	otpID bson.ObjectID,
	now time.Time,
) (bool, error) {
	filter := bson.D{
		{Key: "_id", Value: otpID},
		{
			Key: "expires_at",
			Value: bson.D{
				{Key: "$gt", Value: now},
			},
		},
		{
			Key: "$expr",
			Value: bson.D{
				{
					Key: "$lt",
					Value: bson.A{
						"$attempts",
						"$max_attempts",
					},
				},
			},
		},
	}

	result, err := r.otps.UpdateOne(
		ctx,
		filter,
		bson.D{
			{
				Key: "$inc",
				Value: bson.D{
					{Key: "attempts", Value: 1},
				},
			},
			{
				Key: "$set",
				Value: bson.D{
					{Key: "updated_at", Value: now},
				},
			},
		},
	)

	if err != nil {
		return false, err
	}

	return result.ModifiedCount == 1, nil
}

// ConsumeEmailOTP atomically deletes an OTP after successful verification.
// This ensures an OTP cannot be successfully reused.
func (r *AuthRepository) ConsumeEmailOTP(
	ctx context.Context,
	otpID bson.ObjectID,
	otpHash string,
	now time.Time,
) (bool, error) {
	result, err := r.otps.DeleteOne(
		ctx,
		bson.D{
			{Key: "_id", Value: otpID},
			{Key: "otp_hash", Value: otpHash},
			{
				Key: "expires_at",
				Value: bson.D{
					{Key: "$gt", Value: now},
				},
			},
			{
				Key: "$expr",
				Value: bson.D{
					{
						Key: "$lt",
						Value: bson.A{
							"$attempts",
							"$max_attempts",
						},
					},
				},
			},
		},
	)

	if err != nil {
		return false, err
	}

	if result.DeletedCount != 1 {
		return false, ErrOTPInvalidOrExpired
	}

	return true, nil
}

// =====================================================
// REFRESH TOKEN OPERATIONS
// =====================================================

// CreateRefreshSession stores a new refresh-token session.
func (r *AuthRepository) CreateRefreshSession(
	ctx context.Context,
	session *model.RefreshSession,
) error {
	if session.ID.IsZero() {
		session.ID = bson.NewObjectID()
	}

	if session.FamilyID.IsZero() {
		session.FamilyID = bson.NewObjectID()
	}

	_, err := r.sessions.InsertOne(ctx, session)
	return err
}

// FindRefreshSessionByHash retrieves a refresh session.
func (r *AuthRepository) FindRefreshSessionByHash(
	ctx context.Context,
	tokenHash string,
) (*model.RefreshSession, error) {
	var session model.RefreshSession

	err := r.sessions.FindOne(
		ctx,
		bson.D{{Key: "token_hash", Value: tokenHash}},
	).Decode(&session)

	if err != nil {
		return nil, err
	}

	return &session, nil
}

// RotateRefreshSession atomically revokes an old token and stores
// its replacement within a MongoDB transaction.
func (r *AuthRepository) RotateRefreshSession(
	ctx context.Context,
	oldTokenHash string,
	newSession *model.RefreshSession,
	now time.Time,
) error {
	if newSession.ID.IsZero() {
		newSession.ID = bson.NewObjectID()
	}

	session, err := r.client.StartSession()
	if err != nil {
		return err
	}
	defer session.EndSession(ctx)

	_, err = session.WithTransaction(
		ctx,
		func(txCtx context.Context) (interface{}, error) {

			// Revoke the existing token only if it is still active.
			result, err := r.sessions.UpdateOne(
				txCtx,
				bson.D{
					{Key: "token_hash", Value: oldTokenHash},
					{
						Key: "revoked_at",
						Value: bson.D{
							{Key: "$exists", Value: false},
						},
					},
					{
						Key: "expires_at",
						Value: bson.D{
							{Key: "$gt", Value: now},
						},
					},
				},
				bson.D{
					{
						Key: "$set",
						Value: bson.D{
							{Key: "revoked_at", Value: now},
							{Key: "revoked_reason", Value: "rotated"},
							{Key: "replaced_by_token_hash", Value: newSession.TokenHash},
							{Key: "last_used_at", Value: now},
						},
					},
				},
			)

			if err != nil {
				return nil, err
			}

			if result.ModifiedCount != 1 {
				return nil, ErrRefreshSessionInactive
			}

			// Insert the replacement token in the same transaction.
			_, err = r.sessions.InsertOne(txCtx, newSession)
			if err != nil {
				return nil, err
			}

			return nil, nil
		},
	)

	return err
}

// RevokeRefreshSession revokes one active refresh session.
func (r *AuthRepository) RevokeRefreshSession(
	ctx context.Context,
	tokenHash string,
	now time.Time,
	reason string,
) (bool, error) {
	result, err := r.sessions.UpdateOne(
		ctx,
		bson.D{
			{Key: "token_hash", Value: tokenHash},
			{
				Key: "revoked_at",
				Value: bson.D{
					{Key: "$exists", Value: false},
				},
			},
		},
		bson.D{
			{
				Key: "$set",
				Value: bson.D{
					{Key: "revoked_at", Value: now},
					{Key: "revoked_reason", Value: reason},
				},
			},
		},
	)

	if err != nil {
		return false, err
	}

	return result.ModifiedCount == 1, nil
}

// RevokeTokenFamily revokes every active refresh token
// belonging to the same token family.
func (r *AuthRepository) RevokeTokenFamily(
	ctx context.Context,
	familyID bson.ObjectID,
	now time.Time,
	reason string,
) error {
	_, err := r.sessions.UpdateMany(
		ctx,
		bson.D{
			{Key: "family_id", Value: familyID},
			{
				Key: "revoked_at",
				Value: bson.D{
					{Key: "$exists", Value: false},
				},
			},
		},
		bson.D{
			{
				Key: "$set",
				Value: bson.D{
					{Key: "revoked_at", Value: now},
					{Key: "revoked_reason", Value: reason},
				},
			},
		},
	)

	return err
}

func (r *AuthRepository) ConsumeOTPAndVerifyUser(
	ctx context.Context,
	userID bson.ObjectID,
	otpID bson.ObjectID,
	otpHash string,
	now time.Time,
) error {

	session, err := r.client.StartSession()
	if err != nil {
		return err
	}
	defer session.EndSession(ctx)

	_, err = session.WithTransaction(
		ctx,
		func(txCtx context.Context) (interface{}, error) {

			// 1. Delete OTP only if it is valid.
			result, err := r.otps.DeleteOne(
				txCtx,
				bson.D{
					{Key: "_id", Value: otpID},
					{Key: "user_id", Value: userID},
					{Key: "otp_hash", Value: otpHash},
					{
						Key: "expires_at",
						Value: bson.D{
							{Key: "$gt", Value: now},
						},
					},
					{
						Key: "$expr",
						Value: bson.D{
							{
								Key: "$lt",
								Value: bson.A{
									"$attempts",
									"$max_attempts",
								},
							},
						},
					},
				},
			)

			if err != nil {
				return nil, err
			}

			if result.DeletedCount != 1 {
				return nil, ErrOTPInvalidOrExpired
			}

			// 2. Mark user as verified.
			updateResult, err := r.users.UpdateOne(
				txCtx,
				bson.D{
					{Key: "_id", Value: userID},
					{Key: "is_email_verified", Value: false},
				},
				bson.D{
					{
						Key: "$set",
						Value: bson.D{
							{Key: "is_email_verified", Value: true},
							{Key: "email_verified_at", Value: now},
							{Key: "updated_at", Value: now},
						},
					},
				},
			)

			if err != nil {
				return nil, err
			}

			if updateResult.ModifiedCount != 1 {
				return nil, ErrUserNotEligible
			}

			return nil, nil
		},
	)

	return err
}
