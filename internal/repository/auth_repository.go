package repository

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

var (
	ErrEmailExists                = errors.New("email already exists")
	ErrInvalidRefreshToken        = errors.New("invalid refresh token")
	ErrInvalidEmailOTP            = errors.New("invalid email OTP")
	ErrEmailVerificationExpired   = errors.New("email verification expired")
	ErrEmailVerificationLocked    = errors.New("maximum OTP attempts exceeded")
	ErrEmailAlreadyVerified       = errors.New("email already verified")
	ErrVerificationUserNotFound   = errors.New("verification user not found")
	ErrVerificationResendCooldown = errors.New("OTP resend cooldown active")
)

type User struct {
	ID            string
	Name          string
	Email         string
	PasswordHash  string
	EmailVerified bool
}

type AuthRepository struct {
	db *sql.DB
}

func NewAuthRepository(db *sql.DB) *AuthRepository {
	return &AuthRepository{db: db}
}

// CreatePendingUserWithOTP creates an unverified user
// and their initial verification OTP atomically.
func (r *AuthRepository) CreatePendingUserWithOTP(
	ctx context.Context,
	name string,
	email string,
	passwordHash string,
	codeHash []byte,
	expiresAt time.Time,
) (User, error) {

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback()

	user := User{
		ID:            uuid.NewString(),
		Name:          name,
		Email:         email,
		PasswordHash:  passwordHash,
		EmailVerified: false,
	}

	query := `
		INSERT INTO users (
			id, name, email, password_hash, email_verified
		)
		VALUES ($1, $2, $3, $4, FALSE)
		RETURNING id::text
	`

	err = tx.QueryRowContext(
		ctx,
		query,
		user.ID,
		user.Name,
		user.Email,
		user.PasswordHash,
	).Scan(&user.ID)

	if err != nil {
		var pqErr *pq.Error

		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			return User{}, ErrEmailExists
		}

		return User{}, err
	}

	_, err = tx.ExecContext(
		ctx,
		`
			INSERT INTO email_verification_otps (
				id, user_id, code_hash, expires_at
			)
			VALUES ($1, $2, $3, $4)
		`,
		uuid.NewString(),
		user.ID,
		codeHash,
		expiresAt,
	)

	if err != nil {
		return User{}, err
	}

	if err := tx.Commit(); err != nil {
		return User{}, err
	}

	return user, nil
}

// GetUserByEmail retrieves a user for login.
func (r *AuthRepository) GetUserByEmail(
	ctx context.Context,
	email string,
) (User, error) {

	var user User

	query := `
		SELECT
			id::text,
			name,
			email,
			password_hash,
			email_verified
		FROM users
		WHERE LOWER(email) = LOWER($1)
		LIMIT 1
	`

	err := r.db.QueryRowContext(
		ctx,
		query,
		email,
	).Scan(
		&user.ID,
		&user.Name,
		&user.Email,
		&user.PasswordHash,
		&user.EmailVerified,
	)

	if err != nil {
		return User{}, err
	}

	return user, nil
}

// IssueEmailVerificationOTP invalidates the previous OTP
// and stores a new OTP after checking the resend cooldown.
func (r *AuthRepository) IssueEmailVerificationOTP(
	ctx context.Context,
	email string,
	codeHash []byte,
	expiresAt time.Time,
	cooldown time.Duration,
) (User, error) {

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback()

	var user User

	err = tx.QueryRowContext(
		ctx,
		`
			SELECT id::text, name, email, password_hash, email_verified
			FROM users
			WHERE LOWER(email) = LOWER($1)
			FOR UPDATE
		`,
		email,
	).Scan(
		&user.ID,
		&user.Name,
		&user.Email,
		&user.PasswordHash,
		&user.EmailVerified,
	)

	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrVerificationUserNotFound
	}

	if err != nil {
		return User{}, err
	}

	if user.EmailVerified {
		return User{}, ErrEmailAlreadyVerified
	}

	var lastCreated time.Time

	err = tx.QueryRowContext(
		ctx,
		`
			SELECT created_at
			FROM email_verification_otps
			WHERE user_id = $1
			ORDER BY created_at DESC
			LIMIT 1
		`,
		user.ID,
	).Scan(&lastCreated)

	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return User{}, err
	}

	if err == nil && time.Now().Before(lastCreated.Add(cooldown)) {
		return User{}, ErrVerificationResendCooldown
	}

	_, err = tx.ExecContext(
		ctx,
		`
			UPDATE email_verification_otps
			SET consumed_at = NOW()
			WHERE user_id = $1
			  AND consumed_at IS NULL
		`,
		user.ID,
	)

	if err != nil {
		return User{}, err
	}

	_, err = tx.ExecContext(
		ctx,
		`
			INSERT INTO email_verification_otps (
				id, user_id, code_hash, expires_at
			)
			VALUES ($1, $2, $3, $4)
		`,
		uuid.NewString(),
		user.ID,
		codeHash,
		expiresAt,
	)

	if err != nil {
		return User{}, err
	}

	if err := tx.Commit(); err != nil {
		return User{}, err
	}

	return user, nil
}

// VerifyEmailOTP checks the OTP and marks the user as verified.
// Both operations happen inside one transaction.
func (r *AuthRepository) VerifyEmailOTP(
	ctx context.Context,
	email string,
	submittedHash []byte,
	maxAttempts int,
) (User, error) {

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback()

	var user User

	err = tx.QueryRowContext(
		ctx,
		`
			SELECT id::text, name, email, password_hash, email_verified
			FROM users
			WHERE LOWER(email) = LOWER($1)
			FOR UPDATE
		`,
		email,
	).Scan(
		&user.ID,
		&user.Name,
		&user.Email,
		&user.PasswordHash,
		&user.EmailVerified,
	)

	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrInvalidEmailOTP
	}

	if err != nil {
		return User{}, err
	}

	if user.EmailVerified {
		return User{}, ErrEmailAlreadyVerified
	}

	var (
		otpID      string
		storedHash []byte
		expiresAt  time.Time
		attempts   int
		consumedAt sql.NullTime
	)

	err = tx.QueryRowContext(
		ctx,
		`
			SELECT id::text, code_hash, expires_at, attempts, consumed_at
			FROM email_verification_otps
			WHERE user_id = $1
			ORDER BY created_at DESC
			LIMIT 1
			FOR UPDATE
		`,
		user.ID,
	).Scan(
		&otpID,
		&storedHash,
		&expiresAt,
		&attempts,
		&consumedAt,
	)

	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrInvalidEmailOTP
	}

	if err != nil {
		return User{}, err
	}

	if consumedAt.Valid {
		return User{}, ErrInvalidEmailOTP
	}

	if attempts >= maxAttempts {
		return User{}, ErrEmailVerificationLocked
	}

	if !expiresAt.After(time.Now()) {
		_, err = tx.ExecContext(
			ctx,
			`UPDATE email_verification_otps
			 SET consumed_at = NOW()
			 WHERE id = $1`,
			otpID,
		)

		if err != nil {
			return User{}, err
		}

		if err := tx.Commit(); err != nil {
			return User{}, err
		}

		return User{}, ErrEmailVerificationExpired
	}

	if subtle.ConstantTimeCompare(storedHash, submittedHash) != 1 {
		nextAttempts := attempts + 1

		_, err = tx.ExecContext(
			ctx,
			`
				UPDATE email_verification_otps
				SET attempts = $1,
				    consumed_at = CASE
				        WHEN $1 >= $2 THEN NOW()
				        ELSE consumed_at
				    END
				WHERE id = $3
			`,
			nextAttempts,
			maxAttempts,
			otpID,
		)

		if err != nil {
			return User{}, err
		}

		if err := tx.Commit(); err != nil {
			return User{}, err
		}

		if nextAttempts >= maxAttempts {
			return User{}, ErrEmailVerificationLocked
		}

		return User{}, ErrInvalidEmailOTP
	}

	_, err = tx.ExecContext(
		ctx,
		`
			UPDATE email_verification_otps
			SET consumed_at = NOW()
			WHERE id = $1
		`,
		otpID,
	)

	if err != nil {
		return User{}, err
	}

	_, err = tx.ExecContext(
		ctx,
		`
			UPDATE users
			SET email_verified = TRUE,
			    updated_at = NOW()
			WHERE id = $1
		`,
		user.ID,
	)

	if err != nil {
		return User{}, err
	}

	if err := tx.Commit(); err != nil {
		return User{}, err
	}

	user.EmailVerified = true

	return user, nil
}

// CreateRefreshSession stores a hashed refresh token.
func (r *AuthRepository) CreateRefreshSession(
	ctx context.Context,
	userID string,
	familyID string,
	tokenHash []byte,
	expiresAt time.Time,
) error {

	_, err := r.db.ExecContext(
		ctx,
		`
			INSERT INTO auth_refresh_tokens (
				id, user_id, family_id, token_hash, expires_at
			)
			VALUES ($1, $2, $3, $4, $5)
		`,
		uuid.NewString(),
		userID,
		familyID,
		tokenHash,
		expiresAt,
	)

	return err
}

// RotateRefreshToken atomically replaces the old token.
func (r *AuthRepository) RotateRefreshToken(
	ctx context.Context,
	oldHash []byte,
	newHash []byte,
	newExpiry time.Time,
) (User, error) {

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback()

	var (
		sessionID string
		userID    string
		familyID  string
		expiresAt time.Time
		revokedAt sql.NullTime
	)

	err = tx.QueryRowContext(
		ctx,
		`
			SELECT id::text, user_id::text, family_id::text,
			       expires_at, revoked_at
			FROM auth_refresh_tokens
			WHERE token_hash = $1
			FOR UPDATE
		`,
		oldHash,
	).Scan(
		&sessionID,
		&userID,
		&familyID,
		&expiresAt,
		&revokedAt,
	)

	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrInvalidRefreshToken
	}

	if err != nil {
		return User{}, err
	}

	// Reuse detection: revoke the complete session family.
	if revokedAt.Valid {
		_, err = tx.ExecContext(
			ctx,
			`
				UPDATE auth_refresh_tokens
				SET revoked_at = NOW()
				WHERE family_id = $1
				  AND revoked_at IS NULL
			`,
			familyID,
		)

		if err != nil {
			return User{}, err
		}

		if err := tx.Commit(); err != nil {
			return User{}, err
		}

		return User{}, ErrInvalidRefreshToken
	}

	if !expiresAt.After(time.Now()) {
		_, err = tx.ExecContext(
			ctx,
			`
				UPDATE auth_refresh_tokens
				SET revoked_at = NOW()
				WHERE id = $1
			`,
			sessionID,
		)

		if err != nil {
			return User{}, err
		}

		if err := tx.Commit(); err != nil {
			return User{}, err
		}

		return User{}, ErrInvalidRefreshToken
	}

	var user User

	err = tx.QueryRowContext(
		ctx,
		`
			SELECT id::text, name, email, password_hash, email_verified
			FROM users
			WHERE id = $1
		`,
		userID,
	).Scan(
		&user.ID,
		&user.Name,
		&user.Email,
		&user.PasswordHash,
		&user.EmailVerified,
	)

	if err != nil {
		return User{}, err
	}

	_, err = tx.ExecContext(
		ctx,
		`
			UPDATE auth_refresh_tokens
			SET revoked_at = NOW(),
			    replaced_by_token_hash = $1
			WHERE id = $2
		`,
		newHash,
		sessionID,
	)

	if err != nil {
		return User{}, err
	}

	_, err = tx.ExecContext(
		ctx,
		`
			INSERT INTO auth_refresh_tokens (
				id, user_id, family_id, token_hash, expires_at
			)
			VALUES ($1, $2, $3, $4, $5)
		`,
		uuid.NewString(),
		user.ID,
		familyID,
		newHash,
		newExpiry,
	)

	if err != nil {
		return User{}, err
	}

	if err := tx.Commit(); err != nil {
		return User{}, err
	}

	return user, nil
}

// RevokeRefreshToken logs out the current session.
func (r *AuthRepository) RevokeRefreshToken(
	ctx context.Context,
	tokenHash []byte,
) error {

	result, err := r.db.ExecContext(
		ctx,
		`
			UPDATE auth_refresh_tokens
			SET revoked_at = COALESCE(revoked_at, NOW())
			WHERE token_hash = $1
		`,
		tokenHash,
	)

	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rows == 0 {
		return ErrInvalidRefreshToken
	}

	return nil
}
