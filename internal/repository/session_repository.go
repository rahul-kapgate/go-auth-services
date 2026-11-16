package repository

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
)

var ErrSessionNotFound = errors.New("session not found")

type Session struct {
	ID                  string
	UserID              string
	FamilyID            string
	TokenHash           string
	ExpiresAt           time.Time
	RevokedAt           sql.NullTime
	ReplacedByTokenHash sql.NullString
	CreatedAt           time.Time
}

type SessionRepository struct {
	db *sql.DB
}

func NewSessionRepository(db *sql.DB) *SessionRepository {
	return &SessionRepository{db: db}
}

// Create creates a refresh-token session.
func (r *SessionRepository) Create(
	ctx context.Context,
	userID string,
	tokenHash string,
	expiresAt time.Time,
) (*Session, error) {
	session := &Session{
		ID:        uuid.NewString(),
		UserID:    userID,
		FamilyID:  uuid.NewString(),
		TokenHash: tokenHash,
		ExpiresAt: expiresAt,
	}

	query := `
		INSERT INTO auth_refresh_tokens (
			id,
			user_id,
			family_id,
			token_hash,
			expires_at,
			created_at
		)
		VALUES ($1, $2, $3, $4, $5, NOW())
		RETURNING created_at
	`

	err := r.db.QueryRowContext(
		ctx,
		query,
		session.ID,
		session.UserID,
		session.FamilyID,
		session.TokenHash,
		session.ExpiresAt,
	).Scan(&session.CreatedAt)

	if err != nil {
		return nil, err
	}

	return session, nil
}

// FindByTokenHash retrieves a session by its token hash.
func (r *SessionRepository) FindByTokenHash(
	ctx context.Context,
	tokenHash string,
) (*Session, error) {
	query := `
		SELECT id, user_id, family_id, token_hash,
		       expires_at, revoked_at,
		       replaced_by_token_hash, created_at
		FROM auth_refresh_tokens
		WHERE token_hash = $1
		LIMIT 1
	`

	session := &Session{}

	err := r.db.QueryRowContext(
		ctx,
		query,
		tokenHash,
	).Scan(
		&session.ID,
		&session.UserID,
		&session.FamilyID,
		&session.TokenHash,
		&session.ExpiresAt,
		&session.RevokedAt,
		&session.ReplacedByTokenHash,
		&session.CreatedAt,
	)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrSessionNotFound
	}

	if err != nil {
		return nil, err
	}

	return session, nil
}

// Revoke revokes a refresh-token session.
func (r *SessionRepository) Revoke(
	ctx context.Context,
	tokenHash string,
) error {
	query := `
		UPDATE auth_refresh_tokens
		SET revoked_at = NOW()
		WHERE token_hash = $1
		  AND revoked_at IS NULL
	`

	_, err := r.db.ExecContext(ctx, query, tokenHash)
	return err
}

// RevokeAllForUser revokes every active session belonging to a user.
func (r *SessionRepository) RevokeAllForUser(
	ctx context.Context,
	userID string,
) error {
	query := `
		UPDATE auth_refresh_tokens
		SET revoked_at = NOW()
		WHERE user_id = $1
		  AND revoked_at IS NULL
	`

	_, err := r.db.ExecContext(ctx, query, userID)
	return err
}

// IsActive checks whether a session is valid.
func (r *SessionRepository) IsActive(
	ctx context.Context,
	tokenHash string,
) (bool, error) {
	query := `
		SELECT EXISTS (
			SELECT 1
			FROM auth_refresh_tokens
			WHERE token_hash = $1
			  AND revoked_at IS NULL
			  AND expires_at > NOW()
		)
	`

	var active bool

	err := r.db.QueryRowContext(
		ctx,
		query,
		tokenHash,
	).Scan(&active)

	return active, err
}
