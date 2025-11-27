package models

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type RefreshToken struct {
	ID        int       `json:"id"`
	UserID    int       `json:"user_id"`
	JTI       string    `json:"jti"`
	TokenHash string    `json:"-"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

func StoreRefreshToken(ctx context.Context, db *pgxpool.Pool, userID int, jti, tokenHash string, expiresAt time.Time) error {
	query := `INSERT INTO refresh_tokens (user_id, jti, token_hash, expires_at) VALUES ($1, $2, $3, $4)`
	_, err := db.Exec(ctx, query, userID, jti, tokenHash, expiresAt)
	return err
}

func GetRefreshToken(ctx context.Context, db *pgxpool.Pool, jti string) (*RefreshToken, error) {
	var token RefreshToken
	query := `SELECT id, user_id, jti, token_hash, expires_at, created_at FROM refresh_tokens WHERE jti = $1`
	err := db.QueryRow(ctx, query, jti).Scan(&token.ID, &token.UserID, &token.JTI, &token.TokenHash, &token.ExpiresAt, &token.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &token, nil
}

func DeleteRefreshToken(ctx context.Context, db *pgxpool.Pool, jti string) error {
	query := `DELETE FROM refresh_tokens WHERE jti = $1`
	_, err := db.Exec(ctx, query, jti)
	return err
}

func DeleteAllUserTokens(ctx context.Context, db *pgxpool.Pool, userID int) error {
	query := `DELETE FROM refresh_tokens WHERE user_id = $1`
	_, err := db.Exec(ctx, query, userID)
	return err
}
