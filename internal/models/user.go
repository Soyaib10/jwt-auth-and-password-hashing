package models

import (
	"context"
	"time"

	"github.com/Soyaib10/jwt-auth-and-password-hashing/internal/helpers"
	"github.com/jackc/pgx/v5/pgxpool"
)

type User struct {
	ID           int       `json:"id"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
}

func CreateUser(ctx context.Context, db *pgxpool.Pool, email, password string) (*User, error) {
	hash, err := helpers.HashPassword(password)
	if err != nil {
		return nil, err
	}

	var user User
	query := `INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email, created_at`
	err = db.QueryRow(ctx, query, email, hash).Scan(&user.ID, &user.Email, &user.CreatedAt)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

func GetUserByEmail(ctx context.Context, db *pgxpool.Pool, email string) (*User, error) {
	var user User
	query := `SELECT id, email, password_hash, created_at FROM users WHERE email = $1`
	err := db.QueryRow(ctx, query, email).Scan(&user.ID, &user.Email, &user.PasswordHash, &user.CreatedAt)
	if err != nil {
		return nil, err
	}

	return &user, nil
}
