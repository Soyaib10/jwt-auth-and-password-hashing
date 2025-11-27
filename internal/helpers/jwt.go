package helpers

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func GenerateAccessToken(userID int, email, secret string) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"email":   email,
		"type":    "access",
		"exp":     time.Now().Add(15 * time.Minute).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

func GenerateRefreshToken(userID int, secret string) (string, string, error) {
	jti := uuid.New().String()

	claims := jwt.MapClaims{
		"user_id": userID,
		"jti":     jti,
		"type":    "refresh",
		"exp":     time.Now().Add(7 * 24 * time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(secret))
	return tokenString, jti, err
}

func ValidateRefreshToken(tokenString, secret string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte(secret), nil
	})

	if err != nil || !token.Valid {
		return nil, errors.New("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid claims")
	}

	if claims["type"] != "refresh" {
		return nil, errors.New("invalid token type")
	}

	return claims, nil
}

func HashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// Deprecated: Use GenerateAccessToken instead
func GenerateJWT(userID int, email, secret string) (string, error) {
	return GenerateAccessToken(userID, email, secret)
}
