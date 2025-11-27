package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/Soyaib10/jwt-auth-and-password-hashing/internal/helpers"
	"github.com/Soyaib10/jwt-auth-and-password-hashing/internal/models"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type RefreshHandler struct {
	DB        *pgxpool.Pool
	JWTSecret string
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type RefreshResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func (h *RefreshHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	claims, err := helpers.ValidateRefreshToken(req.RefreshToken, h.JWTSecret)
	if err != nil {
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	jti := claims["jti"].(string)
	userID := int(claims["user_id"].(float64))

	storedToken, err := models.GetRefreshToken(r.Context(), h.DB, jti)
	if err != nil {
		if err == pgx.ErrNoRows {
			models.DeleteAllUserTokens(r.Context(), h.DB, userID)
			http.Error(w, "Token reuse detected", http.StatusUnauthorized)
			return
		}
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	tokenHash := helpers.HashToken(req.RefreshToken)
	if storedToken.TokenHash != tokenHash {
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	if err := models.DeleteRefreshToken(r.Context(), h.DB, jti); err != nil {
		http.Error(w, "Failed to rotate token", http.StatusInternalServerError)
		return
	}

	user, err := models.GetUserByEmail(r.Context(), h.DB, claims["email"].(string))
	if err != nil {
		user = &models.User{ID: userID}
	}

	accessToken, err := helpers.GenerateAccessToken(userID, user.Email, h.JWTSecret)
	if err != nil {
		http.Error(w, "Failed to generate access token", http.StatusInternalServerError)
		return
	}

	newRefreshToken, newJTI, err := helpers.GenerateRefreshToken(userID, h.JWTSecret)
	if err != nil {
		http.Error(w, "Failed to generate refresh token", http.StatusInternalServerError)
		return
	}

	newTokenHash := helpers.HashToken(newRefreshToken)
	expiresAt := time.Now().Add(7 * 24 * time.Hour)

	if err := models.StoreRefreshToken(r.Context(), h.DB, userID, newJTI, newTokenHash, expiresAt); err != nil {
		http.Error(w, "Failed to store refresh token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(RefreshResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
	})
}
