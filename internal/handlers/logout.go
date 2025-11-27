package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/Soyaib10/jwt-auth-and-password-hashing/internal/helpers"
	"github.com/Soyaib10/jwt-auth-and-password-hashing/internal/middleware"
	"github.com/Soyaib10/jwt-auth-and-password-hashing/internal/models"
	"github.com/jackc/pgx/v5/pgxpool"
)

type LogoutHandler struct {
	DB        *pgxpool.Pool
	JWTSecret string
}

type LogoutRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func (h *LogoutHandler) Logout(w http.ResponseWriter, r *http.Request) {
	var req LogoutRequest
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

	if err := models.DeleteRefreshToken(r.Context(), h.DB, jti); err != nil {
		http.Error(w, "Failed to logout", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Logged out successfully"})
}

func (h *LogoutHandler) LogoutAll(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r)

	if err := models.DeleteAllUserTokens(r.Context(), h.DB, userID); err != nil {
		http.Error(w, "Failed to logout", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Logged out from all devices"})
}
