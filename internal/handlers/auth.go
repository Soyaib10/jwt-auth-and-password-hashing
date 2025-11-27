package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/Soyaib10/jwt-auth-and-password-hashing/internal/helpers"
	"github.com/Soyaib10/jwt-auth-and-password-hashing/internal/models"
	"github.com/jackc/pgx/v5/pgxpool"
)

type AuthHandler struct {
	DB        *pgxpool.Pool
	JWTSecret string
}

type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginResponse struct {
	AccessToken  string       `json:"access_token"`
	RefreshToken string       `json:"refresh_token"`
	User         *models.User `json:"user"`
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	user, err := models.CreateUser(r.Context(), h.DB, req.Email, req.Password)
	if err != nil {
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(user)
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	user, err := models.GetUserByEmail(r.Context(), h.DB, req.Email)
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if err := helpers.CheckPassword(user.PasswordHash, req.Password); err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	accessToken, err := helpers.GenerateAccessToken(user.ID, user.Email, h.JWTSecret)
	if err != nil {
		http.Error(w, "Failed to generate access token", http.StatusInternalServerError)
		return
	}

	refreshToken, jti, err := helpers.GenerateRefreshToken(user.ID, h.JWTSecret)
	if err != nil {
		http.Error(w, "Failed to generate refresh token", http.StatusInternalServerError)
		return
	}

	tokenHash := helpers.HashToken(refreshToken)
	expiresAt := time.Now().Add(7 * 24 * time.Hour)

	if err := models.StoreRefreshToken(r.Context(), h.DB, user.ID, jti, tokenHash, expiresAt); err != nil {
		http.Error(w, "Failed to store refresh token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User:         user,
	})
}

