package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/Soyaib10/jwt-auth-and-password-hashing/internal/middleware"
	"github.com/Soyaib10/jwt-auth-and-password-hashing/internal/models"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ProfileHandler struct {
	DB *pgxpool.Pool
}

func (h *ProfileHandler) GetProfile(w http.ResponseWriter, r *http.Request) {
	email := middleware.GetUserEmail(r)

	user, err := models.GetUserByEmail(r.Context(), h.DB, email)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}
