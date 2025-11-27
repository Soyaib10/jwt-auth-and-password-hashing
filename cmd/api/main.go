package main

import (
	"log"
	"net/http"

	"github.com/Soyaib10/jwt-auth-and-password-hashing/internal/config"
	"github.com/Soyaib10/jwt-auth-and-password-hashing/internal/database"
	"github.com/Soyaib10/jwt-auth-and-password-hashing/internal/handlers"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal("Failed to load config:", err)
	}

	db, err := database.NewPool(cfg)
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	defer db.Close()

	authHandler := &handlers.AuthHandler{
		DB:        db,
		JWTSecret: cfg.JWTSecret,
	}

	profileHandler := &handlers.ProfileHandler{
		DB: db,
	}

	r := setupRoutes(authHandler, profileHandler, cfg.JWTSecret)

	log.Printf("Server starting on port %s", cfg.Port)
	if err := http.ListenAndServe(":"+cfg.Port, r); err != nil {
		log.Fatal("Server failed:", err)
	}
}
