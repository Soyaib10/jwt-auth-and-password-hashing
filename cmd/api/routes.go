package main

import (
	"github.com/Soyaib10/jwt-auth-and-password-hashing/internal/handlers"
	"github.com/Soyaib10/jwt-auth-and-password-hashing/internal/middleware"
	"github.com/go-chi/chi/v5"
)

func setupRoutes(authHandler *handlers.AuthHandler, profileHandler *handlers.ProfileHandler, jwtSecret string) *chi.Mux {
	r := chi.NewRouter()

	r.Post("/api/register", authHandler.Register)
	r.Post("/api/login", authHandler.Login)

	r.Group(func(r chi.Router) {
		r.Use(middleware.JWTAuth(jwtSecret))
		r.Get("/api/profile", profileHandler.GetProfile)
	})

	return r
}
