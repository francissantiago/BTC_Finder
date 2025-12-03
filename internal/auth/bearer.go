package auth

import (
	"net/http"
	"strings"
)

// BearerTokenValidator validates bearer tokens in HTTP requests
type BearerTokenValidator struct {
	token string
}

// NewBearerTokenValidator creates a new validator with a token
func NewBearerTokenValidator(token string) *BearerTokenValidator {
	return &BearerTokenValidator{
		token: token,
	}
}

// Middleware is an HTTP middleware that validates bearer token in Authorization header
func (v *BearerTokenValidator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "missing Authorization header", http.StatusUnauthorized)
			return
		}

		// Expected format: "Bearer <token>"
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, "invalid Authorization header format", http.StatusUnauthorized)
			return
		}

		token := parts[1]
		if token != v.token {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// ValidateToken checks if a token is valid
func (v *BearerTokenValidator) ValidateToken(token string) bool {
	return token == v.token
}

// ValidateAuthHeader validates the full Authorization header
func (v *BearerTokenValidator) ValidateAuthHeader(authHeader string) bool {
	if authHeader == "" {
		return false
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return false
	}

	return parts[1] == v.token
}
