package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Geheime context key om botsingen te voorkomen
type contextKey string

const UserClaimsKey contextKey = "userClaims"

// CustomClaims bevat de gegevens die we in het token opslaan.
// We gebruiken RegisteredClaims van de library voor exp, iss, sub, etc.
type CustomClaims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// JWTMiddleware maakt een middleware functie die routes beveiligt met een secret.
func JWTMiddleware(secret []byte) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 1. Haal de Authorization header op
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, `{"error": "Unauthorized"}`, http.StatusUnauthorized)
				return
			}

			// 2. Controleer of de header begint met 'Bearer '
			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || parts[0] != "Bearer" {
				http.Error(w, `{"error": "Unauthorized"}`, http.StatusUnauthorized)
				return
			}
			tokenString := parts[1]

			// 3. Valideer en parse het token
			claims := &CustomClaims{}
			token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
				// VEILIGHEIDSCHECK: Controleer expliciet het algoritme!
				// Dit voorkomt de 'none' aanval en algorithm confusion.
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("onverwacht algoritme: %v", token.Header["alg"])
				}
				return secret, nil
			})

			// 4. Als het parsen mislukt of het token ongeldig is (bijv. verlopen of gemanipuleerd)
			if err != nil || !token.Valid {
				// Geef altijd een simpele 401 terug zonder gevoelige security details (AC8)
				http.Error(w, `{"error": "Unauthorized"}`, http.StatusUnauthorized)
				return
			}

			// 5. Token is geldig! Sla de claims op in de request context zodat de volgende handler erbij kan
			ctx := context.WithValue(r.Context(), UserClaimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Helper functie om makkelijk de claims uit de context te halen in een route handler
func GetClaims(r *http.Request) (*CustomClaims, bool) {
	claims, ok := r.Context().Value(UserClaimsKey).(*CustomClaims)
	return claims, ok
}

// Helper functie om snel een geldig token aan te maken (handig voor tests en login)
func GenerateTestToken(username string, secret []byte, duration time.Duration) (string, error) {
	claims := CustomClaims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   username,
			Issuer:    "mijn-schoolproject-api",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(duration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secret)
}
