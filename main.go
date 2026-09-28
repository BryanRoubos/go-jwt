package main

import (
	"fmt"
	"net/http"
	"os"
	"time"
)

func main() {
	// Secret ophalen uit de omgeving (KC5: nooit hardcoded in code)
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		secret = "mijn-super-geheime-sleutel-voor-de-api-12345" // fallback voor lokaal testen
	}
	secretBytes := []byte(secret)

	// Maak onze middleware
	requireAuth := JWTMiddleware(secretBytes)

	// Router maken
	mux := http.NewServeMux()

	// 1. Openbare route: login (geeft een token)
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		token, err := GenerateTestToken("bryan", secretBytes, 15*time.Minute)
		if err != nil {
			http.Error(w, "Kon token niet genereren", http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, `{"token": "%s"}`, token)
	})

	// 2. Beveiligde route 1: Profiel
	mux.Handle("/api/profile", requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, _ := GetClaims(r)
		fmt.Fprintf(w, "Welkom op je profiel, %s!", claims.Username)
	})))

	// 3. Beveiligde route 2: Dashboard (bewijst herbruikbaarheid)
	mux.Handle("/api/dashboard", requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, _ := GetClaims(r)
		fmt.Fprintf(w, "Dashboard data voor gebruiker: %s", claims.Username)
	})))

	fmt.Println("Server draait op http://localhost:8080")
	_ = http.ListenAndServe(":8080", mux)
}
