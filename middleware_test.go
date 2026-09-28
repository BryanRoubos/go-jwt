package main

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var (
	testSecret  = []byte("geheime-sleutel-voor-de-unit-tests-12345")
	wrongSecret = []byte("helemaal-verkeerde-sleutel-99999")
)

// AC1: Een geldig token geeft toegang (200 OK) en claims zijn beschikbaar
func TestValidToken(t *testing.T) {
	middleware := JWTMiddleware(testSecret)

	var usernameInHandler string
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := GetClaims(r)
		if ok && claims != nil {
			usernameInHandler = claims.Username
		}
		w.WriteHeader(http.StatusOK)
	})

	token, err := GenerateTestToken("bryan", testSecret, 10*time.Minute)
	if err != nil {
		t.Fatalf("fout bij genereren token: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/profile", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	middleware(testHandler).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Verwachtte status 200 OK, maar kreeg %d", rec.Code)
	}
	if usernameInHandler != "bryan" {
		t.Errorf("Verwachtte username 'bryan' in handler, maar kreeg '%s'", usernameInHandler)
	}
}

// AC2: Een gemanipuleerde payload wordt geweigerd met 401
func TestManipulatedPayload(t *testing.T) {
	middleware := JWTMiddleware(testSecret)

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	token, _ := GenerateTestToken("bryan", testSecret, 10*time.Minute)

	// We passen 1 letter aan in het payload-gedeelte van het token (tussen de twee punten)
	parts := strings.Split(token, ".")
	tamperedPayload := parts[1] + "a" // manipulatie
	tamperedToken := parts[0] + "." + tamperedPayload + "." + parts[2]

	req := httptest.NewRequest("GET", "/api/profile", nil)
	req.Header.Set("Authorization", "Bearer "+tamperedToken)
	rec := httptest.NewRecorder()

	middleware(testHandler).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Gemanipuleerd token moet 401 geven, maar kreeg %d", rec.Code)
	}
}

// AC3: Een token ondertekend met een ander geheim wordt geweigerd met 401
func TestWrongSecret(t *testing.T) {
	middleware := JWTMiddleware(testSecret)

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Token gemaakt met 'wrongSecret'
	token, _ := GenerateTestToken("bryan", wrongSecret, 10*time.Minute)

	req := httptest.NewRequest("GET", "/api/profile", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	middleware(testHandler).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Token met verkeerd geheim moet 401 geven, maar kreeg %d", rec.Code)
	}
}

// AC4: Een token met 'none' algoritme wordt geweigerd met 401
func TestAlgorithmNone(t *testing.T) {
	middleware := JWTMiddleware(testSecret)

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Handmatig een unsigned JWT maken met alg: "none"
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"username":"attacker","sub":"attacker","exp":9999999999}`))
	noneToken := header + "." + payload + "."

	req := httptest.NewRequest("GET", "/api/profile", nil)
	req.Header.Set("Authorization", "Bearer "+noneToken)
	rec := httptest.NewRecorder()

	middleware(testHandler).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Algoritme 'none' token moet 401 geven, maar kreeg %d", rec.Code)
	}
}

// AC5: Een verlopen token wordt geweigerd met 401
func TestExpiredToken(t *testing.T) {
	middleware := JWTMiddleware(testSecret)

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Token dat 10 minuten geleden al is verlopen
	expiredToken, _ := GenerateTestToken("bryan", testSecret, -10*time.Minute)

	req := httptest.NewRequest("GET", "/api/profile", nil)
	req.Header.Set("Authorization", "Bearer "+expiredToken)
	rec := httptest.NewRecorder()

	middleware(testHandler).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Verlopen token moet 401 geven, maar kreeg %d", rec.Code)
	}
}

// AC6: Ongeldige of ontbrekende Authorization-header wordt geweigerd met 401
func TestInvalidOrMissingHeader(t *testing.T) {
	middleware := JWTMiddleware(testSecret)

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	testCases := []struct {
		name   string
		header string
	}{
		{"Geen header", ""},
		{"Basic auth ipv Bearer", "Basic dXNlcjpwYXNz"},
		{"Alleen Bearer zonder token", "Bearer"},
		{"Ongeldige indeling", "Bearer a b c"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/profile", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			rec := httptest.NewRecorder()

			middleware(testHandler).ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Errorf("[%s] Verwachtte 401 Unauthorized, maar kreeg %d", tc.name, rec.Code)
			}
		})
	}
}

// AC7: Dezelfde middleware kan eenvoudig worden hergebruikt voor meerdere routes
func TestMultipleRoutes(t *testing.T) {
	middleware := JWTMiddleware(testSecret)

	mux := http.NewServeMux()
	mux.Handle("/api/profile", middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("profiel"))
	})))
	mux.Handle("/api/dashboard", middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("dashboard"))
	})))

	token, _ := GenerateTestToken("bryan", testSecret, 10*time.Minute)

	// Test route 1
	req1 := httptest.NewRequest("GET", "/api/profile", nil)
	req1.Header.Set("Authorization", "Bearer "+token)
	rec1 := httptest.NewRecorder()
	mux.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Errorf("Route /api/profile faalde met status %d", rec1.Code)
	}

	// Test route 2 met hetzelfde token en dezelfde middleware
	req2 := httptest.NewRequest("GET", "/api/dashboard", nil)
	req2.Header.Set("Authorization", "Bearer "+token)
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Errorf("Route /api/dashboard faalde met status %d", rec2.Code)
	}
}

// AC8: Geen security-details of interne stacktraces lekken naar de client
func TestNoSecurityDetailsLeaked(t *testing.T) {
	middleware := JWTMiddleware(testSecret)

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/api/profile", nil)
	req.Header.Set("Authorization", "Bearer ongeldig-token")
	rec := httptest.NewRecorder()

	middleware(testHandler).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Verwachtte 401, kreeg %d", rec.Code)
	}

	// Check dat de body geen interne library-foutmeldingen of stacktraces bevat
	body := strings.TrimSpace(rec.Body.String())
	if strings.Contains(body, "token is malformed") || strings.Contains(body, "signature is invalid") {
		t.Errorf("Body lekt interne foutmelding: %s", body)
	}
}

// Benchmark om de rekentijd van de validatie te meten (LT6 in PDF)
func BenchmarkJWTMiddleware(b *testing.B) {
	middleware := JWTMiddleware(testSecret)
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	protected := middleware(testHandler)

	token, _ := GenerateTestToken("bryan", testSecret, 10*time.Minute)
	req := httptest.NewRequest("GET", "/api/profile", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		protected.ServeHTTP(rec, req)
	}
}
