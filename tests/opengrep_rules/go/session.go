// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
package main

import (
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

func login(w http.ResponseWriter, r *http.Request, value string) {
	// ruleid: secreview.go.cookie-insecure
	http.SetCookie(w, &http.Cookie{Name: "session", Value: value, Path: "/"})
	// ruleid: secreview.go.cookie-insecure
	http.SetCookie(w, &http.Cookie{Name: "theme", Value: "dark", HttpOnly: false})
	// ok: secreview.go.cookie-insecure
	http.SetCookie(w, &http.Cookie{Name: "session", Value: value, Secure: true, HttpOnly: true})
	// ok: secreview.go.cookie-insecure
	http.SetCookie(w, &http.Cookie{Name: "theme", Value: "dark"})
}

func claims(raw string, key []byte) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	parser := jwt.NewParser()
	// ruleid: secreview.go.jwt-signature-not-verified
	_, _, err := parser.ParseUnverified(raw, claims)
	// ok: secreview.go.jwt-signature-not-verified
	_, err = jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) { return key, nil },
		jwt.WithValidMethods([]string{"HS256"}))
	return claims, err
}

func legacy(raw string) {
	// ruleid: secreview.go.jwt-signature-not-verified
	jwt.Parse(raw, func(t *jwt.Token) (any, error) { return jwt.UnsafeAllowNoneSignatureType, nil })
}
