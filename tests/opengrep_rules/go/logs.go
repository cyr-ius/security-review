// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// Request data written to the standard log.
package main

import (
	"log"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
)

func loginHandler(w http.ResponseWriter, r *http.Request) {
	user := r.FormValue("user")
	// ruleid: secreview.go.taint-log-injection
	log.Printf("failed login for %s", user)
	// ok: secreview.go.taint-log-injection
	log.Printf("failed login for %q", user)
	// ok: secreview.go.taint-log-injection
	log.Println("failed login for", strconv.Quote(user))
	// ok: secreview.go.taint-log-injection
	log.Println("failed login for", strings.ReplaceAll(user, "\n", ""))
	// ok: secreview.go.taint-log-injection
	slog.Warn("failed login", "user", user)
}
