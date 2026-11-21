// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// Request data written to a strings.Builder.
package main

import (
	"database/sql"
	"net/http"
	"strings"
)

var buildersDB *sql.DB

func buildersHandler(w http.ResponseWriter, r *http.Request) {
	var query strings.Builder
	query.WriteString("SELECT * FROM users WHERE name = '")
	query.WriteString(r.FormValue("name"))
	query.WriteString("'")
	// ruleid: secreview.go.taint-sql
	buildersDB.Query(query.String())
}
