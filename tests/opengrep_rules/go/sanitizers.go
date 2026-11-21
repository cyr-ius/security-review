// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// Request data made safe for its sink.
package main

import (
	"database/sql"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"

	"al.essio.dev/pkg/shellescape"
	"github.com/lib/pq"
)

var sanitizedDB *sql.DB

func sanitizedHandler(w http.ResponseWriter, r *http.Request) {
	// ok: secreview.go.taint-ssrf
	http.Get("https://api.example.com/users/" + url.PathEscape(r.FormValue("user")))
	// ok: secreview.go.taint-sql
	sanitizedDB.Query("SELECT * FROM users ORDER BY " + pq.QuoteIdentifier(r.FormValue("sort")))
	// ok: secreview.go.taint-command
	exec.Command("sh", "-c", "ls "+shellescape.Quote(r.FormValue("dir"))).Run()
	// ok: secreview.go.taint-path-traversal
	os.ReadFile(filepath.Join("/srv/files", filepath.Clean("/"+r.FormValue("name"))))
}
