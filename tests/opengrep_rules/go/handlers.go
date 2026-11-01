// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
package main

import (
	"archive/zip"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"fmt"
	"html"
	"html/template"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var db *sql.DB

func users(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	// ruleid: secreview.go.taint-sql
	rows, _ := db.Query(fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name))
	// ok: secreview.go.taint-sql
	rows, _ = db.Query("SELECT * FROM users WHERE name = $1", name)
	id, _ := strconv.Atoi(r.FormValue("id"))
	// ok: secreview.go.taint-sql
	db.QueryRow(fmt.Sprintf("SELECT * FROM users WHERE id = %d", id))
	defer rows.Close()
}

func ping(w http.ResponseWriter, r *http.Request) {
	host := r.FormValue("host")
	// ruleid: secreview.go.taint-command
	exec.Command("sh", "-c", "ping -c 1 "+host).Run()
	// ok: secreview.go.taint-command
	exec.Command("ping", "-c", "1", host).Run()
}

func download(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("file")
	// ruleid: secreview.go.taint-path-traversal
	data, _ := os.ReadFile(filepath.Join("/srv/files", name))
	// ok: secreview.go.taint-path-traversal
	http.ServeFile(w, r, filepath.Join("/srv/files", filepath.Base(name)))
	w.Write(data)
}

func fetch(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	// ruleid: secreview.go.taint-ssrf
	resp, _ := http.Get(target)
	// ok: secreview.go.taint-ssrf
	http.Get("https://api.example.com/status")
	defer resp.Body.Close()
}

func login(w http.ResponseWriter, r *http.Request) {
	// ruleid: secreview.go.taint-open-redirect
	http.Redirect(w, r, r.FormValue("next"), http.StatusFound)
	// ok: secreview.go.taint-open-redirect
	http.Redirect(w, r, "/home", http.StatusFound)
}

func hello(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	// ruleid: secreview.go.taint-xss
	fmt.Fprintf(w, "<p>Hello %s</p>", name)
	// ok: secreview.go.taint-xss
	fmt.Fprintf(w, "<p>Hello %s</p>", html.EscapeString(name))
	// ruleid: secreview.go.taint-xss
	_ = template.HTML(name)
}

func client() *http.Client {
	// ruleid: secreview.go.tls-insecure-skip-verify
	insecure := &tls.Config{InsecureSkipVerify: true}
	// ok: secreview.go.tls-insecure-skip-verify
	strict := &tls.Config{MinVersion: tls.VersionTLS12}
	_ = strict
	return &http.Client{Transport: &http.Transport{TLSClientConfig: insecure}}
}

func unzip(archive *zip.Reader, dest string) {
	for _, file := range archive.File {
		// ruleid: secreview.go.zip-slip
		path := filepath.Join(dest, file.Name)
		os.MkdirAll(path, 0o750)
	}
}

func unzipSafe(archive *zip.Reader, dest string) {
	for _, file := range archive.File {
		// ok: secreview.go.zip-slip
		target := filepath.Join(dest, file.Name)
		if !strings.HasPrefix(target, filepath.Clean(dest)+string(os.PathSeparator)) {
			continue
		}
		os.MkdirAll(target, 0o750)
	}
}

func serve(handler http.Handler) {
	// ruleid: secreview.go.http-server-without-timeouts
	http.ListenAndServe(":8080", handler)
	// ok: secreview.go.http-server-without-timeouts
	server := &http.Server{Addr: ":8080", Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	server.ListenAndServe()
}

func digest(data []byte) {
	// ruleid: secreview.go.weak-crypto
	md5.Sum(data)
	// ok: secreview.go.weak-crypto
	sha256.Sum256(data)
}

func tokens() {
	// ruleid: secreview.go.math-rand-for-secret
	sessionToken := strconv.Itoa(rand.Int())
	// ok: secreview.go.math-rand-for-secret
	jitter := rand.Intn(100)
	_, _ = sessionToken, jitter
}
