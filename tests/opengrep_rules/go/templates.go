// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
package main

import (
	"crypto/tls"
	"net/http"
	"text/template"
	"time"
)

func preview(w http.ResponseWriter, r *http.Request) {
	body := r.FormValue("template")
	// ruleid: secreview.go.taint-template-injection
	tmpl := template.Must(template.New("preview").Parse(body))
	// ok: secreview.go.taint-template-injection
	safe := template.Must(template.New("safe").Parse("Hello {{.}}"))
	tmpl.Execute(w, nil)
	safe.Execute(w, r.FormValue("name"))
}

func servers() (*tls.Config, *tls.Config) {
	// ruleid: secreview.go.tls-weak-version
	legacy := &tls.Config{MinVersion: tls.VersionTLS10}
	// ok: secreview.go.tls-weak-version
	modern := &tls.Config{MinVersion: tls.VersionTLS12}
	return legacy, modern
}

func fetch(url string) {
	// ruleid: secreview.go.http-client-without-timeout
	http.Get(url)
	// ok: secreview.go.http-client-without-timeout
	client := &http.Client{}
	// ok: secreview.go.http-client-without-timeout
	bounded := &http.Client{Timeout: 10 * time.Second}
	client.Get(url)
	bounded.Get(url)
}
