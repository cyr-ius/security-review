// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// Request data passed as an argument of a program (option injection).
package main

import (
	"net/http"
	"os/exec"
)

func mirror(w http.ResponseWriter, r *http.Request) {
	url := r.FormValue("url")
	// ruleid: secreview.go.taint-argument-injection
	exec.Command("git", "clone", url, "/srv/mirror").Run()
	// ruleid: secreview.go.taint-argument-injection
	exec.CommandContext(r.Context(), "ssh", url, "uptime").Run()
	// ok: secreview.go.taint-argument-injection
	exec.Command("git", "clone", "--", url, "/srv/mirror").Run()
	// ok: secreview.go.taint-argument-injection
	exec.Command("git", "clone", "--branch="+url, "https://example.com/repo").Run()
	// ok: secreview.go.taint-argument-injection
	exec.Command("/opt/tools/report", url).Run()
}
