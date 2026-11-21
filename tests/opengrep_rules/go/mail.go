// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// Password reset links built from the Host header.
package main

import (
	"net/http"
	"net/smtp"
	"os"
)

func resetHandler(w http.ResponseWriter, r *http.Request) {
	token := newToken()
	link := "https://" + r.Host + "/reset?token=" + token
	// ruleid: secreview.go.taint-host-header
	smtp.SendMail("localhost:25", nil, "noreply@example.com", []string{r.FormValue("email")}, []byte("Subject: Reset\r\n\r\nOpen "+link))
	// ok: secreview.go.taint-host-header
	smtp.SendMail("localhost:25", nil, "noreply@example.com", []string{r.FormValue("email")}, []byte("Subject: Reset\r\n\r\nOpen "+os.Getenv("BASE_URL")+"/reset?token="+token))
}
