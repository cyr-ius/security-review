// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
)

func verify(body, signature, key []byte, token, expectedToken string) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	expected := mac.Sum(nil)
	// ruleid: secreview.go.non-constant-time-compare
	if !bytes.Equal(signature, mac.Sum(nil)) {
		return false
	}
	// ruleid: secreview.go.non-constant-time-compare
	if token != expectedToken {
		return false
	}
	// ok: secreview.go.non-constant-time-compare
	if token == "" {
		return false
	}
	// ok: secreview.go.non-constant-time-compare
	return hmac.Equal(signature, expected)
}
