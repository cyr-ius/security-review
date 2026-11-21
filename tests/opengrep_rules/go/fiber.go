// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// Request data read from a Fiber context.
package main

import (
	"database/sql"
	"os/exec"

	"github.com/gofiber/fiber/v2"
)

var fiberDB *sql.DB

func fiberUser(c *fiber.Ctx) error {
	// ruleid: secreview.go.taint-sql
	fiberDB.Query("SELECT * FROM users WHERE name = '" + c.Query("name") + "'")
	// ok: secreview.go.taint-sql
	fiberDB.Query("SELECT * FROM users WHERE name = $1", c.Query("name"))
	// ruleid: secreview.go.taint-command
	return exec.Command("sh", "-c", "ping "+c.Params("host")).Run()
}
