// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// LDAP filters and MongoDB queries built from request data.
package main

import (
	"net/http"

	"github.com/go-ldap/ldap/v3"
	"go.mongodb.org/mongo-driver/bson"
)

func directoryHandler(w http.ResponseWriter, r *http.Request) {
	user := r.FormValue("user")
	// ruleid: secreview.go.taint-ldap-injection
	ldap.NewSearchRequest("dc=example,dc=com", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, "(uid="+user+")", nil, nil)
	// ok: secreview.go.taint-ldap-injection
	ldap.NewSearchRequest("dc=example,dc=com", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, "(uid="+ldap.EscapeFilter(user)+")", nil, nil)

	// ruleid: secreview.go.taint-nosql-injection
	where := bson.M{"$where": "this.owner == '" + user + "'"}
	// ok: secreview.go.taint-nosql-injection
	filter := bson.M{"owner": user}
	_, _ = where, filter
}
