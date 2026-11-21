// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// Request data naming a module, a class or a method reached by reflection.
package main

import (
	"net/http"
	"reflect"
)

type Actions struct{}

func (Actions) Export() {}

func action(w http.ResponseWriter, r *http.Request) {
	// ruleid: secreview.go.taint-unsafe-reflection
	reflect.ValueOf(Actions{}).MethodByName(r.FormValue("action")).Call(nil)
	// ok: secreview.go.taint-unsafe-reflection
	reflect.ValueOf(Actions{}).MethodByName("Export").Call(nil)
}
