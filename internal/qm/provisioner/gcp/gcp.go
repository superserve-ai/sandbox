// Package gcp holds the real implementations of the provisioner's step
// clients. Each type satisfies one interface declared in the steps package
// and does nothing else: the decisions about ordering, idempotence and what
// a tenant is made of live in the steps, and the code here is only the
// mapping onto Google's APIs.
//
// Two rules run through all of it. Every call is idempotent — "already
// exists" is success on the way up and "already gone" is success on the way
// down — and every error says what was being attempted, because the
// runner's event log is what an operator debugging a stuck tenant reads.
package gcp

import (
	"errors"
	"net/http"

	"google.golang.org/api/googleapi"
)

// isStatus reports whether err is a Google API error with this HTTP status.
func isStatus(err error, code int) bool {
	var gerr *googleapi.Error
	return errors.As(err, &gerr) && gerr.Code == code
}

// alreadyExists is the create-side "this is fine".
func alreadyExists(err error) bool { return isStatus(err, http.StatusConflict) }

// notFound is the delete-side "this is fine".
func notFound(err error) bool { return isStatus(err, http.StatusNotFound) }
