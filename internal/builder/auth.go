package builder

import (
	"github.com/google/go-containerregistry/pkg/authn"
)

// keychain is the default credential source for OCI registries. V1 resolves
// credentials in this order:
//
//  1. ~/.docker/config.json on the builder host (for operators pre-logging in)
//  2. Anonymous — works for public Docker Hub images, which covers most V1 use
//
// Private registry support (per-template credentials) is V2. When a user needs
// ghcr.io/private/image or a corporate registry, they'll supply an auth token
// as part of the build request; we'll plumb that in then.
var keychain = authn.DefaultKeychain
