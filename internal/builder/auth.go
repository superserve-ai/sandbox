package builder

import (
	"github.com/google/go-containerregistry/pkg/authn"
)

// keychain is the default credential source for OCI registries.
// Resolves in order: ~/.docker/config.json on the builder host, then
// anonymous (public images).
var keychain = authn.DefaultKeychain
