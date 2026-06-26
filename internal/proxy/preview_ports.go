package proxy

import "context"

// PreviewPortAuthorizer decides whether a request may proxy to a user app
// port on a sandbox instance.
type PreviewPortAuthorizer interface {
	Allowed(ctx context.Context, sandboxID string, port int, info InstanceInfo) (bool, error)
}

type allowAllPreviewPortAuthorizer struct{}

func (allowAllPreviewPortAuthorizer) Allowed(context.Context, string, int, InstanceInfo) (bool, error) {
	return true, nil
}
