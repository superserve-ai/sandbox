package vmdwaker

import "github.com/superserve-ai/sandbox/internal/vmdclient"

// Compile-time guarantee that the real vmd gRPC client is a SandboxBooter, so
// the production wiring is `vmdwaker.New(vmdClient, boxdDeliverer, resolver)`
// with no adapter. (boxd event delivery is the Deliverer, supplied by the
// control plane.)
var _ SandboxBooter = (vmdclient.Client)(nil)
