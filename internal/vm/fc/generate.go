package fc

// firecracker.yaml is a verbatim copy of the spec this repo builds against;
// client/ and models/ are generated from it — regenerate, don't hand-edit.
// The generator is pinned because its output is not stable across versions:
// v0.33.1 is the newest whose output compiles against the go-openapi/runtime
// in go.mod.
//
//go:generate go run github.com/go-swagger/go-swagger/cmd/swagger@v0.33.1 generate client -f firecracker.yaml -A firecracker
