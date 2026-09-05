package vmdpb

import (
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

func TestResumeVMRequestGenerationRoundTrip(t *testing.T) {
	req := &ResumeVMRequest{VmId: "vm-1", SnapshotPath: "/snap/vmstate.snap"}
	req.SetGeneration("gen-abc123")
	req.SetFcSha256("deadbeef")

	if got := req.GetGeneration(); got != "gen-abc123" {
		t.Fatalf("GetGeneration() = %q, want %q", got, "gen-abc123")
	}
	if got := req.GetFcSha256(); got != "deadbeef" {
		t.Fatalf("GetFcSha256() = %q, want %q", got, "deadbeef")
	}

	// The whole point of riding unknown fields: values must survive an
	// actual wire marshal/unmarshal, not just live on the in-memory struct
	// — this is what proves a gRPC round trip between two vmdpb-linked
	// binaries actually carries them.
	wire, err := proto.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	var decoded ResumeVMRequest
	if err := proto.Unmarshal(wire, &decoded); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if got := decoded.GetVmId(); got != "vm-1" {
		t.Errorf("decoded VmId = %q, want %q", got, "vm-1")
	}
	if got := decoded.GetGeneration(); got != "gen-abc123" {
		t.Errorf("decoded GetGeneration() = %q, want %q", got, "gen-abc123")
	}
	if got := decoded.GetFcSha256(); got != "deadbeef" {
		t.Errorf("decoded GetFcSha256() = %q, want %q", got, "deadbeef")
	}
}

func TestResumeVMRequestGenerationUnsetIsEmpty(t *testing.T) {
	req := &ResumeVMRequest{VmId: "vm-1"}
	if got := req.GetGeneration(); got != "" {
		t.Errorf("GetGeneration() on an unset request = %q, want \"\"", got)
	}
	if got := req.GetFcSha256(); got != "" {
		t.Errorf("GetFcSha256() on an unset request = %q, want \"\"", got)
	}
}

func TestResumeVMRequestGenerationNilSafe(t *testing.T) {
	var req *ResumeVMRequest
	if got := req.GetGeneration(); got != "" {
		t.Errorf("GetGeneration() on nil = %q, want \"\"", got)
	}
	// Must not panic.
	req.SetGeneration("ignored")
}

func TestResumeVMRequestSetGenerationEmptyIsNoop(t *testing.T) {
	req := &ResumeVMRequest{VmId: "vm-1"}
	req.SetGeneration("")
	if len(req.ProtoReflect().GetUnknown()) != 0 {
		t.Errorf("SetGeneration(\"\") wrote unknown field bytes, want none")
	}
}

// A non-length-delimited unknown field ahead of ours in the wire (varint
// field 9, mirroring how ArtifactManifestEntry.AllocatedBytes rides
// unknown bytes elsewhere in this package) must not desync the scan: the
// old implementation assumed every unknown field was length-delimited and
// would either read garbage or miss field 7 entirely once one appeared.
func TestResumeVMRequestGenerationSkipsNonBytesUnknownField(t *testing.T) {
	req := &ResumeVMRequest{VmId: "vm-1"}
	unknown := req.ProtoReflect().GetUnknown()
	unknown = protowire.AppendTag(unknown, 9, protowire.VarintType)
	unknown = protowire.AppendVarint(unknown, 123456)
	req.ProtoReflect().SetUnknown(unknown)
	req.SetGeneration("gen-after-varint")

	if got := req.GetGeneration(); got != "gen-after-varint" {
		t.Fatalf("GetGeneration() = %q, want %q (varint unknown field ahead of it desynced the scan)", got, "gen-after-varint")
	}

	wire, err := proto.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	var decoded ResumeVMRequest
	if err := proto.Unmarshal(wire, &decoded); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if got := decoded.GetGeneration(); got != "gen-after-varint" {
		t.Errorf("decoded GetGeneration() = %q, want %q", got, "gen-after-varint")
	}
}
