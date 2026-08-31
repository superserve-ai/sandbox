package vmdpb

import "google.golang.org/protobuf/encoding/protowire"

// resumeGenerationField and resumeFcSha256Field carry ResumeVMRequest's
// fetch-before-resume fields (see proto/vmd.proto) through the unknown
// field set instead of the generated struct — the same compatibility
// shim build_status_compat.go uses for GetBuildStatusResponse's
// allocation fields, needed here because vmd.pb.go already lags
// vmd.proto by several other messages' fields and a full regeneration
// would fold in unrelated, still-in-flight changes.
const (
	resumeGenerationField protowire.Number = 7
	resumeFcSha256Field   protowire.Number = 8
)

// GetGeneration returns the backup generation the caller wants
// fetch-before-resume to restore from, or "" if unset.
func (x *ResumeVMRequest) GetGeneration() string {
	return resumeRequestString(x, resumeGenerationField)
}

// SetGeneration sets the backup generation field.
func (x *ResumeVMRequest) SetGeneration(value string) {
	setResumeRequestString(x, resumeGenerationField, value)
}

// GetFcSha256 returns the Firecracker build digest the generation was
// captured under, or "" if unset — no attestation source populates this
// yet, so "" is the normal case, not an error.
func (x *ResumeVMRequest) GetFcSha256() string {
	return resumeRequestString(x, resumeFcSha256Field)
}

// SetFcSha256 sets the fc_sha256 field.
func (x *ResumeVMRequest) SetFcSha256(value string) {
	setResumeRequestString(x, resumeFcSha256Field, value)
}

func resumeRequestString(x *ResumeVMRequest, field protowire.Number) string {
	if x == nil {
		return ""
	}
	unknown := x.ProtoReflect().GetUnknown()
	for len(unknown) > 0 {
		num, typ, n := protowire.ConsumeTag(unknown)
		if n < 0 {
			break
		}
		unknown = unknown[n:]
		value, n := protowire.ConsumeBytes(unknown)
		if n < 0 {
			break
		}
		unknown = unknown[n:]
		if num == field && typ == protowire.BytesType {
			return string(value)
		}
	}
	return ""
}

// setResumeRequestString appends the field's wire bytes to the unknown
// set. Callers set each field at most once per request (built fresh
// per RPC), so the possible-duplicate-entry ambiguity a repeated Set
// would create — protowire's linear scan returns the first match —
// never arises in practice.
func setResumeRequestString(x *ResumeVMRequest, field protowire.Number, value string) {
	if x == nil || value == "" {
		return
	}
	unknown := x.ProtoReflect().GetUnknown()
	unknown = protowire.AppendTag(unknown, field, protowire.BytesType)
	unknown = protowire.AppendString(unknown, value)
	x.ProtoReflect().SetUnknown(unknown)
}
