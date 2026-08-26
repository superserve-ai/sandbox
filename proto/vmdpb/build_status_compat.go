package vmdpb

import "google.golang.org/protobuf/encoding/protowire"

const (
	getBuildStatusRootfsAllocatedField  protowire.Number = 13
	getBuildStatusBaseAllocatedField    protowire.Number = 14
	getBuildStatusDeltaAllocatedField   protowire.Number = 15
	getBuildStatusAllocatedSupportField protowire.Number = 16
)

func (x *GetBuildStatusResponse) GetRootfsAllocatedBytes() int64 {
	return getBuildStatusResponseVarint(x, getBuildStatusRootfsAllocatedField)
}

func (x *GetBuildStatusResponse) GetBaseAllocatedBytes() int64 {
	return getBuildStatusResponseVarint(x, getBuildStatusBaseAllocatedField)
}

func (x *GetBuildStatusResponse) GetDeltaAllocatedBytes() int64 {
	return getBuildStatusResponseVarint(x, getBuildStatusDeltaAllocatedField)
}

func (x *GetBuildStatusResponse) GetAllocatedBytesSupported() bool {
	return getBuildStatusResponseVarint(x, getBuildStatusAllocatedSupportField) != 0
}

func (x *GetBuildStatusResponse) SetRootfsAllocatedBytes(value int64) {
	setBuildStatusResponseVarint(x, getBuildStatusRootfsAllocatedField, uint64(value))
}

func (x *GetBuildStatusResponse) SetBaseAllocatedBytes(value int64) {
	setBuildStatusResponseVarint(x, getBuildStatusBaseAllocatedField, uint64(value))
}

func (x *GetBuildStatusResponse) SetDeltaAllocatedBytes(value int64) {
	setBuildStatusResponseVarint(x, getBuildStatusDeltaAllocatedField, uint64(value))
}

func (x *GetBuildStatusResponse) SetAllocatedBytesSupported(value bool) {
	var encoded uint64
	if value {
		encoded = 1
	}
	setBuildStatusResponseVarint(x, getBuildStatusAllocatedSupportField, encoded)
}

func getBuildStatusResponseVarint(x *GetBuildStatusResponse, field protowire.Number) int64 {
	if x == nil {
		return 0
	}
	unknown := x.ProtoReflect().GetUnknown()
	for len(unknown) > 0 {
		num, typ, n := protowire.ConsumeTag(unknown)
		if n < 0 {
			break
		}
		unknown = unknown[n:]
		value, n := protowire.ConsumeVarint(unknown)
		if n < 0 {
			break
		}
		unknown = unknown[n:]
		if num == field && typ == protowire.VarintType {
			return int64(value)
		}
	}
	return 0
}

func setBuildStatusResponseVarint(x *GetBuildStatusResponse, field protowire.Number, value uint64) {
	if x == nil {
		return
	}
	unknown := x.ProtoReflect().GetUnknown()
	unknown = protowire.AppendTag(unknown, field, protowire.VarintType)
	unknown = protowire.AppendVarint(unknown, value)
	x.ProtoReflect().SetUnknown(unknown)
}
