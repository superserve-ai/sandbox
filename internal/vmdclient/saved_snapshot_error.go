package vmdclient

import (
	"context"
	"errors"
	"strings"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// SavedSnapshotOperation identifies the trusted operation context used when a
// saved-snapshot error crosses an RPC or logging boundary. Keeping this as a
// closed set prevents a caller-controlled filesystem path from becoming the
// replacement error message.
type SavedSnapshotOperation uint8

const (
	SavedSnapshotOperationUnknown SavedSnapshotOperation = iota
	SavedSnapshotOperationHostResolution
	SavedSnapshotOperationCapabilityCheck
	SavedSnapshotOperationCapture
	SavedSnapshotOperationRestore
	SavedSnapshotOperationDelete
	SavedSnapshotOperationWritableLayerMeasurement
)

func (o SavedSnapshotOperation) message() string {
	switch o {
	case SavedSnapshotOperationHostResolution:
		return "saved snapshot host resolution failed"
	case SavedSnapshotOperationCapabilityCheck:
		return "saved snapshot capability check failed"
	case SavedSnapshotOperationCapture:
		return "saved snapshot capture failed"
	case SavedSnapshotOperationRestore:
		return "saved snapshot restore failed"
	case SavedSnapshotOperationDelete:
		return "saved snapshot artifact delete failed"
	case SavedSnapshotOperationWritableLayerMeasurement:
		return "sandbox writable-layer measurement failed"
	default:
		return "saved snapshot operation failed"
	}
}

// SanitizeSavedSnapshotError returns an error safe for RPC responses and
// structured logs. Host filesystem paths commonly enter errors through
// os.PathError, Firecracker, or system utilities, so the original description
// and ErrorInfo metadata are deliberately discarded. The gRPC code and safe
// machine-readable ErrorInfo reason/domain remain available for control-flow
// decisions such as source-resume containment.
func SanitizeSavedSnapshotError(operation SavedSnapshotOperation, err error) error {
	if err == nil {
		return nil
	}

	code := status.Code(err)
	switch {
	case errors.Is(err, context.Canceled):
		code = codes.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		code = codes.DeadlineExceeded
	}
	if code == codes.OK {
		code = codes.Unknown
	}

	sanitized := status.New(code, operation.message())
	for _, detail := range status.Convert(err).Details() {
		info, ok := detail.(*errdetails.ErrorInfo)
		if !ok || !safeErrorToken(info.GetReason(), 128) ||
			(info.GetDomain() != "" && !safeErrorToken(info.GetDomain(), 253)) {
			continue
		}
		withDetails, detailErr := sanitized.WithDetails(&errdetails.ErrorInfo{
			Reason: info.GetReason(),
			Domain: info.GetDomain(),
		})
		if detailErr == nil {
			sanitized = withDetails
		}
		break
	}
	return sanitized.Err()
}

func safeErrorToken(value string, maxLen int) bool {
	if value == "" || len(value) > maxLen || strings.ContainsAny(value, `/\\`) {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' {
			continue
		}
		return false
	}
	return true
}
