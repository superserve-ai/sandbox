package vmdclient

import (
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Only refusals produced before admission are safe to place elsewhere. A plain
// transport failure or ResourceExhausted may have happened after a guest booted.
func AdmissionRefused(code codes.Code, message string) error {
	s := status.New(code, message)
	detailed, err := s.WithDetails(&errdetails.ErrorInfo{Reason: "HOST_ADMISSION_REFUSED", Domain: "superserve.vmd"})
	if err != nil {
		return s.Err()
	}
	return detailed.Err()
}
func IsAdmissionRefusal(err error) bool {
	s, ok := status.FromError(err)
	if !ok {
		return false
	}
	if s.Code() != codes.Unavailable && s.Code() != codes.ResourceExhausted {
		return false
	}
	for _, detail := range s.Details() {
		if info, ok := detail.(*errdetails.ErrorInfo); ok && info.Reason == "HOST_ADMISSION_REFUSED" && info.Domain == "superserve.vmd" {
			return true
		}
	}
	return false
}
