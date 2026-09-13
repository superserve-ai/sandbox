package vmdclient

import "context"

type HostAdmissionState struct {
	PendingBoots int64 `json:"pending_boots"`
	Revision     int64 `json:"revision"`
	Closed       bool  `json:"closed"`
	Ready        bool  `json:"ready"`
	Charged      int64 `json:"charged"`
}

// Optional for older daemons; operators must fail closed without this contract.
type HostAdmissionClient interface {
	HostAdmission(context.Context, int64, bool) (HostAdmissionState, error)
}
