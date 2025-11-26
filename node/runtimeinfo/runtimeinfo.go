package runtimeinfo

import "time"

// Info is a minimal placeholder type for data returned by the Cryftee sidecar.
//
// This is intentionally small and can be extended later to mirror the true
// /runtime/self JSON schema once Cryftee is finalized.
type Info struct {
	// When this runtime info was generated.
	Timestamp time.Time `json:"timestamp"`

	// Whether the runtime sidecar reports that all required pins are present.
	AllRuntimePinsPresent bool `json:"allRuntimePinsPresent"`

	// Free-form capabilities advertised by the runtime (e.g. "PIN_PROVIDER").
	Capabilities []string `json:"capabilities,omitempty"`
}

// PinSummary provides a minimal view over runtime pin state.
// This matches the usage in api/info/service.go.
type PinSummary struct {
	Pinned  int `json:"pinned"`
	Missing int `json:"missing"`
}

// RuntimeInfo is the minimal shape expected by Info.GetRuntimeInfo.
// This can be extended later to mirror Cryftee's /runtime/self JSON.
type RuntimeInfo struct {
	Healthy    bool       `json:"healthy"`
	Epoch      uint64     `json:"epoch"`
	PinSummary PinSummary `json:"pinSummary"`
}
