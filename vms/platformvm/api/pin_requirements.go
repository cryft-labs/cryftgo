// filepath: c:\Users\CryftCrest\Documents\cryftgo\vms\platformvm\api\pin_requirements.go
package api

import (
	"net/http"
)

type PinRequirement struct {
	CID       string `json:"cid"`
	FromEpoch uint64 `json:"fromEpoch"`
	ToEpoch   uint64 `json:"toEpoch"`
}

type GetPinRequirementsArgs struct {
	// Optional epoch filter; kept for API compatibility.
	Epoch *uint64 `json:"epoch,omitempty"`
}

type GetPinRequirementsReply struct {
	Requirements []PinRequirement `json:"requirements"`
}

// ActiveRequiredDirs is now unused but kept for compatibility; callers that
// still import it will see consistent behavior.
//
// A dir is active if FromEpoch <= epoch and (ToEpoch == 0 || epoch <= ToEpoch).
func ActiveRequiredDirs(all []PinRequirement, epoch uint64) []PinRequirement {
	out := make([]PinRequirement, 0, len(all))
	for _, d := range all {
		if d.FromEpoch <= epoch && (d.ToEpoch == 0 || epoch <= d.ToEpoch) {
			out = append(out, d)
		}
	}
	return out
}

// GetPinRequirements no longer uses genesis_pins.json.
// It always returns an empty list, regardless of args.
func (s *StaticService) GetPinRequirements(
	_ *http.Request,
	_ *GetPinRequirementsArgs,
	reply *GetPinRequirementsReply,
) error {
	reply.Requirements = nil
	return nil
}
