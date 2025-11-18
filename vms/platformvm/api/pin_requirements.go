// filepath: c:\Users\CryftCrest\Documents\cryftgo\vms\platformvm\api\pin_requirements.go
package api

import (
    "encoding/json"
    "fmt"
    "net/http"
    "os"
    "path/filepath"

    "github.com/cryft-labs/cryftgo/utils/constants"
)

type PinRequirement struct {
    CID       string `json:"cid"`
    FromEpoch uint64 `json:"fromEpoch"`
    ToEpoch   uint64 `json:"toEpoch"`
}

type GetPinRequirementsArgs struct {
    // Optional epoch filter; if omitted, returns all pin requirements.
    Epoch *uint64 `json:"epoch,omitempty"`
}

type GetPinRequirementsReply struct {
    Requirements []PinRequirement `json:"requirements"`
}

type genesisPinsFile struct {
    RequiredDirs []PinRequirement `json:"requiredDirs"`
}

// ActiveRequiredDirs mirrors the epoch activation logic used by Cryftee.
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

// loadGenesisPinRequirements reads genesis/genesis_pins.json relative to the
// repo/binary working directory. This is intentionally simple and may be
// replaced by on-chain pin governance in the future.
func loadGenesisPinRequirements() ([]PinRequirement, error) {
    p := filepath.Join(constants.GenesisDir, "genesis_pins.json")
    b, err := os.ReadFile(p)
    if err != nil {
        return nil, fmt.Errorf("failed to read genesis_pins.json: %w", err)
    }

    var wrapper genesisPinsFile
    if err := json.Unmarshal(b, &wrapper); err != nil {
        return nil, fmt.Errorf("failed to unmarshal genesis_pins.json: %w", err)
    }
    return wrapper.RequiredDirs, nil
}

// GetPinRequirements returns static IPFS pin requirements derived from
// genesis/genesis_pins.json.
func (ss *StaticService) GetPinRequirements(_ *http.Request, args *GetPinRequirementsArgs, reply *GetPinRequirementsReply) error {
    all, err := loadGenesisPinRequirements()
    if err != nil {
        return err
    }

    if args != nil && args.Epoch != nil {
        reply.Requirements = ActiveRequiredDirs(all, *args.Epoch)
        return nil
    }

    reply.Requirements = all
    return nil
}