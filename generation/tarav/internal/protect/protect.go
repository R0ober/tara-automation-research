// Package protect derives an edge's protection level from the flags stated
// in an item definition (plan §6, SPEC D11–D13).
//
// Derivation is strict: a flag that is not stated is unknown, never false.
// An edge is only "none" when encryption, MAC and CRC are all stated false.
package protect

import "strings"

// Level is a protection level, strongest first.
type Level string

const (
	Encrypted    Level = "encrypted"
	MACFreshness Level = "mac_freshness"
	MAC          Level = "mac"
	CRC          Level = "crc"
	None         Level = "none"
	Unknown      Level = "unknown"
)

// Flag names one input to the derivation.
type Flag string

const (
	FlagEncrypted Flag = "encrypted"
	FlagCRC       Flag = "e2e_crc"
	FlagMAC       Flag = "mac"
	FlagFreshness Flag = "freshness"
)

// Value is one flag as found in the input. Set is false when nothing states
// it. Pointer is the RFC 6901 pointer of the stating field; Source says in
// words where it came from ("connection", "COMP-X security_configuration.k,
// receiver").
type Value struct {
	Set     bool   `json:"set"`
	On      bool   `json:"on"`
	Pointer string `json:"json_path,omitempty"`
	Source  string `json:"source,omitempty"`
}

func (v Value) on() bool  { return v.Set && v.On }
func (v Value) off() bool { return v.Set && !v.On }

// Flags is the gathered input for one edge.
type Flags struct {
	Encrypted Value `json:"encrypted"`
	CRC       Value `json:"e2e_crc"`
	MAC       Value `json:"mac"`
	Freshness Value `json:"freshness"`
}

func (f Flags) get(n Flag) Value {
	switch n {
	case FlagEncrypted:
		return f.Encrypted
	case FlagCRC:
		return f.CRC
	case FlagMAC:
		return f.MAC
	default:
		return f.Freshness
	}
}

// Result is a derived level. Missing lists the unstated flags that could
// raise the level if they were known (empty when the level is final).
type Result struct {
	Level     Level  `json:"level"`
	Missing   []Flag `json:"missing,omitempty"`
	Rationale string `json:"rationale"`
}

// Derive applies plan §6 (first match wins) with D12's strict reading.
func Derive(f Flags) Result {
	var lvl Level
	var could []Flag // flags whose value could raise lvl
	switch {
	case f.Encrypted.on():
		lvl = Encrypted
	case f.MAC.on() && f.Freshness.on():
		lvl, could = MACFreshness, []Flag{FlagEncrypted}
	case f.MAC.on():
		lvl, could = MAC, []Flag{FlagEncrypted, FlagFreshness}
	case f.CRC.on():
		lvl, could = CRC, []Flag{FlagEncrypted, FlagMAC}
	case f.Encrypted.off() && f.MAC.off() && f.CRC.off():
		lvl = None
	default:
		lvl, could = Unknown, []Flag{FlagEncrypted, FlagMAC, FlagCRC}
	}
	r := Result{Level: lvl}
	for _, n := range could {
		if !f.get(n).Set {
			r.Missing = append(r.Missing, n)
		}
	}
	r.Rationale = rationale(f)
	return r
}

// rationale lists every flag with its value and source, in a fixed order.
func rationale(f Flags) string {
	parts := make([]string, 0, 4)
	for _, n := range []Flag{FlagEncrypted, FlagMAC, FlagFreshness, FlagCRC} {
		v := f.get(n)
		switch {
		case !v.Set:
			parts = append(parts, string(n)+" not stated")
		case v.On:
			parts = append(parts, string(n)+" true ("+v.Source+")")
		default:
			parts = append(parts, string(n)+" false ("+v.Source+")")
		}
	}
	return strings.Join(parts, "; ")
}
