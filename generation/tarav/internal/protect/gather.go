package protect

import (
	"fmt"

	"tarav/internal/model"
)

// KeyTable maps each flag to the exact, unprefixed security_configuration
// keys that state it (SPEC D11). Keys are tried in this order. Prefixed,
// message-scoped keys are deliberately absent: their prefixes do not match
// message names, so matching them would be a guess.
var KeyTable = map[Flag][]string{
	FlagCRC:       {"e2e_crc_enabled"},
	FlagMAC:       {"secoc_mac_enabled", "secoc_mac_verification", "secoc_mac_verification_enabled", "command_authentication_mac"},
	FlagFreshness: {"secoc_freshness_counter_enabled", "secoc_freshness_counter_verification_enabled"},
}

// ForConnection gathers the flags for connections[i].
func ForConnection(it *model.Item, i int) Flags {
	c := &it.Connections[i]
	base := model.Pointer("connections", i)
	f := Flags{Encrypted: boolValue(c.Encrypted, base+"/encrypted", "connection")}
	explicit(&f, c.Protection, base+"/protection", "connection protection")
	fromKeys(&f, it, c.TargetComponent, c.SourceComponent)
	return f
}

// ForMessage gathers the flags for connections[i].messages[j] (D13): the
// message's own protection, then the connection's, then the key table for
// the message's endpoints (falling back to the connection's). Encryption is
// the connection's.
func ForMessage(it *model.Item, i, j int) Flags {
	c := &it.Connections[i]
	m := &c.Messages[j]
	base := model.Pointer("connections", i)
	f := Flags{Encrypted: boolValue(c.Encrypted, base+"/encrypted", "connection")}
	explicit(&f, m.Protection, model.Pointer("connections", i, "messages", j, "protection"), "message "+m.CANID+" protection")
	explicit(&f, c.Protection, base+"/protection", "connection protection")
	fromKeys(&f, it, or(m.TargetComponent, c.TargetComponent), or(m.SourceComponent, c.SourceComponent))
	return f
}

// ForEntry gathers the flags for the edge from connections[i].entry_points[j]
// into the item: the entry point's own encrypted flag when stated, else the
// connection's; the rest as for the connection.
func ForEntry(it *model.Item, i, j int) Flags {
	f := ForConnection(it, i)
	if ep := it.Connections[i].EntryPoints[j]; ep.Encrypted != nil {
		f.Encrypted = boolValue(ep.Encrypted, model.Pointer("connections", i, "entry_points", j, "encrypted"), "entry point")
	}
	return f
}

func explicit(f *Flags, p *model.Protection, base, source string) {
	if p == nil {
		return
	}
	fill := func(dst *Value, b *bool, key string) {
		if !dst.Set {
			*dst = boolValue(b, base+"/"+key, source)
		}
	}
	fill(&f.CRC, p.E2ECRC, "e2e_crc")
	fill(&f.MAC, p.MAC, "mac")
	fill(&f.Freshness, p.Freshness, "freshness")
}

// fromKeys fills flags still unset from the key table, receiver first
// (plan §6: receiver-side verification wins), then sender.
func fromKeys(f *Flags, it *model.Item, receiver, sender string) {
	for _, side := range []struct{ id, role string }{{receiver, "receiver"}, {sender, "sender"}} {
		k, comp := component(it, side.id)
		if comp == nil {
			continue
		}
		for _, n := range []Flag{FlagCRC, FlagMAC, FlagFreshness} {
			dst := f.ptr(n)
			if dst.Set {
				continue
			}
			*dst = lookup(comp, k, KeyTable[n], side.role)
		}
	}
}

// lookup finds the first table key stated as a boolean on the component's
// own security_configuration, then on each hosted software's, in order.
func lookup(c *model.Component, k int, keys []string, role string) Value {
	type cfg struct {
		bag     model.Config
		pointer string
		label   string
	}
	cfgs := []cfg{{c.SecurityConfiguration, model.Pointer("components", k, "security_configuration"), c.ComponentID + " security_configuration"}}
	for s, sw := range c.HostedSoftware {
		cfgs = append(cfgs, cfg{sw.SecurityConfiguration, model.Pointer("components", k, "hosted_software", s, "security_configuration"),
			fmt.Sprintf("%s %s security_configuration", c.ComponentID, sw.Name)})
	}
	for _, key := range keys {
		for _, g := range cfgs {
			if b, ok := g.bag[key].(bool); ok {
				return Value{Set: true, On: b, Pointer: g.pointer + model.Pointer(key), Source: g.label + "." + key + ", " + role}
			}
		}
	}
	return Value{}
}

func (f *Flags) ptr(n Flag) *Value {
	switch n {
	case FlagCRC:
		return &f.CRC
	case FlagMAC:
		return &f.MAC
	default:
		return &f.Freshness
	}
}

// component returns the first component with id and its index; EXTERNAL_*
// sentinels and undefined IDs give nil.
func component(it *model.Item, id string) (int, *model.Component) {
	for k := range it.Components {
		if it.Components[k].ComponentID == id {
			return k, &it.Components[k]
		}
	}
	return -1, nil
}

func boolValue(b *bool, pointer, source string) Value {
	if b == nil {
		return Value{}
	}
	return Value{Set: true, On: *b, Pointer: pointer, Source: source}
}

func or(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
