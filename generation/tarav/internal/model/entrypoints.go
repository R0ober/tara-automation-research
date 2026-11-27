package model

import "fmt"

// EntrySource says where in the input an entry point was declared.
type EntrySource string

const (
	// SourceDeclared: connections[].entry_points[].
	SourceDeclared EntrySource = "entry_points"
	// SourceComponentPhysical: components[].physical_access (debug headers).
	SourceComponentPhysical EntrySource = "component_physical_access"
	// SourceConnectionPhysical: connections[].physical_access (bus/harness taps).
	SourceConnectionPhysical EntrySource = "connection_physical_access"
	// SourceExternalConnection: a connection with an EXTERNAL_* end and no
	// entry_points[] is itself the entry point (D6; how OTA-ADAS declares
	// its attack surface).
	SourceExternalConnection EntrySource = "external_connection"
)

// Declaration is one place an entry point is declared.
type Declaration struct {
	Source  EntrySource `json:"source"`
	Pointer string      `json:"json_path"` // RFC 6901, into the input
}

// EntryPoint is one normalized point of access into the item (SPEC D3).
// Entries are keyed by ID: the same interface declared in several places,
// or towards several components, is one entry point reaching all of them.
type EntryPoint struct {
	// ID is the interface ID, or "<connection_id>#physical_access" for a
	// tap without one, or "<connection_id>" for an external connection
	// without an interface_id.
	ID          string `json:"id"`
	InterfaceID string `json:"interface_id,omitempty"`
	// Physical is true when any declaration is a physical_access.
	Physical bool `json:"physical"`
	// Components directly reached, in first-seen order; never EXTERNAL_*.
	Components []string `json:"components"`
	// Instances directly reached (target_instances of a tapped connection).
	Instances []string `json:"instances,omitempty"`
	// Connections the entry point is declared on or taps.
	Connections  []string      `json:"connections,omitempty"`
	Declarations []Declaration `json:"declarations"`
}

// EntryPoints returns the normalized entry points in document order of
// their first declaration (components before connections, then by index).
func (it *Item) EntryPoints() []EntryPoint {
	var out []EntryPoint
	pos := map[string]int{}
	add := func(id, iface string, physical bool, src EntrySource, ptr string, conn string, comps, insts []string) {
		i, ok := pos[id]
		if !ok {
			i = len(out)
			pos[id] = i
			out = append(out, EntryPoint{ID: id, InterfaceID: iface})
		}
		ep := &out[i]
		ep.Physical = ep.Physical || physical
		ep.Components = appendNew(ep.Components, comps...)
		ep.Instances = appendNew(ep.Instances, insts...)
		if conn != "" {
			ep.Connections = appendNew(ep.Connections, conn)
		}
		ep.Declarations = append(ep.Declarations, Declaration{Source: src, Pointer: ptr})
	}

	for i, c := range it.Components {
		if pa := c.PhysicalAccess; pa != nil && pa.InterfaceID != "" {
			add(pa.InterfaceID, pa.InterfaceID, true, SourceComponentPhysical,
				fmt.Sprintf("/components/%d/physical_access", i), "", []string{c.ComponentID}, nil)
		}
	}
	for i, c := range it.Connections {
		ends := internalEnds(c)
		for j, d := range c.EntryPoints {
			add(d.InterfaceID, d.InterfaceID, false, SourceDeclared,
				fmt.Sprintf("/connections/%d/entry_points/%d", i, j), c.ConnectionID, ends, nil)
		}
		if len(c.EntryPoints) == 0 && (IsExternal(c.SourceComponent) || IsExternal(c.TargetComponent)) && len(ends) > 0 {
			id := c.InterfaceID
			if id == "" {
				id = c.ConnectionID
			}
			add(id, c.InterfaceID, false, SourceExternalConnection,
				fmt.Sprintf("/connections/%d", i), c.ConnectionID, ends, c.TargetInstances)
		}
		if c.PhysicalAccess != nil {
			// A tap on the wire reaches every end of it.
			add(c.ConnectionID+"#physical_access", "", true, SourceConnectionPhysical,
				fmt.Sprintf("/connections/%d/physical_access", i), c.ConnectionID, ends, c.TargetInstances)
		}
	}
	return out
}

// internalEnds lists a connection's non-external endpoints, source first.
func internalEnds(c Connection) []string {
	var ends []string
	for _, id := range []string{c.SourceComponent, c.TargetComponent} {
		if id != "" && !IsExternal(id) {
			ends = appendNew(ends, id)
		}
	}
	return ends
}

// appendNew appends the values not already in s, keeping order.
func appendNew(s []string, vals ...string) []string {
outer:
	for _, v := range vals {
		for _, x := range s {
			if x == v {
				continue outer
			}
		}
		s = append(s, v)
	}
	return s
}
