package protect

import (
	"fmt"

	"tarav/internal/model"
)

// EdgeKind is the kind of a protection-carrying edge.
type EdgeKind string

const (
	// KindConnection is a connection drawn source → target.
	KindConnection EdgeKind = "connection"
	// KindMessage is a message whose endpoints differ from its connection's
	// (plan §5: catches RIC → VDCM, listed only under adjacent_components).
	KindMessage EdgeKind = "message"
	// KindEntry is an edge from a declared entry point into the item.
	KindEntry EdgeKind = "entry"
)

// Edge is one drawn edge that carries a protection level. Physical-access
// and diagnostic-route edges carry none (D13) and are not listed.
type Edge struct {
	ID         string   `json:"id"`
	Kind       EdgeKind `json:"kind"`
	Connection int      `json:"-"` // index into Item.Connections
	Index      int      `json:"-"` // message or entry_points index; -1 for connections
	Pointer    string   `json:"json_path"`
	Flags      Flags    `json:"flags"`
	Result     Result   `json:"protection"`
}

// Edges lists the protection-carrying edges in input order: for each
// connection, its own edge, then its distinct message edges, then its
// entry-point edges.
//
// A connection with an EXTERNAL_* end that declares entry_points is not
// drawn itself: its entry-point edges stand in for it. Messages with the
// same endpoints as their connection and no protection of their own fold
// into the connection's edge.
func Edges(it *model.Item) []Edge {
	var out []Edge
	for i := range it.Connections {
		c := &it.Connections[i]
		external := model.IsExternal(c.SourceComponent) || model.IsExternal(c.TargetComponent)
		if !(external && len(c.EntryPoints) > 0) {
			f := ForConnection(it, i)
			out = append(out, Edge{ID: c.ConnectionID, Kind: KindConnection, Connection: i, Index: -1,
				Pointer: model.Pointer("connections", i), Flags: f, Result: Derive(f)})
		}
		used := map[string]bool{}
		for j := range c.Messages {
			if !MessageDrawn(c, j) {
				continue
			}
			m := &c.Messages[j]
			id := c.ConnectionID + "#msg:" + m.CANID
			if used[id] {
				id = fmt.Sprintf("%s~%d", id, j)
			}
			used[id] = true
			f := ForMessage(it, i, j)
			out = append(out, Edge{ID: id, Kind: KindMessage, Connection: i, Index: j,
				Pointer: model.Pointer("connections", i, "messages", j), Flags: f, Result: Derive(f)})
		}
		for j, ep := range c.EntryPoints {
			id := c.ConnectionID + "#ep:" + ep.InterfaceID
			if used[id] {
				id = fmt.Sprintf("%s~%d", id, j)
			}
			used[id] = true
			f := ForEntry(it, i, j)
			out = append(out, Edge{ID: id, Kind: KindEntry, Connection: i, Index: j,
				Pointer: model.Pointer("connections", i, "entry_points", j), Flags: f, Result: Derive(f)})
		}
	}
	return out
}

// MessageDrawn reports whether c.Messages[j] gets its own edge: it names a
// source or target that differs from the connection's, or states its own
// protection (folding it would hide a level that differs from the
// connection's).
func MessageDrawn(c *model.Connection, j int) bool {
	m := &c.Messages[j]
	if m.Protection != nil {
		return true
	}
	src, tgt := or(m.SourceComponent, c.SourceComponent), or(m.TargetComponent, c.TargetComponent)
	return src != c.SourceComponent || tgt != c.TargetComponent
}
