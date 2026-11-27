package graph

import (
	"fmt"
	"strings"

	"tarav/internal/model"
)

// Locate returns the ID of the graph element a JSON pointer into it is
// shown on (SPEC D18), or "" when it has none. The element whose own
// pointer is the longest prefix of ptr wins. On a tie an edge beats a node
// (an entry point's edge carries its protection), except physical-access
// edges, which repeat their entry node's pointer once per bus end.
// Elements that are not drawn fall back to their owner: a duplicate
// component (L002) to the drawn component with its ID, a connection without
// a drawable edge of its own to its first entry edge or entry node, else to
// whichever of its endpoint components exists, and an asset to its parent
// component, else its first drawn associated connection. Edges with an
// undefined end (L001) are never drawn, so they are never a link target.
func (g *Graph) Locate(it *model.Item, ptr string) string {
	best, bestLen := "", -1
	try := func(id, p string, winsTie bool) {
		if (len(p) > bestLen || winsTie && len(p) == bestLen) && (ptr == p || strings.HasPrefix(ptr, p+"/")) {
			best, bestLen = id, len(p)
		}
	}
	for _, n := range g.Nodes {
		try(n.ID, n.JSONPath, false)
	}
	for _, e := range g.Edges {
		if g.Drawable(e) {
			try(e.ID, e.JSONPath, e.Kind != EdgePhysical)
		}
	}
	// A match on the collection's index itself (e.g. /connections/0) is
	// already the owner; deeper matches are more specific. Only fall back
	// when nothing at or below the owning index matched.
	owner, idx := splitOwner(ptr)
	if owner == "" || bestLen >= len(model.Pointer(owner, idx)) {
		return best
	}
	switch owner {
	case "components":
		if idx < len(it.Components) && g.hasNode(it.Components[idx].ComponentID) {
			return it.Components[idx].ComponentID
		}
	case "connections":
		prefix := model.Pointer("connections", idx) + "/"
		for _, e := range g.Edges {
			if g.Drawable(e) && strings.HasPrefix(e.JSONPath, prefix) {
				return e.ID
			}
		}
		for _, n := range g.Nodes {
			if n.JSONPath == prefix[:len(prefix)-1] || strings.HasPrefix(n.JSONPath, prefix) {
				return n.ID
			}
		}
		if idx < len(it.Connections) {
			for _, end := range []string{it.Connections[idx].SourceComponent, it.Connections[idx].TargetComponent} {
				if g.hasNode(end) {
					return end
				}
			}
		}
	case "assets":
		if idx >= len(g.Assets) {
			break
		}
		a := g.Assets[idx]
		if g.hasNode(a.Component) {
			return a.Component
		}
		for _, c := range a.Connections {
			for _, e := range g.Edges {
				if e.ElementID == c {
					return e.ID
				}
			}
		}
	}
	return best
}

// Drawable reports whether both ends of e are nodes. Edges to undefined
// references (L001) are kept in the graph for completeness but not drawn.
func (g *Graph) Drawable(e Edge) bool { return g.hasNode(e.Source) && g.hasNode(e.Target) }

func (g *Graph) hasNode(id string) bool {
	for _, n := range g.Nodes {
		if n.ID == id {
			return true
		}
	}
	return false
}

// splitOwner returns the top-level collection and index of ptr
// ("/assets/2/name" -> "assets", 2), or "" if ptr is not inside one.
func splitOwner(ptr string) (string, int) {
	var owner string
	var idx int
	for _, c := range []string{"components", "connections", "assets"} {
		if _, err := fmt.Sscanf(ptr, "/"+c+"/%d", &idx); err == nil {
			owner = c
			break
		}
	}
	return owner, idx
}
