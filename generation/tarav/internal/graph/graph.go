// Package graph turns an item definition into the node/edge graph the viewer
// draws (plan §5). The graph is layout-free: positions are computed in the
// browser by ELK. Output order follows input order, so the same item always
// gives the same graph.
package graph

import (
	"fmt"
	"regexp"
	"strings"

	"tarav/internal/model"
	"tarav/internal/protect"
)

// Graph is the viewer's input.
type Graph struct {
	Item   Item    `json:"item"`
	Zones  []Zone  `json:"zones"`
	Nodes  []Node  `json:"nodes"`
	Edges  []Edge  `json:"edges"`
	Assets []Asset `json:"assets"`
}

type Item struct {
	ID     string `json:"item_id"`
	Name   string `json:"name"`
	Schema string `json:"schema,omitempty"`
}

// Zone is a trust zone, drawn as a container.
type Zone struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	TrustZone string `json:"trust_zone"`
}

// NodeKind is the kind of a node.
type NodeKind string

const (
	KindComponent NodeKind = "component"
	KindInstance  NodeKind = "instance"
	KindEntry     NodeKind = "entry"
	// KindExternal is an EXTERNAL_* end that is not an entry point (both
	// ends of its connection are external).
	KindExternal NodeKind = "external"
)

// Node is a component, instance or entry point. ElementID is the ID that
// lint findings use for it; JSONPath points at its definition.
type Node struct {
	ID            string   `json:"id"`
	Kind          NodeKind `json:"kind"`
	Label         string   `json:"label"`
	Name          string   `json:"name,omitempty"`
	Zone          string   `json:"zone,omitempty"`   // zone ID, for components
	Parent        string   `json:"parent,omitempty"` // owning component, for instances
	ASIL          string   `json:"asil,omitempty"`
	InstanceCount int      `json:"instance_count,omitempty"`
	Physical      bool     `json:"physical,omitempty"` // entry points: physical access
	Reaches       []string `json:"reaches,omitempty"`  // entry points: components they reach directly
	Reach         *Reach   `json:"reach,omitempty"`    // entry points: everything reachable (D17)
	ElementID     string   `json:"element_id"`
	JSONPath      string   `json:"json_path"`
}

// Reach is what can be reached from an entry point by following drawn edges
// in their declared direction (SPEC D17), in graph order. It includes the
// entry node itself. Topology only, not attack feasibility.
type Reach struct {
	Nodes []string `json:"nodes"`
	Edges []string `json:"edges"`
}

// EdgeKind is the kind of an edge.
type EdgeKind string

const (
	EdgeConnection EdgeKind = "connection"
	EdgeMessage    EdgeKind = "message"
	EdgeEntry      EdgeKind = "entry"
	EdgePhysical   EdgeKind = "physical"
	EdgeDiagnostic EdgeKind = "diagnostic"
)

// Edge is a drawn edge. Protection is set for connection, message and entry
// edges (protect.Edges) and nil for physical and diagnostic ones (D13).
// ElementID is the connection ID, which lint findings on the edge use.
type Edge struct {
	ID              string          `json:"id"`
	Kind            EdgeKind        `json:"kind"`
	Source          string          `json:"source"`
	Target          string          `json:"target"`
	TargetInstances []string        `json:"target_instances,omitempty"`
	Label           string          `json:"label"`
	Protection      *protect.Result `json:"protection,omitempty"`
	Flags           *protect.Flags  `json:"flags,omitempty"`
	ElementID       string          `json:"element_id"`
	JSONPath        string          `json:"json_path"`
}

// Asset is an asset marker on its parent component.
type Asset struct {
	ID          string   `json:"id"`
	Label       string   `json:"label"`
	Name        string   `json:"name"`
	Component   string   `json:"component"`
	Connections []string `json:"connections,omitempty"`
	JSONPath    string   `json:"json_path"`
}

const (
	zonePrefix  = "zone:"
	entryPrefix = "ep:"
)

// Build returns the graph for it. It assumes a schema-valid item; dangling
// references (L001) produce edges to nodes that do not exist, which the
// viewer drops and lint reports.
func Build(it *model.Item) *Graph {
	g := &Graph{Item: Item{ID: it.ItemDefinition.ItemID, Name: it.ItemDefinition.Name, Schema: it.Schema}}
	b := builder{it: it, g: g, extEntry: map[int]string{}, nodes: map[string]bool{}}
	b.zones()
	b.components()
	b.entryPoints()
	b.edges()
	b.assets()
	b.reach()
	return g
}

type builder struct {
	it       *model.Item
	g        *Graph
	extEntry map[int]string // connection index -> entry node for its EXTERNAL_* end
	nodes    map[string]bool
}

func (b *builder) addNode(n Node) {
	if b.nodes[n.ID] {
		return // duplicate IDs are L002's to report; the first one is drawn
	}
	b.nodes[n.ID] = true
	b.g.Nodes = append(b.g.Nodes, n)
}

func (b *builder) zones() {
	seen := map[string]bool{}
	for _, c := range b.it.Components {
		if seen[c.TrustZone] {
			continue
		}
		seen[c.TrustZone] = true
		label := strings.ReplaceAll(strings.TrimSuffix(c.TrustZone, "_Zone"), "_", " ")
		b.g.Zones = append(b.g.Zones, Zone{ID: zonePrefix + c.TrustZone, Label: label, TrustZone: c.TrustZone})
	}
}

func (b *builder) components() {
	for i, c := range b.it.Components {
		b.addNode(Node{ID: c.ComponentID, Kind: KindComponent, Label: ShortName(c.Name), Name: c.Name,
			Zone: zonePrefix + c.TrustZone, ASIL: c.ASILLevel, InstanceCount: len(c.Instances),
			ElementID: c.ComponentID, JSONPath: model.Pointer("components", i)})
		for j, in := range c.Instances {
			b.addNode(Node{ID: in.InstanceID, Kind: KindInstance, Label: lastToken(in.InstanceID),
				Parent: c.ComponentID, ASIL: c.ASILLevel,
				ElementID: in.InstanceID, JSONPath: model.Pointer("components", i, "instances", j)})
		}
	}
}

// entryPoints adds one node per normalized entry point (D3), and the
// physical-access edges, which carry no protection level.
func (b *builder) entryPoints() {
	for _, ep := range b.it.EntryPoints() {
		id := entryPrefix + ep.ID
		first := ep.Declarations[0]
		label := strings.TrimPrefix(ep.InterfaceID, "INT-")
		elem := ep.ID
		switch first.Source {
		case model.SourceConnectionPhysical:
			c := b.it.Connection(ep.Connections[0])
			label = "physical: " + strings.TrimPrefix(c.ConnectionID, "CONN-")
			if c.PhysicalAccess != nil && c.PhysicalAccess.Location != "" {
				label = c.PhysicalAccess.Location
			}
			elem = c.ConnectionID
		case model.SourceExternalConnection:
			if label == "" {
				label = strings.TrimPrefix(ep.ID, "CONN-")
			}
		}
		b.addNode(Node{ID: id, Kind: KindEntry, Label: label, Physical: ep.Physical, Reaches: ep.Components,
			ElementID: elem, JSONPath: first.Pointer})

		for _, d := range ep.Declarations {
			var ci int
			switch d.Source {
			case model.SourceExternalConnection:
				fmt.Sscanf(d.Pointer, "/connections/%d", &ci)
				b.extEntry[ci] = id
			case model.SourceComponentPhysical:
				var k int
				fmt.Sscanf(d.Pointer, "/components/%d/", &k)
				c := b.it.Components[k]
				b.g.Edges = append(b.g.Edges, Edge{ID: "phys:" + ep.ID + ":" + c.ComponentID, Kind: EdgePhysical,
					Source: id, Target: c.ComponentID, Label: "physical", ElementID: c.ComponentID, JSONPath: d.Pointer})
			case model.SourceConnectionPhysical:
				fmt.Sscanf(d.Pointer, "/connections/%d/", &ci)
				c := b.it.Connections[ci]
				// A tap on a bus reaches both internal ends; the target end
				// fans out to its instances when expanded.
				for _, end := range []struct {
					id   string
					inst []string
				}{{c.SourceComponent, nil}, {c.TargetComponent, c.TargetInstances}} {
					if model.IsExternal(end.id) {
						continue
					}
					b.g.Edges = append(b.g.Edges, Edge{ID: "phys:" + ep.ID + ":" + end.id, Kind: EdgePhysical,
						Source: id, Target: end.id, TargetInstances: end.inst, Label: "physical",
						ElementID: c.ConnectionID, JSONPath: d.Pointer})
				}
			}
		}
	}
}

// end maps a component reference to its node: EXTERNAL_* ends become the
// connection's entry node, or an external node if it has none.
func (b *builder) end(ci int, id string) string {
	if !model.IsExternal(id) {
		return id
	}
	if n, ok := b.extEntry[ci]; ok {
		return n
	}
	b.addNode(Node{ID: id, Kind: KindExternal, Label: strings.TrimPrefix(id, model.ExternalPrefix),
		ElementID: id, JSONPath: model.Pointer("connections", ci)})
	return id
}

func (b *builder) edges() {
	prot := protect.Edges(b.it)
	k := 0
	for ci := range b.it.Connections {
		c := &b.it.Connections[ci]
		for ; k < len(prot) && prot[k].Connection == ci; k++ {
			e := prot[k]
			r, f := e.Result, e.Flags
			out := Edge{ID: e.ID, Kind: EdgeKind(e.Kind), Protection: &r, Flags: &f,
				ElementID: c.ConnectionID, JSONPath: e.Pointer}
			switch e.Kind {
			case protect.KindConnection:
				out.Source, out.Target = b.end(ci, c.SourceComponent), b.end(ci, c.TargetComponent)
				out.TargetInstances = c.TargetInstances
				out.Label = connLabel(c)
			case protect.KindMessage:
				m := &c.Messages[e.Index]
				out.Source = b.end(ci, or(m.SourceComponent, c.SourceComponent))
				out.Target = b.end(ci, or(m.TargetComponent, c.TargetComponent))
				out.Label = m.CANID
			case protect.KindEntry:
				// One edge, into the target end (the source end when the
				// target is external); the entry node's Reaches lists every
				// component the entry point reaches.
				ep := c.EntryPoints[e.Index]
				out.Source = entryPrefix + ep.InterfaceID
				out.Target = c.TargetComponent
				if model.IsExternal(out.Target) {
					out.Target = c.SourceComponent
				}
				out.Label = strings.TrimPrefix(ep.InterfaceID, "INT-")
			}
			b.g.Edges = append(b.g.Edges, out)
		}
		if da := c.DiagnosticAccess; da != nil && da.RequestHandlerComponent != "" {
			for ri, r := range da.DownstreamRoutes {
				if r.TargetComponent == "" {
					continue
				}
				label := "diag"
				if p := firstWord(r.Protocol); p != "" {
					label += " · " + p
				}
				b.g.Edges = append(b.g.Edges, Edge{ID: fmt.Sprintf("diag:%s:%d", c.ConnectionID, ri), Kind: EdgeDiagnostic,
					Source: da.RequestHandlerComponent, Target: r.TargetComponent, Label: label,
					ElementID: c.ConnectionID, JSONPath: model.Pointer("connections", ci, "diagnostic_access", "downstream_routes", ri)})
			}
		}
	}
}

func (b *builder) assets() {
	for i, a := range b.it.Assets {
		b.g.Assets = append(b.g.Assets, Asset{ID: a.AssetID, Label: assetLabel(a.AssetID), Name: a.Name,
			Component: a.ParentComponent, Connections: a.AssociatedConnections, JSONPath: model.Pointer("assets", i)})
	}
}

// reach fills Reach for every entry node (D17). Entering a component
// reaches its instances and an instance reaches its component, so a fan-out
// to target_instances and a group behave the same; an edge is traversed
// when its source is reached and its target is a node.
func (b *builder) reach() {
	nodeIdx := map[string]int{}
	members := map[string][]string{} // component -> instances
	for i, n := range b.g.Nodes {
		nodeIdx[n.ID] = i
		if n.Kind == KindInstance {
			members[n.Parent] = append(members[n.Parent], n.ID)
		}
	}
	out := map[string][]int{} // node -> outgoing edge indices
	for i, e := range b.g.Edges {
		out[e.Source] = append(out[e.Source], i)
	}
	for k := range b.g.Nodes {
		start := &b.g.Nodes[k]
		if start.Kind != KindEntry {
			continue
		}
		seenN, seenE := map[string]bool{}, map[int]bool{}
		queue := []string{start.ID}
		visit := func(id string) {
			if _, ok := nodeIdx[id]; ok && !seenN[id] {
				queue = append(queue, id)
			}
		}
		for len(queue) > 0 {
			id := queue[0]
			queue = queue[1:]
			if seenN[id] {
				continue
			}
			seenN[id] = true
			n := b.g.Nodes[nodeIdx[id]]
			for _, m := range members[id] {
				visit(m)
			}
			if n.Kind == KindInstance {
				visit(n.Parent)
			}
			for _, ei := range out[id] {
				e := b.g.Edges[ei]
				if _, ok := nodeIdx[e.Target]; !ok {
					continue // dangling reference (L001)
				}
				seenE[ei] = true
				visit(e.Target)
				for _, ti := range e.TargetInstances {
					visit(ti)
				}
			}
		}
		r := &Reach{Nodes: []string{}, Edges: []string{}}
		for _, n := range b.g.Nodes {
			if seenN[n.ID] {
				r.Nodes = append(r.Nodes, n.ID)
			}
		}
		for i, e := range b.g.Edges {
			if seenE[i] {
				r.Edges = append(r.Edges, e.ID)
			}
		}
		start.Reach = r
	}
}

// ------------------------------------------------------------------ labels

var parens = regexp.MustCompile(`\(([^)]+)\)`)
var countSuffix = regexp.MustCompile(`\s*[x×]\d+$`)

// ShortName returns the parenthesised abbreviation in a component name
// ("Electro-Mechanical Brake Actuator (EMBA) x4" -> "EMBA"), or the name.
func ShortName(name string) string {
	m := parens.FindStringSubmatch(name)
	if m == nil {
		return name
	}
	return countSuffix.ReplaceAllString(m[1], "")
}

// connLabel is "<id without CONN-> · <what it carries>": the CAN IDs of its
// folded messages, else the first protocol word.
func connLabel(c *model.Connection) string {
	var ids []string
	for j, m := range c.Messages {
		if !protect.MessageDrawn(c, j) && m.CANID != "" {
			ids = append(ids, m.CANID)
		}
	}
	what := strings.Join(ids, ", ")
	if what == "" {
		what = firstWord(c.Protocol)
	}
	id := strings.TrimPrefix(c.ConnectionID, "CONN-")
	if what == "" {
		return id
	}
	return id + " · " + what
}

// firstWord is the first meaningful protocol word: "Raw CAN-FD Frames …" -> "CAN-FD".
func firstWord(protocol string) string {
	p := strings.TrimSpace(protocol)
	for _, pre := range []string{"Raw ", "Plain "} {
		p = strings.TrimPrefix(p, pre)
	}
	if f := strings.Fields(p); len(f) > 0 {
		return strings.TrimRight(f[0], ",;:")
	}
	return ""
}

// assetLabel is a short marker: "ASSET-BRK-04" -> "A04", "ASSET-01" -> "A01";
// an ID without a dash is used as is.
func assetLabel(id string) string {
	if t := lastToken(id); t != id {
		return "A" + t
	}
	return id
}

func lastToken(id string) string {
	if i := strings.LastIndexByte(id, '-'); i >= 0 && i < len(id)-1 {
		return id[i+1:]
	}
	return id
}

func or(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
