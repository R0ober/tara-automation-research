package lint

import (
	"fmt"
	"strings"

	"tarav/internal/model"
)

// L002: duplicate IDs. One global namespace (SPEC D8) covers component,
// instance, connection, asset and damage-scenario IDs, so every element_id
// is unambiguous. Interface IDs are excluded: they are references listed per
// component and legitimately repeat.
//
// The first occurrence is the definition; each later one is a finding at
// its own pointer, naming where the first one is.
func init() {
	Register(Rule{
		ID:          "L002",
		Severity:    Error,
		Description: "duplicate ID across components, instances, connections, assets and damage scenarios",
		Check:       checkDuplicateIDs,
	})
}

type idSite struct {
	kind    string
	pointer string
}

func checkDuplicateIDs(it *model.Item) []Finding {
	first := map[string]idSite{}
	var out []Finding
	see := func(id, kind, ptr string) {
		if id == "" {
			return // missing IDs are the schema's job
		}
		if prev, dup := first[id]; dup {
			out = append(out, Finding{
				Message:   fmt.Sprintf("%s ID %q is already used by %s %s at %s", kind, id, article(prev.kind), prev.kind, prev.pointer),
				JSONPath:  ptr,
				ElementID: id,
			})
			return
		}
		first[id] = idSite{kind, ptr}
	}
	// Document order, so "first" means first in the file.
	for i, c := range it.Components {
		see(c.ComponentID, "component", model.Pointer("components", i, "component_id"))
		for j, in := range c.Instances {
			see(in.InstanceID, "instance", model.Pointer("components", i, "instances", j, "instance_id"))
		}
	}
	for i, c := range it.Connections {
		see(c.ConnectionID, "connection", model.Pointer("connections", i, "connection_id"))
	}
	for i, a := range it.Assets {
		see(a.AssetID, "asset", model.Pointer("assets", i, "asset_id"))
		for j, d := range a.DamageScenarios {
			see(d.DamageID, "damage scenario", model.Pointer("assets", i, "damage_scenarios", j, "damage_id"))
		}
	}
	return out
}

func article(noun string) string {
	if noun != "" && strings.ContainsRune("aeiou", rune(noun[0])) {
		return "an"
	}
	return "a"
}
