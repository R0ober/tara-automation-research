package lint

import (
	"fmt"

	"tarav/internal/model"
)

// L003: an asset with no damage scenario cannot be assessed, so the TARA is
// incomplete. The schema allows the list to be missing or empty; this rule
// does not. json_path points at the empty list when present, otherwise at
// the asset, so it always resolves in the input.
func init() {
	Register(Rule{
		ID:          "L003",
		Severity:    Error,
		Description: "asset with no damage scenario",
		Check:       checkNoDamageScenario,
	})
}

func checkNoDamageScenario(it *model.Item) []Finding {
	var out []Finding
	for i, a := range it.Assets {
		if len(a.DamageScenarios) > 0 {
			continue
		}
		ptr, how := model.Pointer("assets", i), "has no damage_scenarios"
		if a.DamageScenarios != nil {
			ptr, how = model.Pointer("assets", i, "damage_scenarios"), "has an empty damage_scenarios list"
		}
		out = append(out, Finding{
			Message:   fmt.Sprintf("asset %s %s; every asset needs at least one damage scenario", a.AssetID, how),
			JSONPath:  ptr,
			ElementID: a.AssetID,
		})
	}
	return out
}
