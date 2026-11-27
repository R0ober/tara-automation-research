package lint

import (
	"fmt"
	"strings"

	"tarav/internal/model"
	"tarav/internal/protect"
)

// L017: an edge's protection could not be fully derived (plan §6, SPEC
// D14). Fires for every drawn edge (protect.Edges) with missing flags:
// either the level is unknown, or a stated flag proves a level that a
// missing one could still raise. element_id is the connection; json_path
// is the edge's connection, message or entry-point object.
func init() {
	Register(Rule{
		ID:          "L017",
		Severity:    Warning,
		Description: "edge protection flags not stated",
		Check:       checkProtectionUnknown,
	})
}

func checkProtectionUnknown(it *model.Item) []Finding {
	var out []Finding
	for _, e := range protect.Edges(it) {
		if len(e.Result.Missing) == 0 {
			continue
		}
		missing := make([]string, len(e.Result.Missing))
		for i, f := range e.Result.Missing {
			missing[i] = string(f)
		}
		level := "is unknown"
		if e.Result.Level != protect.Unknown {
			level = "is at least " + string(e.Result.Level)
		}
		out = append(out, Finding{
			Message: fmt.Sprintf("%s edge %s: protection %s; not stated: %s (set them in `protection` or the receiver's security_configuration)",
				e.Kind, e.ID, level, strings.Join(missing, ", ")),
			JSONPath:  e.Pointer,
			ElementID: it.Connections[e.Connection].ConnectionID,
		})
	}
	return out
}
