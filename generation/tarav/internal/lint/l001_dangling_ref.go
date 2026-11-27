package lint

import (
	"fmt"

	"tarav/internal/model"
)

// L001: dangling references. Every place one element names another by ID
// must name something defined in the item:
//
//   - components: connection source/target, adjacent_components, message
//     source/target, diagnostic_access.request_handler_component,
//     downstream_routes[].target_component, asset parent_component.
//     EXTERNAL_* sentinels count as defined (SPEC D6).
//   - instances: target_instances, payload_fields[].target_instance.
//   - connections: downstream_routes[].via_connection, diagnostic_services
//     request/execution_connection, forwarding_rules input/output_connection,
//     asset associated_connections.
//   - interfaces: connection interface_id (only where present; inferred
//     interfaces are defined by construction, SPEC D10), entry_points[],
//     component physical_access, and diagnostic entry_interfaces. Interfaces
//     have no definition list, so "defined" means listed by some component.
//
// Empty strings are skipped: a missing required ID is the schema's job.
// element_id is the element holding the reference; json_path points at the
// reference itself.
func init() {
	Register(Rule{
		ID:          "L001",
		Severity:    Error,
		Description: "reference to an undefined component, instance, connection or interface",
		Check:       checkDanglingRefs,
	})
}

type refKind struct {
	noun    string
	defined func(*model.Item, string) bool
}

var (
	refComponent  = refKind{"component", (*model.Item).HasComponent}
	refInstance   = refKind{"instance", (*model.Item).HasInstance}
	refConnection = refKind{"connection", (*model.Item).HasConnection}
	refInterface  = refKind{"interface", (*model.Item).HasInterface}
)

func checkDanglingRefs(it *model.Item) []Finding {
	var out []Finding
	// ref checks one reference. owner names the referring element for the
	// message ("connection CONN-1"); field is the referring field's name.
	ref := func(k refKind, id, ownerKind, ownerID, field string, ptr ...any) {
		if id == "" || k.defined(it, id) {
			return
		}
		out = append(out, Finding{
			Message:   fmt.Sprintf("%s %s: %s %q is not a defined %s", ownerKind, ownerID, field, id, k.noun),
			JSONPath:  model.Pointer(ptr...),
			ElementID: ownerID,
		})
	}

	for i, c := range it.Components {
		id := c.ComponentID
		if pa := c.PhysicalAccess; pa != nil {
			ref(refInterface, pa.InterfaceID, "component", id, "physical_access.interface_id", "components", i, "physical_access", "interface_id")
		}
		for j, s := range c.DiagnosticServices {
			ref(refConnection, s.RequestConnection, "component", id, "diagnostic_services.request_connection", "components", i, "diagnostic_services", j, "request_connection")
			ref(refConnection, s.ExecutionConnection, "component", id, "diagnostic_services.execution_connection", "components", i, "diagnostic_services", j, "execution_connection")
		}
		for j, r := range c.ForwardingRules {
			ref(refConnection, r.InputConnection, "component", id, "forwarding_rules.input_connection", "components", i, "forwarding_rules", j, "input_connection")
			ref(refConnection, r.OutputConnection, "component", id, "forwarding_rules.output_connection", "components", i, "forwarding_rules", j, "output_connection")
		}
	}

	for i, c := range it.Connections {
		id := c.ConnectionID
		base := []any{"connections", i}
		at := func(rest ...any) []any { return append(append([]any(nil), base...), rest...) }

		ref(refComponent, c.SourceComponent, "connection", id, "source_component", at("source_component")...)
		ref(refComponent, c.TargetComponent, "connection", id, "target_component", at("target_component")...)
		ref(refInterface, c.InterfaceID, "connection", id, "interface_id", at("interface_id")...)
		for j, x := range c.TargetInstances {
			ref(refInstance, x, "connection", id, "target_instances", at("target_instances", j)...)
		}
		for j, x := range c.AdjacentComponents {
			ref(refComponent, x, "connection", id, "adjacent_components", at("adjacent_components", j)...)
		}
		for j, e := range c.EntryPoints {
			ref(refInterface, e.InterfaceID, "connection", id, "entry_points.interface_id", at("entry_points", j, "interface_id")...)
		}
		for j, m := range c.Messages {
			ref(refComponent, m.SourceComponent, "connection", id, "messages.source_component", at("messages", j, "source_component")...)
			ref(refComponent, m.TargetComponent, "connection", id, "messages.target_component", at("messages", j, "target_component")...)
			for k, p := range m.PayloadFields {
				ref(refInstance, p.TargetInstance, "connection", id, "payload_fields.target_instance", at("messages", j, "payload_fields", k, "target_instance")...)
			}
		}
		if da := c.DiagnosticAccess; da != nil {
			ref(refComponent, da.RequestHandlerComponent, "connection", id, "diagnostic_access.request_handler_component", at("diagnostic_access", "request_handler_component")...)
			if b := da.BrakeOverrideService; b != nil {
				for j, x := range b.EntryInterfaces {
					ref(refInterface, x, "connection", id, "brake_override_service.entry_interfaces", at("diagnostic_access", "brake_override_service", "entry_interfaces", j)...)
				}
			}
			for j, r := range da.DownstreamRoutes {
				rp := func(rest ...any) []any {
					return at(append([]any{"diagnostic_access", "downstream_routes", j}, rest...)...)
				}
				ref(refComponent, r.TargetComponent, "connection", id, "downstream_routes.target_component", rp("target_component")...)
				ref(refConnection, r.ViaConnection, "connection", id, "downstream_routes.via_connection", rp("via_connection")...)
				for k, x := range r.EntryInterfaces {
					ref(refInterface, x, "connection", id, "downstream_routes.entry_interfaces", rp("entry_interfaces", k)...)
				}
			}
		}
	}

	for i, a := range it.Assets {
		ref(refComponent, a.ParentComponent, "asset", a.AssetID, "parent_component", "assets", i, "parent_component")
		for j, x := range a.AssociatedConnections {
			ref(refConnection, x, "asset", a.AssetID, "associated_connections", "assets", i, "associated_connections", j)
		}
	}
	return out
}
