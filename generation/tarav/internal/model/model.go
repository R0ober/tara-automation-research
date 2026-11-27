// Package model holds typed Go structs for an item definition.
//
// Structural fields (IDs, references, names, transport) are typed. The
// free-form configuration bags whose keys differ per component
// (security_configuration, operational_parameters, diagnostic_programming,
// firmware_*, ssh_maintenance) are kept as map[string]any: the schema, not
// the model, decides how strict the input is (SPEC M1 scope), and unknown
// fields anywhere are ignored on load.
//
// Optional booleans are *bool so callers can tell "false" from "absent";
// plan §6 treats an absent protection flag as "unknown", not "none".
package model

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// ExternalPrefix marks reserved component IDs for "outside the item"
// (SPEC D6). They count as defined for reference checks.
const ExternalPrefix = "EXTERNAL_"

// IsExternal reports whether id is a reserved EXTERNAL_* sentinel.
func IsExternal(id string) bool { return strings.HasPrefix(id, ExternalPrefix) }

// Config is a free-form configuration object, decoded as generic JSON.
type Config = map[string]any

// Item is a whole item-definition document.
type Item struct {
	Schema         string         `json:"$schema,omitempty"`
	ItemDefinition ItemDefinition `json:"item_definition"`
	Components     []Component    `json:"components"`
	Connections    []Connection   `json:"connections"`
	Assets         []Asset        `json:"assets"`

	idx index
}

type ItemDefinition struct {
	ItemID              string     `json:"item_id"`
	Name                string     `json:"name"`
	StandardReference   string     `json:"standard_reference,omitempty"`
	SystemBoundary      string     `json:"system_boundary,omitempty"`
	Functions           []Function `json:"functions,omitempty"`
	ModelingAssumptions []string   `json:"modeling_assumptions,omitempty"`
}

type Function struct {
	FunctionID  string `json:"function_id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

type Component struct {
	ComponentID string     `json:"component_id"`
	Name        string     `json:"name"`
	Type        string     `json:"type,omitempty"`
	Role        string     `json:"role,omitempty"`
	TrustZone   string     `json:"trust_zone"`
	ASILLevel   string     `json:"asil_level,omitempty"`
	Hardware    string     `json:"hardware,omitempty"`
	Instances   []Instance `json:"instances,omitempty"`
	Interfaces  []string   `json:"interfaces"`

	OS             *OS        `json:"os,omitempty"`
	HostedSoftware []Software `json:"hosted_software,omitempty"`
	// Component-level security config (no sample uses it yet; software-level
	// configs live on Software).
	SecurityConfiguration Config `json:"security_configuration,omitempty"`

	PhysicalAccess        *ComponentPhysicalAccess `json:"physical_access,omitempty"`
	DiagnosticServices    []DiagnosticService      `json:"diagnostic_services,omitempty"`
	DiagnosticProgramming Config                   `json:"diagnostic_programming,omitempty"`
	FirmwareProgramming   Config                   `json:"firmware_programming,omitempty"`
	FirmwareActivation    Config                   `json:"firmware_activation,omitempty"`
	ForwardingRules       []ForwardingRule         `json:"forwarding_rules,omitempty"`
}

type Instance struct {
	InstanceID    string `json:"instance_id"`
	WheelPosition string `json:"wheel_position,omitempty"`
}

type OS struct {
	Name                      string `json:"name"`
	Version                   string `json:"version,omitempty"`
	KernelVersion             string `json:"kernel_version,omitempty"`
	KernelSource              string `json:"kernel_source,omitempty"`
	VendorKernelModifications *bool  `json:"vendor_kernel_modifications,omitempty"`
	CPE                       string `json:"cpe,omitempty"`
}

type Software struct {
	Name                  string `json:"name"`
	Version               string `json:"version,omitempty"`
	CPE                   string `json:"cpe,omitempty"`
	Role                  string `json:"role,omitempty"`
	ListeningPort         *int   `json:"listening_port,omitempty"`
	SecurityConfiguration Config `json:"security_configuration,omitempty"`
	OperationalParameters Config `json:"operational_parameters,omitempty"`
}

// ComponentPhysicalAccess is a debug/physical port on a component; its
// interface_id is a reference into the component's interfaces.
type ComponentPhysicalAccess struct {
	InterfaceID                 string `json:"interface_id"`
	RequiredAccess              string `json:"required_access,omitempty"`
	DebugAuthenticationRequired *bool  `json:"debug_authentication_required,omitempty"`
	Capability                  string `json:"capability,omitempty"`
}

type DiagnosticService struct {
	ServiceID                    string `json:"service_id,omitempty"`
	Routine                      string `json:"routine,omitempty"`
	Operation                    string `json:"operation,omitempty"`
	SecurityAccessRequired       *bool  `json:"security_access_required,omitempty"`
	VehicleSpeedInterlockEnabled *bool  `json:"vehicle_speed_interlock_enabled,omitempty"`
	// References to connections.
	ExecutionConnection string `json:"execution_connection,omitempty"`
	RequestConnection   string `json:"request_connection,omitempty"`
	// Descriptive text.
	ExecutionBehavior        string `json:"execution_behavior,omitempty"`
	TargetSelection          string `json:"target_selection,omitempty"`
	TargetScope              string `json:"target_scope,omitempty"`
	Effect                   string `json:"effect,omitempty"`
	VDCMDiagnosticForwarding string `json:"vdcm_diagnostic_forwarding,omitempty"`
}

type ForwardingRule struct {
	InputConnection                          string `json:"input_connection"`
	OutputConnection                         string `json:"output_connection"`
	RequestScope                             string `json:"request_scope,omitempty"`
	RawCANForwardingEnabled                  *bool  `json:"raw_can_forwarding_enabled,omitempty"`
	ClientAuthorizationRequiredForForwarding *bool  `json:"client_authorization_required_for_forwarding,omitempty"`
}

type Connection struct {
	ConnectionID       string   `json:"connection_id"`
	Name               string   `json:"name,omitempty"`
	Purpose            string   `json:"purpose,omitempty"`
	SourceComponent    string   `json:"source_component"`
	TargetComponent    string   `json:"target_component"`
	TargetInstances    []string `json:"target_instances,omitempty"`
	AdjacentComponents []string `json:"adjacent_components,omitempty"`
	// InterfaceID is optional (SPEC D10).
	InterfaceID   string `json:"interface_id,omitempty"`
	Medium        string `json:"medium,omitempty"`
	Protocol      string `json:"protocol,omitempty"`
	Encrypted     *bool  `json:"encrypted,omitempty"`
	Authenticated string `json:"authenticated,omitempty"`

	// Protection is the explicit flag set (schema 1.1.0, SPEC D11).
	Protection       *Protection               `json:"protection,omitempty"`
	EntryPoints      []EntryPointDecl          `json:"entry_points,omitempty"`
	Messages         []Message                 `json:"messages,omitempty"`
	PhysicalAccess   *ConnectionPhysicalAccess `json:"physical_access,omitempty"`
	DiagnosticAccess *DiagnosticAccess         `json:"diagnostic_access,omitempty"`
	SSHMaintenance   Config                    `json:"ssh_maintenance,omitempty"`

	TelemetryQueueReadAccess *bool `json:"telemetry_queue_read_access,omitempty"`
}

// Protection states which integrity/authenticity mechanisms the receiver
// verifies. A nil flag is unknown, never false (SPEC D12).
type Protection struct {
	E2ECRC    *bool `json:"e2e_crc,omitempty"`
	MAC       *bool `json:"mac,omitempty"`
	Freshness *bool `json:"freshness,omitempty"`
}

// EntryPointDecl is an entry point as declared under connections[].entry_points.
// The normalized list across all locations is built separately (task 8, D3).
type EntryPointDecl struct {
	InterfaceID       string `json:"interface_id"`
	Medium            string `json:"medium,omitempty"`
	Protocol          string `json:"protocol,omitempty"`
	AccessRequirement string `json:"access_requirement,omitempty"`
	Encrypted         *bool  `json:"encrypted,omitempty"`
}

type Message struct {
	CANID            string         `json:"can_id"`
	Name             string         `json:"name"`
	SourceComponent  string         `json:"source_component,omitempty"`
	TargetComponent  string         `json:"target_component,omitempty"`
	Protection       *Protection    `json:"protection,omitempty"`
	PayloadUnit      string         `json:"payload_unit,omitempty"`
	PayloadFields    []PayloadField `json:"payload_fields,omitempty"`
	ReceiverBehavior string         `json:"receiver_behavior,omitempty"`
}

type PayloadField struct {
	Name           string   `json:"name"`
	Type           string   `json:"type,omitempty"`
	Unit           string   `json:"unit,omitempty"`
	Meaning        string   `json:"meaning,omitempty"`
	TargetInstance string   `json:"target_instance,omitempty"`
	CoveredFields  []string `json:"covered_fields,omitempty"`
}

// ConnectionPhysicalAccess is a physical tap on a connection (e.g. a harness).
type ConnectionPhysicalAccess struct {
	Location            string `json:"location,omitempty"`
	RequiredAccess      string `json:"required_access,omitempty"`
	RequiredEquipment   string `json:"required_equipment,omitempty"`
	CabinAccessRequired *bool  `json:"cabin_access_required,omitempty"`
}

type DiagnosticAccess struct {
	RequestHandlerComponent        string            `json:"request_handler_component,omitempty"`
	RawChassisCANForwardingEnabled *bool             `json:"raw_chassis_can_forwarding_enabled,omitempty"`
	BrakeOverrideService           *DiagnosticRoute  `json:"brake_override_service,omitempty"`
	DownstreamRoutes               []DownstreamRoute `json:"downstream_routes,omitempty"`
}

// DiagnosticRoute is a diagnostic service reachable through entry interfaces.
type DiagnosticRoute struct {
	ServiceID                       string   `json:"service_id,omitempty"`
	HandlerSoftware                 string   `json:"handler_software,omitempty"`
	EntryInterfaces                 []string `json:"entry_interfaces,omitempty"`
	AdditionalAuthorizationRequired *bool    `json:"additional_authorization_required,omitempty"`
	AllowedWhileDriving             *bool    `json:"allowed_while_driving,omitempty"`
}

type DownstreamRoute struct {
	TargetComponent                       string   `json:"target_component"`
	ViaConnection                         string   `json:"via_connection,omitempty"`
	Protocol                              string   `json:"protocol,omitempty"`
	EntryInterfaces                       []string `json:"entry_interfaces,omitempty"`
	AdditionalClientAuthorizationRequired *bool    `json:"additional_client_authorization_required,omitempty"`
	RequestScope                          string   `json:"request_scope,omitempty"`
}

type Asset struct {
	AssetID                 string           `json:"asset_id"`
	Name                    string           `json:"name"`
	ParentComponent         string           `json:"parent_component"`
	AssociatedConnections   []string         `json:"associated_connections,omitempty"`
	CybersecurityProperties []string         `json:"cybersecurity_properties,omitempty"`
	DamageScenarios         []DamageScenario `json:"damage_scenarios,omitempty"`
	LocalReadAccess         []string         `json:"local_read_access,omitempty"`
	BackendReadAccess       []string         `json:"backend_read_access,omitempty"`
	LocalRetention          string           `json:"local_retention,omitempty"`
	ReportContents          []string         `json:"report_contents,omitempty"`
}

type DamageScenario struct {
	DamageID           string `json:"damage_id"`
	Description        string `json:"description,omitempty"`
	ExpectedSFOPImpact *SFOP  `json:"expected_sfop_impact,omitempty"`
}

// SFOP ratings (Safety, Financial, Operational, Privacy) as written in the input.
type SFOP struct {
	Safety      string `json:"Safety,omitempty"`
	Financial   string `json:"Financial,omitempty"`
	Operational string `json:"Operational,omitempty"`
	Privacy     string `json:"Privacy,omitempty"`
}

// ---------------------------------------------------------------- loading

// Load decodes an item definition. Unknown fields are ignored; run schema
// validation first if strictness matters.
func Load(data []byte) (*Item, error) {
	var it Item
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&it); err != nil {
		return nil, fmt.Errorf("decode item definition: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("decode item definition: trailing data after top-level value")
	}
	it.buildIndex()
	return &it, nil
}

// LoadFile reads and decodes an item definition from path.
func LoadFile(path string) (*Item, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Load(data)
}

// ---------------------------------------------------------------- lookups

// index maps IDs to slice positions. With duplicate IDs the first
// occurrence wins; detecting duplicates is L002's job, not the index's.
type index struct {
	component  map[string]int
	instance   map[string]string // instance ID -> owning component ID
	connection map[string]int
	iface      map[string][]string // interface ID -> components listing it, in input order
}

func (it *Item) buildIndex() {
	ix := index{
		component:  map[string]int{},
		instance:   map[string]string{},
		connection: map[string]int{},
		iface:      map[string][]string{},
	}
	for i, c := range it.Components {
		if _, dup := ix.component[c.ComponentID]; !dup {
			ix.component[c.ComponentID] = i
		}
		for _, in := range c.Instances {
			if _, dup := ix.instance[in.InstanceID]; !dup {
				ix.instance[in.InstanceID] = c.ComponentID
			}
		}
		for _, f := range c.Interfaces {
			ix.iface[f] = append(ix.iface[f], c.ComponentID)
		}
	}
	for i, c := range it.Connections {
		if _, dup := ix.connection[c.ConnectionID]; !dup {
			ix.connection[c.ConnectionID] = i
		}
	}
	it.idx = ix
}

// HasComponent reports whether id names a component, or is an EXTERNAL_*
// sentinel (D6).
func (it *Item) HasComponent(id string) bool {
	if IsExternal(id) {
		return true
	}
	_, ok := it.idx.component[id]
	return ok
}

// HasInstance reports whether id names an instance of some component.
func (it *Item) HasInstance(id string) bool {
	_, ok := it.idx.instance[id]
	return ok
}

// HasInterface reports whether any component lists id in its interfaces.
// Interfaces have no separate definition list; the union of the per-component
// lists is the set of defined interfaces.
func (it *Item) HasInterface(id string) bool {
	_, ok := it.idx.iface[id]
	return ok
}

// HasConnection reports whether id names a connection.
func (it *Item) HasConnection(id string) bool {
	_, ok := it.idx.connection[id]
	return ok
}

// Component returns the component with id (first occurrence), or nil.
// EXTERNAL_* sentinels have no component and return nil.
func (it *Item) Component(id string) *Component {
	if i, ok := it.idx.component[id]; ok {
		return &it.Components[i]
	}
	return nil
}

// Connection returns the connection with id (first occurrence), or nil.
func (it *Item) Connection(id string) *Connection {
	if i, ok := it.idx.connection[id]; ok {
		return &it.Connections[i]
	}
	return nil
}

// Pointer builds an RFC 6901 JSON Pointer from tokens (strings or ints).
func Pointer(tokens ...any) string {
	var b strings.Builder
	for _, t := range tokens {
		b.WriteByte('/')
		b.WriteString(pointerEscaper.Replace(fmt.Sprint(t)))
	}
	return b.String()
}

var pointerEscaper = strings.NewReplacer("~", "~0", "/", "~1")
