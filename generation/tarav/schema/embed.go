// Package schemafiles embeds the versioned item-definition JSON Schemas.
// A released version's file is never edited; changes go into a new version.
package schemafiles

import _ "embed"

// ItemDefinitionV1_0 is item-definition.schema.json, $id …/item-definition/1.0.0.
//
//go:embed item-definition.schema.json
var ItemDefinitionV1_0 []byte

// ItemDefinitionV1_1 is item-definition-1.1.0.schema.json, $id …/item-definition/1.1.0.
//
//go:embed item-definition-1.1.0.schema.json
var ItemDefinitionV1_1 []byte
