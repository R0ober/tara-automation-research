// Package web embeds the viewer page, its script and style, and the pinned
// vendored libraries (SPEC D4) that internal/render inlines into one file.
package web

import "embed"

// FS holds viewer.html, viewer.js, viewer.css and the vendored libraries.
//
//go:embed viewer.html viewer.js viewer.css vendor/cytoscape.min.js vendor/elk.bundled.js
var FS embed.FS

// Vendor lists the vendored scripts in load order.
var Vendor = []string{"vendor/cytoscape.min.js", "vendor/elk.bundled.js"}
