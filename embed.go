// Package aidefensekit exposes the rule data compiled into the binary.
package aidefensekit

import "embed"

// Data holds the built-in rules, explanations and fix guides.
//
//go:embed rules explain fixes mappings
var Data embed.FS
