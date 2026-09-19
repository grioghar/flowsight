// Package web embeds the static UI so the binary is self-contained.
package web

import "embed"

//go:embed static
var Files embed.FS
