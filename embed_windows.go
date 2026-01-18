package main

import (
	"embed"
)

//go:embed Aurora/Build/Aurora.dll
var embeddedFiles embed.FS
