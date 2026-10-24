// Package server embeds isolated CottenDNS accounts behind a caller-owned DNS
// router. It does not bind ports, read key files or change system configuration.
package server

import "cottendns-go/internal/udpserver"

type Config = udpserver.EmbeddedConfig
type Server = udpserver.Embedded

var New = udpserver.NewEmbedded
