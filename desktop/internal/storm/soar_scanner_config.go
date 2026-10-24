package storm

import (
	"strings"

	"whitedns-desktop/internal/model"
)

// The pinned Soar helper limits explicit resolver scanning to eight workers.
const MaxSoarScannerParallel = 8

func RenderSoarScannerConfig(connection model.ConnectionProfile, parallel int) (string, error) {
	if err := model.ValidateSoarProfile(connection); err != nil {
		return "", err
	}
	options := model.DefaultSoarSettings()
	if connection.SoarSettings != nil {
		options = *connection.SoarSettings
	}
	// A different discovery candidate must never validate the resolver under test.
	options.Discovery = false
	options.DiscoveryConcurrency = max(1, min(parallel, MaxSoarScannerParallel))
	connection.SoarSettings = &options
	connection.Domain = model.ConnectionDomains(connection)[0]
	connection.EncryptionKey = strings.TrimSpace(connection.EncryptionKey)
	runtime := model.DefaultSoarSettingsProfile()
	runtime.ListenIP = "127.0.0.1"
	runtime.ListenPort = 10886 // Required by validation; scan-only does not bind it.
	runtime.SOCKS5Authentication = false
	return renderSoarConfig(connection, runtime)
}
