package storm

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"

	"whitedns-desktop/internal/model"
)

// Soar is a separate protocol. MasterDNS encryption and MTU knobs are never
// translated into Soar options; only the common local proxy settings are used.
func renderSoarConfig(connection model.ConnectionProfile, runtime model.SettingsProfile) (string, error) {
	if err := model.ValidateSoarProfile(connection); err != nil {
		return "", err
	}
	options := model.DefaultSoarSettings()
	if connection.SoarSettings != nil {
		options = *connection.SoarSettings
	}
	host := runtime.ListenIP
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return "", fmt.Errorf("the internal Soar listener must use a loopback address")
	}
	cfg := struct {
		Zone     string             `json:"zone"`
		Key      string             `json:"server_public_key"`
		Listen   string             `json:"listen"`
		Username string             `json:"username"`
		Password string             `json:"password"`
		Soar     model.SoarSettings `json:"soar"`
	}{connection.Domain, connection.EncryptionKey, net.JoinHostPort(host, strconv.Itoa(runtime.ListenPort)), runtime.SOCKSUsername, runtime.SOCKSPassword, options}
	if !runtime.SOCKS5Authentication {
		cfg.Username = ""
		cfg.Password = ""
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	return string(raw), err
}
