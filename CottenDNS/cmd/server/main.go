// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"cottendns-go/internal/config"
	"cottendns-go/internal/logger"
	"cottendns-go/internal/runtimepath"
	"cottendns-go/internal/security"
	UDPServer "cottendns-go/internal/udpserver"
	"cottendns-go/internal/version"
)

func waitForExitInput() {
	_, _ = fmt.Fprint(os.Stderr, "Press Enter to exit...")
	reader := bufio.NewReader(os.Stdin)
	_, _ = reader.ReadString('\n')
}

func main() {
	configPath := flag.String("config", "server_config.toml", "Path to server configuration file")
	logPath := flag.String("log", "", "Path to log file (optional)")
	versionFlag := flag.Bool("version", false, "Print version and exit")
	metricsAddress := flag.String("metrics-address", "", "Optional HTTP health/Prometheus listen address (for example 127.0.0.1:9090)")
	configFlags, err := config.NewServerConfigFlagBinder(flag.CommandLine)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Server flag setup failed: %v\n", err)
		os.Exit(2)
	}
	flag.Parse()

	if *versionFlag {
		fmt.Printf("CottenDns Server Version: %s\n", version.GetVersion())
		return
	}

	resolvedConfigPath := runtimepath.Resolve(*configPath)

	cfg, err := config.LoadServerConfigWithOverrides(resolvedConfigPath, configFlags.Overrides())
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Server startup failed: %v\n", err)
		waitForExitInput()
		os.Exit(1)
	}

	var log *logger.Logger
	if *logPath != "" {
		log = logger.NewWithFile("CottenDns Server", cfg.LogLevel, *logPath)
	} else {
		log = logger.New("CottenDns Server", cfg.LogLevel)
	}

	log.Infof("============================================================")
	log.Infof("<cyan>GitHub:</cyan> <yellow>https://github.com/TaJirax/CottenDns</yellow>")
	log.Infof("<cyan>Telegram:</cyan> <yellow>https://t.me/whitedns</yellow>")
	log.Infof("<cyan>Build Version:</cyan> <yellow>%s</yellow>", version.GetVersion())
	log.Infof("============================================================")

	log.Infof("\U0001F680 <magenta>CottenDns Server starting ...</magenta>")

	keyInfo, err := security.EnsureServerEncryptionKey(cfg)
	if err != nil {
		log.Errorf("\u274C <red>Encryption Key Setup Failed</red> <magenta>|</magenta> <cyan>%v</cyan>", err)
		waitForExitInput()
		os.Exit(1)
	}

	codec, err := security.NewCodecFromConfig(cfg, keyInfo.Key)
	if err != nil {
		log.Errorf("\u274C <red>Encryption Codec Setup Failed</red> <magenta>|</magenta> <cyan>%v</cyan>", err)
		waitForExitInput()
		os.Exit(1)
	}

	srv := UDPServer.New(cfg, log, codec)

	// Encryption-method auto-detection: build a codec per method from the shared
	// key so the server adapts to whatever method the client uses, with the
	// configured method tried first. Disabled by ENCRYPTION_AUTO_DETECT=false.
	if cfg.EncryptionAutoDetect {
		autoDetectMethods := security.AutoDetectMethods(cfg.DataEncryptionMethod)
		codecSet, setErr := security.NewCodecSet(autoDetectMethods, keyInfo.Key)
		if setErr != nil {
			log.Errorf("❌ <red>Encryption Codec Set Setup Failed</red> <magenta>|</magenta> <cyan>%v</cyan>", setErr)
			waitForExitInput()
			os.Exit(1)
		}
		preferred := 0
		for i, m := range autoDetectMethods {
			if m == cfg.DataEncryptionMethod {
				preferred = i
				break
			}
		}
		srv.SetCodecSet(codecSet, preferred)
		log.Infof("\U0001F513 <green>Encryption Auto-Detect: <cyan>enabled</cyan> <gray>(%d methods, default tried first)</gray></green>", len(codecSet))
		if cfg.DataEncryptionMethod == 0 {
			log.Warnf("<yellow>DATA_ENCRYPTION_METHOD=0 permits unauthenticated tunnel frames; use method 1 or an AEAD method (3-5) for ingress flood resistance</yellow>")
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *metricsAddress != "" {
		listener, listenErr := net.Listen("tcp", *metricsAddress)
		if listenErr != nil {
			log.Errorf("Metrics listener setup failed: %v", listenErr)
			os.Exit(1)
		}
		log.Infof("Metrics and health listener ready: <cyan>%s</cyan>", listener.Addr())
		go func() {
			if serveErr := srv.ServeMetrics(ctx, listener); serveErr != nil && ctx.Err() == nil {
				log.Errorf("Metrics listener stopped unexpectedly: %v", serveErr)
				stop()
			}
		}()
	}

	log.Infof("\U0001F680 <green>Server Configuration Loaded</green>")
	if len(cfg.Domain) > 0 {
		log.Infof(
			"\U0001F310 <green>Allowed Domains: <cyan>%s</cyan>, Min Label:<cyan>%d</cyan></green>",
			strings.Join(cfg.Domain, ", "),
			cfg.MinVPNLabelLength,
		)
	} else {
		log.Errorf("\u26A0\uFE0F <yellow>No Allowed Domains Configured!</yellow>")
		waitForExitInput()
		os.Exit(1)
	}

	log.Infof(
		"\U0001F510 <green>Encryption Method: <cyan>%s</cyan> <gray>(id=%d)</gray></green>",
		keyInfo.MethodName,
		keyInfo.MethodID,
	)
	if cfg.UseExternalSOCKS5 {
		authMode := "OFF"
		if cfg.SOCKS5Auth {
			authMode = "ON"
		}
		log.Infof(
			"\U0001F9E6 <green>External SOCKS5 Upstream: <cyan>%s:%d</cyan> <magenta>|</magenta> Auth: <cyan>%s</cyan></green>",
			cfg.ForwardIP,
			cfg.ForwardPort,
			authMode,
		)
	}

	if keyInfo.Generated {
		log.Warnf(
			"\U0001F5DD\uFE0F <yellow>Encryption Key Generated, Path: <cyan>%s</cyan></yellow>",
			keyInfo.Path,
		)
	} else {
		log.Infof(
			"\U0001F5C2 <green>Encryption Key Loaded, Path: <cyan>%s</cyan></green>",
			keyInfo.Path,
		)
	}

	// SECURITY: never log the raw key \u2014 logs may be shipped, cached, or shoulder-
	// surfed. Emit only a non-reversible fingerprint so operators can still confirm
	// client and server share the same key.
	log.Infof(
		"\U0001F511 <green>Active Encryption Key Fingerprint: <yellow>%s</yellow> <gray>(sha256; raw key never logged)</gray></green>",
		security.KeyFingerprint(keyInfo.Key),
	)
	log.Debugf("\u25B6\uFE0F <green>Starting UDP Server...</green>")

	if err := srv.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Errorf("\U0001F4A5 <red>Server Stopped Unexpectedly, <cyan>%v</cyan></red>", err)
		os.Exit(1)
	}

	log.Infof("\U0001F6D1 <yellow>Server Stopped</yellow>")
}
