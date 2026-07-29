// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
// Package client provides the core logic for the MasterDnsVPN client.
// This file (session.go) handles session states and initialization requests.
// ==============================================================================
package client

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"masterdnsvpn-go/internal/compression"
	Enums "masterdnsvpn-go/internal/enums"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

var (
	ErrSessionInitFailed = errors.New("session init failed")
	ErrSessionInitBusy   = errors.New("session init busy: server is at capacity or rejected the request")
)

const (
	sessionInitPayloadSize      = 10
	sessionAcceptPayloadSize    = VpnProto.SessionAcceptPayloadSize
	sessionBusyPayloadSize      = 4
	sessionCloseBurstMaxTargets = 10
	sessionCloseBurstRounds     = 3
)

func (c *Client) InitializeSession(maxAttempts int) error {
	mtuState := c.mtuStateSnapshot()
	if mtuState.UploadMTU <= 0 || mtuState.DownloadMTU <= 0 {
		return ErrSessionInitFailed
	}

	if maxAttempts < 1 {
		maxAttempts = 1
	}
	c.debugf(
		"session initialization starting: max_attempts=%d racing_count_config=%d synced_upload=%d synced_download=%d active_resolvers=%d",
		maxAttempts,
		c.cfg.SessionInitRacingCount,
		mtuState.UploadMTU,
		mtuState.DownloadMTU,
		len(c.balancer.ActiveConnections()),
	)

	for attempt := 0; attempt < maxAttempts; attempt++ {
		c.debugf("session initialization attempt: attempt=%d/%d", attempt+1, maxAttempts)
		if err := c.initializeSessionRequest(); err == nil {
			return nil
		} else if errors.Is(err, ErrNoValidConnections) || errors.Is(err, ErrSessionInitBusy) {
			c.debugf("session initialization stopped early: attempt=%d err=%v", attempt+1, err)
			return err
		} else {
			c.debugf("session initialization attempt failed: attempt=%d err=%v", attempt+1, err)
		}
	}

	return ErrSessionInitFailed
}

func (c *Client) initializeSessionRequest() error {
	conn, initPayload, verifyCode, err := c.nextSessionInitAttempt()
	if err != nil {
		return err
	}

	c.log.Infof("<green>Session init attempt with <cyan>%s</cyan> and resolver <cyan>%s</cyan>", conn.Domain, conn.Resolver)
	c.debugf(
		"session init selected resolver: resolver=%s domain=%s up=%d down=%d upload_chars=%d valid=%t",
		conn.ResolverLabel,
		conn.Domain,
		conn.UploadMTUBytes,
		conn.DownloadMTUBytes,
		conn.UploadMTUChars,
		conn.IsValid,
	)

	query, err := c.buildSessionQuery(conn.Domain, Enums.PACKET_SESSION_INIT, initPayload)
	if err != nil {
		return ErrSessionInitFailed
	}

	// Intra-Resolver Racing: Send 3 parallel requests to the same selected resolver.
	// We staggered each attempt by 100ms.
	const racingCount = 3
	const staggerDelay = 100 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	type result struct {
		err    error
		packet VpnProto.Packet
	}

	resChan := make(chan result, racingCount)

	for i := range racingCount {
		if i > 0 {
			select {
			case <-time.After(staggerDelay):
			case <-ctx.Done():
				goto waitPhase
			}
		}

		go func() {
			packet, err := c.exchangeDNSOverConnection(conn, query, c.mtuTestTimeout*3)
			select {
			case resChan <- result{err: err, packet: packet}:
			case <-ctx.Done():
			}
		}()
	}

waitPhase:
	var lastErr error
	responsesReceived := 0
	for {
		select {
		case res := <-resChan:
			responsesReceived++
			if res.err == nil {
				if err := c.applySessionInitPacket(res.packet, initPayload, verifyCode); err == nil {
					c.debugf("session init response accepted: responses_received=%d packet_type=%s", responsesReceived, Enums.PacketTypeName(res.packet.PacketType))
					cancel()
					return nil
				} else if errors.Is(err, ErrSessionInitBusy) {
					c.debugf("session init response busy: responses_received=%d packet_type=%s", responsesReceived, Enums.PacketTypeName(res.packet.PacketType))
					cancel()
					return err
				}
				lastErr = res.err
			} else {
				lastErr = res.err
				c.debugf("session init DNS exchange failed: responses_received=%d err=%v", responsesReceived, res.err)
			}

			if responsesReceived >= racingCount {
				if lastErr == nil {
					return ErrSessionInitFailed
				}
				return lastErr
			}
		case <-time.After(30 * time.Second): // Hard safety timeout
			c.debugf("session init hard timeout: resolver=%s domain=%s responses_received=%d", conn.ResolverLabel, conn.Domain, responsesReceived)
			return ErrSessionInitFailed
		}
	}
}

func (c *Client) applySessionInitPacket(packet VpnProto.Packet, initPayload []byte, verifyCode [4]byte) error {
	if c.SessionReady() {
		return nil
	}

	switch packet.PacketType {
	case Enums.PACKET_SESSION_BUSY:
		if len(packet.Payload) < sessionBusyPayloadSize || !bytes.Equal(packet.Payload[:sessionBusyPayloadSize], verifyCode[:]) {
			return ErrSessionInitFailed
		}
		c.setSessionInitBusyUntil(time.Now().Add(c.cfg.SessionInitBusyRetryInterval()))
		return ErrSessionInitBusy
	case Enums.PACKET_SESSION_ACCEPT:
		sessionAccept, err := VpnProto.DecodeSessionAcceptPayload(packet.Payload)
		if err != nil || !bytes.Equal(sessionAccept.VerifyCode[:], verifyCode[:]) {
			return ErrSessionInitFailed
		}

		c.initStateMu.Lock()
		defer c.initStateMu.Unlock()

		if c.sessionReady {
			return nil
		}

		c.sessionID = sessionAccept.SessionID
		c.sessionCookie = sessionAccept.SessionCookie
		c.responseMode = initPayload[0]
		c.uploadCompression, c.downloadCompression = compression.SplitPair(sessionAccept.CompressionPair)
		if sessionAccept.HasClientPolicySync {
			c.applySessionClientPolicy(sessionAccept.ClientPolicy)
		}
		c.sessionReady = true
		c.applySessionCompressionPolicy()
		c.clearSessionInitBusyUntil()
		c.resetSessionInitStateLocked()
		c.clearSessionResetPending()
		return nil
	default:
		return ErrSessionInitFailed
	}
}

func (c *Client) applySessionClientPolicy(policy VpnProto.SessionAcceptClientPolicy) {
	if c == nil {
		return
	}

	before := VpnProto.SessionAcceptClientSettings{
		PacketDuplicationCount:      c.cfg.PacketDuplicationCount,
		SetupPacketDuplicationCount: c.cfg.SetupPacketDuplicationCount,
		MaxUploadMTU:                c.cfg.MaxUploadMTU,
		MaxDownloadMTU:              c.cfg.MaxDownloadMTU,
		RXTXWorkers:                 c.cfg.RX_TX_Workers,
		PingAggressiveInterval:      c.cfg.PingAggressiveIntervalSeconds,
		MaxPacketsPerBatch:          c.cfg.MaxPacketsPerBatch,
		ARQWindowSize:               c.cfg.ARQWindowSize,
		ARQDataNackMaxGap:           c.cfg.ARQDataNackMaxGap,
		CompressionMinSize:          c.cfg.CompressionMinSize,
		ARQInitialRTOSeconds:        c.cfg.ARQInitialRTOSeconds,
		ARQControlInitialRTOSeconds: c.cfg.ARQControlInitialRTOSeconds,
		ARQMaxRTOSeconds:            c.cfg.ARQMaxRTOSeconds,
		ARQControlMaxRTOSeconds:     c.cfg.ARQControlMaxRTOSeconds,
	}

	settings := VpnProto.ApplySessionAcceptClientPolicy(VpnProto.SessionAcceptClientSettings{
		PacketDuplicationCount:      before.PacketDuplicationCount,
		SetupPacketDuplicationCount: before.SetupPacketDuplicationCount,
		MaxUploadMTU:                before.MaxUploadMTU,
		MaxDownloadMTU:              before.MaxDownloadMTU,
		RXTXWorkers:                 before.RXTXWorkers,
		PingAggressiveInterval:      before.PingAggressiveInterval,
		MaxPacketsPerBatch:          before.MaxPacketsPerBatch,
		ARQWindowSize:               before.ARQWindowSize,
		ARQDataNackMaxGap:           before.ARQDataNackMaxGap,
		CompressionMinSize:          before.CompressionMinSize,
		ARQInitialRTOSeconds:        before.ARQInitialRTOSeconds,
		ARQControlInitialRTOSeconds: before.ARQControlInitialRTOSeconds,
		ARQMaxRTOSeconds:            before.ARQMaxRTOSeconds,
		ARQControlMaxRTOSeconds:     before.ARQControlMaxRTOSeconds,
	}, policy)

	c.cfg.PacketDuplicationCount = settings.PacketDuplicationCount
	c.cfg.SetupPacketDuplicationCount = settings.SetupPacketDuplicationCount
	c.cfg.MaxUploadMTU = settings.MaxUploadMTU
	c.cfg.MaxDownloadMTU = settings.MaxDownloadMTU
	c.cfg.RX_TX_Workers = settings.RXTXWorkers
	c.tunnelRX_TX_Workers = settings.RXTXWorkers
	c.cfg.PingAggressiveIntervalSeconds = settings.PingAggressiveInterval
	c.cfg.MaxPacketsPerBatch = settings.MaxPacketsPerBatch
	c.cfg.ARQWindowSize = settings.ARQWindowSize
	c.cfg.ARQDataNackMaxGap = settings.ARQDataNackMaxGap
	c.cfg.CompressionMinSize = settings.CompressionMinSize
	c.cfg.ARQInitialRTOSeconds = settings.ARQInitialRTOSeconds
	c.cfg.ARQControlInitialRTOSeconds = settings.ARQControlInitialRTOSeconds
	c.cfg.TunnelProcessWorkers = deriveSessionPolicyTunnelProcessWorkers(c.cfg.TunnelProcessWorkers, c.cfg.RX_TX_Workers)
	c.tunnelProcessWorkers = c.cfg.TunnelProcessWorkers

	c.syncSessionPolicyDerivedState()

	c.logSessionClientPolicyChanges(before, settings, policy)
}

func deriveSessionPolicyTunnelProcessWorkers(current int, rxWorkers int) int {
	if rxWorkers < 1 {
		rxWorkers = 1
	}

	recommended := max(4, rxWorkers+1)
	if recommended > 256 {
		recommended = 256
	}

	if current < recommended {
		current = recommended
	}

	if current < rxWorkers {
		return rxWorkers
	}

	if current > 256 {
		return 256
	}
	return current
}

func (c *Client) logSessionClientPolicyChanges(before VpnProto.SessionAcceptClientSettings, after VpnProto.SessionAcceptClientSettings, policy VpnProto.SessionAcceptClientPolicy) {
	if c == nil || c.log == nil {
		return
	}

	logInt := func(label string, oldValue int, newValue int, accepted string) {
		if oldValue == newValue {
			return
		}
		c.log.Warnf(
			"<yellow>Session policy adjusted %s because this server does not accept the requested value</yellow> <magenta>|</magenta> <blue>Requested</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Effective</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Server Rule</blue>: <cyan>%s</cyan>",
			label,
			oldValue,
			newValue,
			accepted,
		)
	}

	logFloat := func(label string, oldValue float64, newValue float64, accepted string) {
		if oldValue == newValue {
			return
		}
		c.log.Warnf(
			"<yellow>Session policy adjusted %s because this server does not accept the requested value</yellow> <magenta>|</magenta> <blue>Requested</blue>: <cyan>%.3f</cyan> <magenta>|</magenta> <blue>Effective</blue>: <cyan>%.3f</cyan> <magenta>|</magenta> <blue>Server Rule</blue>: <cyan>%s</cyan>",
			label,
			oldValue,
			newValue,
			accepted,
		)
	}

	logInt("PACKET_DUPLICATION_COUNT", before.PacketDuplicationCount, after.PacketDuplicationCount, "max="+itoaSafe(policy.MaxPacketDuplicationCount))
	logInt("SETUP_PACKET_DUPLICATION_COUNT", before.SetupPacketDuplicationCount, after.SetupPacketDuplicationCount, "max="+itoaSafe(policy.MaxSetupDuplicationCount))
	logInt("MAX_UPLOAD_MTU", before.MaxUploadMTU, after.MaxUploadMTU, "max="+itoaSafe(policy.MaxUploadMTU))
	logInt("MAX_DOWNLOAD_MTU", before.MaxDownloadMTU, after.MaxDownloadMTU, "max="+itoaSafe(policy.MaxDownloadMTU))
	logInt("RX_TX_WORKERS", before.RXTXWorkers, after.RXTXWorkers, "max="+itoaSafe(policy.MaxRxTxWorkers))
	logFloat("PING_AGGRESSIVE_INTERVAL_SECONDS", before.PingAggressiveInterval, after.PingAggressiveInterval, "min="+formatPolicyFloat(policy.MinPingAggressiveInterval))
	logInt("MAX_PACKETS_PER_BATCH", before.MaxPacketsPerBatch, after.MaxPacketsPerBatch, "max="+itoaSafe(policy.MaxPacketsPerBatch))
	logInt("ARQ_WINDOW_SIZE", before.ARQWindowSize, after.ARQWindowSize, "max="+itoaSafe(policy.MaxARQWindowSize))
	logInt("ARQ_DATA_NACK_MAX_GAP", before.ARQDataNackMaxGap, after.ARQDataNackMaxGap, "max="+itoaSafe(policy.MaxARQDataNackMaxGap))
	logInt("COMPRESSION_MIN_SIZE", before.CompressionMinSize, after.CompressionMinSize, "min="+itoaSafe(policy.MinCompressionMinSize))
	logFloat("ARQ_INITIAL_RTO_SECONDS", before.ARQInitialRTOSeconds, after.ARQInitialRTOSeconds, "min="+formatPolicyFloat(policy.MinARQInitialRTOSeconds))
	logFloat("ARQ_CONTROL_INITIAL_RTO_SECONDS", before.ARQControlInitialRTOSeconds, after.ARQControlInitialRTOSeconds, "min="+formatPolicyFloat(policy.MinARQInitialRTOSeconds))
}

func itoaSafe(value int) string {
	return fmt.Sprintf("%d", value)
}

func formatPolicyFloat(value float64) string {
	return fmt.Sprintf("%.3f", value)
}

func (c *Client) buildSessionInitPayload() ([]byte, bool, [4]byte, error) {
	var verifyCode [4]byte
	randomPart, err := randomBytes(len(verifyCode))
	if err != nil {
		return nil, false, verifyCode, err
	}
	copy(verifyCode[:], randomPart)

	payload := make([]byte, sessionInitPayloadSize)
	if c.cfg.BaseEncodeData {
		payload[0] = mtuProbeBase64Reply
	}
	payload[1] = compression.PackPair(c.uploadCompression, c.downloadCompression)
	mtuState := c.mtuStateSnapshot()
	binary.BigEndian.PutUint16(payload[2:4], uint16(mtuState.UploadMTU))
	binary.BigEndian.PutUint16(payload[4:6], uint16(mtuState.DownloadMTU))
	copy(payload[6:10], verifyCode[:])
	return payload, payload[0] == mtuProbeBase64Reply, verifyCode, nil
}

func (c *Client) nextSessionInitAttempt() (Connection, []byte, [4]byte, error) {
	var empty [4]byte
	if c == nil {
		return Connection{}, nil, empty, ErrSessionInitFailed
	}

	c.initStateMu.Lock()
	defer c.initStateMu.Unlock()

	// Persistence Check: reuse existing token/payload if already ready
	if !c.sessionInitReady {
		payload, responseBase64, verifyCode, err := c.buildSessionInitPayload()
		if err != nil {
			return Connection{}, nil, empty, err
		}
		c.sessionInitPayload = payload
		c.sessionInitBase64 = responseBase64
		c.sessionInitVerify = verifyCode
		c.sessionInitReady = true
		c.sessionInitCursor = 0
	}

	candidates := c.sessionInitCandidates(c.balancer.ActiveConnections())
	if len(candidates) == 0 {
		return Connection{}, nil, empty, ErrNoValidConnections
	}

	// Use the cursor to rotate through the best post-MTU candidates first.
	validLen := len(candidates)
	start := c.sessionInitCursor
	for checked := 0; checked < validLen; checked++ {
		idxInValid := (start + checked) % validLen
		conn := candidates[idxInValid]
		if !conn.IsValid || conn.Key == "" {
			continue
		}

		c.sessionInitCursor = (idxInValid + 1) % validLen
		return conn, c.sessionInitPayload, c.sessionInitVerify, nil
	}

	return Connection{}, nil, empty, ErrNoValidConnections
}

func (c *Client) sessionInitCandidates(active []Connection) []Connection {
	candidates := make([]Connection, 0, len(active))
	for _, conn := range active {
		if conn.IsValid && conn.Key != "" {
			candidates = append(candidates, conn)
		}
	}
	if len(candidates) < 2 {
		return candidates
	}

	mtuState := c.mtuStateSnapshot()
	sort.SliceStable(candidates, func(i, j int) bool {
		left := candidates[i]
		right := candidates[j]
		leftCompatible := sessionInitMTUCompatible(left, mtuState)
		rightCompatible := sessionInitMTUCompatible(right, mtuState)
		if leftCompatible != rightCompatible {
			return leftCompatible
		}
		if left.MTUResolveTime > 0 && right.MTUResolveTime > 0 && left.MTUResolveTime != right.MTUResolveTime {
			return left.MTUResolveTime < right.MTUResolveTime
		}
		if (left.MTUResolveTime > 0) != (right.MTUResolveTime > 0) {
			return left.MTUResolveTime > 0
		}
		if left.DownloadMTUBytes != right.DownloadMTUBytes {
			return left.DownloadMTUBytes > right.DownloadMTUBytes
		}
		if left.UploadMTUBytes != right.UploadMTUBytes {
			return left.UploadMTUBytes > right.UploadMTUBytes
		}
		return left.Key < right.Key
	})
	return candidates
}

func sessionInitMTUCompatible(conn Connection, mtuState mtuStateSnapshot) bool {
	if mtuState.UploadMTU > 0 && conn.UploadMTUBytes > 0 && conn.UploadMTUBytes < mtuState.UploadMTU {
		return false
	}
	if mtuState.DownloadMTU > 0 && conn.DownloadMTUBytes > 0 && conn.DownloadMTUBytes < mtuState.DownloadMTU {
		return false
	}
	return conn.UploadMTUBytes > 0 && conn.DownloadMTUBytes > 0
}

func (c *Client) resetSessionInitState() {
	if c == nil {
		return
	}
	c.initStateMu.Lock()
	c.resetSessionInitStateLocked()
	c.initStateMu.Unlock()
}

func (c *Client) resetSessionInitStateLocked() {
	c.sessionInitPayload = nil
	c.sessionInitVerify = [4]byte{}
	c.sessionInitBase64 = false
	c.sessionInitReady = false
	c.sessionInitCursor = 0
}

func (c *Client) setSessionInitBusyUntil(deadline time.Time) {
	if c == nil {
		return
	}
	c.sessionInitBusyUnix.Store(deadline.UnixNano())
}

func (c *Client) clearSessionInitBusyUntil() {
	if c == nil {
		return
	}
	c.sessionInitBusyUnix.Store(0)
}

func (c *Client) sessionInitBusyUntil() time.Time {
	if c == nil {
		return time.Time{}
	}
	unixNano := c.sessionInitBusyUnix.Load()
	if unixNano <= 0 {
		return time.Time{}
	}
	return time.Unix(0, unixNano)
}

func (c *Client) buildSessionQuery(domain string, packetType uint8, payload []byte) ([]byte, error) {
	return c.buildTunnelQuery(domain, 0, packetType, payload)
}

func (c *Client) buildTunnelQuery(domain string, sessionID uint8, packetType uint8, payload []byte) ([]byte, error) {
	return c.buildTunnelTXTQueryRaw(domain, VpnProto.BuildOptions{
		SessionID:  sessionID,
		PacketType: packetType,
		Payload:    payload,
	})
}

func (c *Client) clearSessionResetPending() {
	if c != nil {
		c.sessionResetPending.Store(false)
	}
}

func (c *Client) notifySessionCloseBurst(timeout time.Duration) {
	if c == nil || !c.SessionReady() || c.sessionID == 0 {
		return
	}
	if !c.sessionResetPending.CompareAndSwap(false, true) {
		return
	}

	targets := c.selectSessionCloseTargets(sessionCloseBurstMaxTargets)
	if len(targets) == 0 {
		c.sessionResetPending.Store(false)
		return
	}

	timeout = normalizeTimeout(timeout, time.Second)
	deadline := time.Now().Add(timeout)

	rounds := sessionCloseBurstRounds
	if rounds < 1 {
		rounds = 1
	}
	interval := timeout / time.Duration(rounds)
	if interval <= 0 {
		interval = timeout
	}

	for round := 0; round < rounds; round++ {
		c.sendSessionCloseRound(targets, deadline)
		if round == rounds-1 {
			break
		}

		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		sleepFor := interval
		if sleepFor > remaining {
			sleepFor = remaining
		}
		time.Sleep(sleepFor)
	}

	if c.log != nil {
		c.log.Debugf(
			"\U0001F6AA <yellow>Client Session Close Burst Sent</yellow> <magenta>|</magenta> <blue>Session</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Targets</blue>: <cyan>%d</cyan>",
			c.sessionID,
			len(targets),
		)
	}
}

func (c *Client) selectSessionCloseTargets(maxTargets int) []Connection {
	if c == nil {
		return nil
	}

	if maxTargets < 1 {
		maxTargets = 1
	}

	targets := c.balancer.GetUniqueConnections(maxTargets)
	if len(targets) > 0 {
		return targets
	}

	if best, ok := c.balancer.GetBestConnection(); ok {
		return []Connection{best}
	}
	return nil
}

func (c *Client) sendSessionCloseRound(targets []Connection, deadline time.Time) {
	if c == nil || len(targets) == 0 {
		return
	}

	var wg sync.WaitGroup
	for _, conn := range targets {
		conn := conn
		wg.Add(1)
		go func() {
			defer wg.Done()
			query, err := c.buildTunnelTXTQueryRaw(conn.Domain, VpnProto.BuildOptions{
				SessionID:     c.sessionID,
				SessionCookie: c.sessionCookie,
				PacketType:    Enums.PACKET_SESSION_CLOSE,
			})
			if err != nil {
				return
			}
			c.sendOneWayDNSQuery(conn, query, deadline)
		}()
	}
	wg.Wait()
}

// applySyncedMTUState updates the client's internal MTU state after successful probing.
func (c *Client) applySyncedMTUState(uploadMTU int, downloadMTU int, uploadChars int) {
	if c == nil {
		return
	}
	c.setSyncedMTUState(uploadMTU, downloadMTU, uploadChars)
	c.applySessionCompressionPolicy()
	if c.log != nil && c.successMTUChecks {
		c.log.Infof("\U0001F4CF <green>MTU state applied: UP=%d, DOWN=%d</green>", uploadMTU, downloadMTU)
	}
}

func (c *Client) applySessionCompressionPolicy() {
	if c == nil {
		return
	}

	minSize := c.cfg.CompressionMinSize
	if minSize <= 0 {
		minSize = compression.DefaultMinSize
	}

	uploadCompression := compression.NormalizeAvailableType(c.uploadCompression)
	downloadCompression := compression.NormalizeAvailableType(c.downloadCompression)

	const mtuWarningThreshold = 100
	mtuState := c.mtuStateSnapshot()

	if mtuState.UploadMTU > 0 && mtuState.UploadMTU < mtuWarningThreshold {
		if uploadCompression != compression.TypeOff && c.log != nil {
			c.log.Warnf(
				"⚠️ <red>Session Compression Upload: <cyan>%s</cyan> (Disabled due to low MTU: <cyan>%d</cyan>)</red>",
				compression.TypeName(uploadCompression),
				mtuState.UploadMTU,
			)
		}
		uploadCompression = compression.TypeOff
		c.cfg.UploadCompressionType = int(compression.TypeOff)
	} else if mtuState.UploadMTU > 0 && mtuState.UploadMTU <= minSize {
		if uploadCompression != compression.TypeOff && c.log != nil {
			c.log.Infof(
				"\U0001F5DC <green>Session Compression Upload: <cyan>%s</cyan> (Disabled due to MinSize MTU: <cyan>%d</cyan>)</green>",
				compression.TypeName(uploadCompression),
				mtuState.UploadMTU,
			)
		}
		uploadCompression = compression.TypeOff
	}

	if mtuState.DownloadMTU > 0 && mtuState.DownloadMTU < mtuWarningThreshold {
		if downloadCompression != compression.TypeOff && c.log != nil {
			c.log.Warnf(
				"⚠️ <red>Session Compression Download: <cyan>%s</cyan> (Disabled due to low MTU: <cyan>%d</cyan>)</red>",
				compression.TypeName(downloadCompression),
				mtuState.DownloadMTU,
			)
		}
		downloadCompression = compression.TypeOff
		c.cfg.DownloadCompressionType = int(compression.TypeOff)
	} else if mtuState.DownloadMTU > 0 && mtuState.DownloadMTU <= minSize {
		if downloadCompression != compression.TypeOff && c.log != nil {
			c.log.Infof(
				"\U0001F5DC <green>Session Compression Download: <cyan>%s</cyan> (Disabled due to MinSize MTU: <cyan>%d</cyan>)</green>",
				compression.TypeName(downloadCompression),
				mtuState.DownloadMTU,
			)
		}
		downloadCompression = compression.TypeOff
	}

	c.uploadCompression = uploadCompression
	c.downloadCompression = downloadCompression

	if c.log != nil {
		c.log.Infof(
			"\U0001F9E9 <green>Effective Compression Upload: <cyan>%s</cyan> Download: <cyan>%s</cyan></green>",
			compression.TypeName(c.uploadCompression),
			compression.TypeName(c.downloadCompression),
		)
	}
}
