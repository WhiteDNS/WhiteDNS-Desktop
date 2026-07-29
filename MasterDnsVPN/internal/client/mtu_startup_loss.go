package client

import (
	"context"
	"time"
)

type mtuProbeAxis uint8

const (
	mtuProbeAxisUpload mtuProbeAxis = iota
	mtuProbeAxisDownload
)

const (
	postConnectStartupLossDelay        = 10 * time.Second
	postConnectStartupLossResolverCap  = 6
	postConnectStartupLossSampleCap    = 2
	postConnectStartupLossCandidateCap = 3
	postConnectStartupLossProbeGap     = 150 * time.Millisecond
)

type startupMTULossOptions struct {
	Delay          time.Duration
	ActiveLimit    int
	MaxSamples     int
	MaxCandidates  int
	InterProbeGap  time.Duration
	LowerOnly      bool
	PostConnectLog bool
}

type mtuLossProbeStats struct {
	Sent   int
	Lost   int
	RTTSum time.Duration
}

func (s mtuLossProbeStats) Successes() int {
	successes := s.Sent - s.Lost
	if successes < 0 {
		return 0
	}
	return successes
}

func (s *mtuLossProbeStats) Add(other mtuLossProbeStats) {
	s.Sent += other.Sent
	s.Lost += other.Lost
	s.RTTSum += other.RTTSum
}

type mtuStartupLossCandidateResult struct {
	Value      int
	ByResolver map[string]mtuLossProbeStats
	Total      mtuLossProbeStats
	Healthy    int
}

func (c *Client) startPostConnectStartupMTULossVerification(ctx context.Context) {
	if c == nil || !c.cfg.MTUStartupLossVerifyEnabled || c.scannerInputPath != "" || c.mtuStartupLossDone.Load() {
		if c != nil && c.scannerInputPath != "" {
			c.debugf("post-connect MTU loss calibration skipped during connected scanner mode")
		}
		return
	}
	if !c.mtuStartupLossRunning.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer c.mtuStartupLossRunning.Store(false)
		if c.runPostConnectStartupMTULossVerification(ctx) {
			c.mtuStartupLossDone.Store(true)
		}
	}()
}

func (c *Client) runPostConnectStartupMTULossVerification(ctx context.Context) bool {
	return c.runStartupMTULossVerificationWithOptions(ctx, startupMTULossOptions{
		Delay:          postConnectStartupLossDelay,
		ActiveLimit:    postConnectStartupLossResolverCap,
		MaxSamples:     postConnectStartupLossSampleCap,
		MaxCandidates:  postConnectStartupLossCandidateCap,
		InterProbeGap:  postConnectStartupLossProbeGap,
		LowerOnly:      true,
		PostConnectLog: true,
	})
}

func (c *Client) runStartupMTULossVerification(ctx context.Context) bool {
	return c.runStartupMTULossVerificationWithOptions(ctx, startupMTULossOptions{})
}

func (c *Client) runStartupMTULossVerificationWithOptions(ctx context.Context, opts startupMTULossOptions) bool {
	if c == nil || c.balancer == nil || !c.cfg.MTUStartupLossVerifyEnabled {
		if c != nil {
			c.debugf("startup MTU loss calibration skipped: enabled=%t", c.cfg.MTUStartupLossVerifyEnabled)
		}
		return true
	}
	if err := ctx.Err(); err != nil {
		return false
	}

	if opts.Delay > 0 {
		if c.log != nil && opts.PostConnectLog {
			c.log.Infof("<cyan>[MTU Loss]</cyan> Post-connect calibration scheduled in %s", opts.Delay)
		}
		if !sleepWithContext(ctx, opts.Delay) {
			c.debugf("startup MTU loss calibration cancelled before delayed start")
			return false
		}
	}

	mtuState := c.mtuStateSnapshot()
	if mtuState.UploadMTU <= 0 || mtuState.DownloadMTU <= 0 {
		c.debugf(
			"startup MTU loss calibration skipped: invalid synced MTU upload=%d download=%d",
			mtuState.UploadMTU,
			mtuState.DownloadMTU,
		)
		return true
	}

	active := c.startupLossActiveConnections(opts.ActiveLimit)
	if len(active) == 0 {
		c.debugf("startup MTU loss calibration skipped: no active resolvers")
		return true
	}

	samples := clampInt(c.cfg.MTUStartupLossVerifySamples, 1, 30)
	candidateCount := clampInt(c.cfg.MTUStartupLossVerifyCandidates, 1, 16)
	if opts.MaxSamples > 0 && samples > opts.MaxSamples {
		samples = opts.MaxSamples
	}
	if opts.MaxCandidates > 0 && candidateCount > opts.MaxCandidates {
		candidateCount = opts.MaxCandidates
	}
	maxLossPercent := clampInt(c.cfg.MTUStartupLossVerifyMaxLossPercent, 0, 100)
	healthyTarget := c.initialMTUEarlyStartTarget(len(active))

	if c.log != nil {
		if opts.PostConnectLog {
			c.log.Infof(
				"<cyan>[MTU Loss]</cyan> Post-connect calibration started: resolvers=%d samples=%d max_loss=%d%%",
				len(active),
				samples,
				maxLossPercent,
			)
		} else {
			c.log.Infof(
				"<cyan>[MTU Loss]</cyan> Startup calibration: resolvers=%d samples=%d max_loss=%d%%",
				len(active),
				samples,
				maxLossPercent,
			)
		}
	}
	c.debugf(
		"startup MTU loss calibration starting: post_connect=%t active=%s synced_upload=%d synced_download=%d samples=%d candidates=%d max_loss=%d healthy_target=%d lower_only=%t",
		opts.PostConnectLog,
		debugConnectionSummary(active, 8),
		mtuState.UploadMTU,
		mtuState.DownloadMTU,
		samples,
		candidateCount,
		maxLossPercent,
		healthyTarget,
		opts.LowerOnly,
	)

	uploadCandidates := startupMTUCandidates(mtuState.UploadMTU, max(c.cfg.MinUploadMTU, minUploadMTUFloor), candidateCount)
	selectedUpload, uploadResult, uploadOK := c.selectStartupLossMTU(
		ctx,
		active,
		mtuProbeAxisUpload,
		uploadCandidates,
		mtuState.UploadMTU,
		samples,
		maxLossPercent,
		healthyTarget,
		opts.InterProbeGap,
	)
	if err := ctx.Err(); err != nil {
		return false
	}
	if !uploadOK {
		c.debugf("startup MTU loss upload fallback: selected current upload=%d", mtuState.UploadMTU)
		selectedUpload = mtuState.UploadMTU
	}

	downloadCandidates := startupMTUCandidates(mtuState.DownloadMTU, max(c.cfg.MinDownloadMTU, minDownloadMTUFloor), candidateCount)
	selectedDownload, downloadResult, downloadOK := c.selectStartupLossMTU(
		ctx,
		active,
		mtuProbeAxisDownload,
		downloadCandidates,
		selectedUpload,
		samples,
		maxLossPercent,
		healthyTarget,
		opts.InterProbeGap,
	)
	if err := ctx.Err(); err != nil {
		return false
	}
	if !downloadOK {
		c.debugf("startup MTU loss download fallback: selected current download=%d", mtuState.DownloadMTU)
		selectedDownload = mtuState.DownloadMTU
	}

	applyState := c.mtuStateSnapshot()
	if opts.LowerOnly {
		selectedUpload = min(selectedUpload, applyState.UploadMTU)
		selectedDownload = min(selectedDownload, applyState.DownloadMTU)
	}
	if selectedUpload != applyState.UploadMTU || selectedDownload != applyState.DownloadMTU {
		c.applySyncedMTUState(selectedUpload, selectedDownload, c.encodedCharsForPayload(selectedUpload))
		if opts.LowerOnly {
			c.capBalancerConnectionMTUs(selectedUpload, selectedDownload)
			c.capActiveStreamUploadMTUs(selectedUpload)
		}
		if c.log != nil {
			if opts.PostConnectLog {
				c.log.Infof(
					"<green>[MTU Loss]</green> Post-connect calibrated synced MTU: upload=%d download=%d",
					selectedUpload,
					selectedDownload,
				)
			} else {
				c.log.Infof(
					"<green>[MTU Loss]</green> Startup calibrated synced MTU: upload=%d download=%d",
					selectedUpload,
					selectedDownload,
				)
			}
		}
	}

	if uploadOK || downloadOK {
		c.seedStartupLossBalancerStats(uploadResult, downloadResult)
	}
	c.debugf(
		"startup MTU loss calibration finished: upload_ok=%t download_ok=%t selected_upload=%d selected_download=%d active=%d",
		uploadOK,
		downloadOK,
		selectedUpload,
		selectedDownload,
		len(c.balancer.ActiveConnections()),
	)
	return true
}

func (c *Client) startupLossActiveConnections(limit int) []Connection {
	if c == nil || c.balancer == nil {
		return nil
	}
	if limit > 0 {
		if selected := c.balancer.GetUniqueConnections(limit); len(selected) > 0 {
			return selected
		}
	}
	active := c.balancer.ActiveConnections()
	if limit > 0 && len(active) > limit {
		return active[:limit]
	}
	return active
}

func (c *Client) capBalancerConnectionMTUs(maxUpload int, maxDownload int) {
	if c == nil || c.balancer == nil || maxUpload <= 0 || maxDownload <= 0 {
		return
	}
	for _, conn := range c.balancer.AllConnections() {
		if conn.Key == "" {
			continue
		}
		upload := conn.UploadMTUBytes
		download := conn.DownloadMTUBytes
		if upload <= 0 || upload > maxUpload {
			upload = maxUpload
		}
		if download <= 0 || download > maxDownload {
			download = maxDownload
		}
		uploadChars := conn.UploadMTUChars
		if uploadChars <= 0 || upload < conn.UploadMTUBytes {
			uploadChars = c.encodedCharsForPayload(upload)
		}
		_ = c.balancer.SetConnectionMTU(conn.Key, upload, uploadChars, download)
	}
}

func (c *Client) capActiveStreamUploadMTUs(maxUpload int) {
	if c == nil || maxUpload <= 0 {
		return
	}
	c.streamsMu.RLock()
	streams := make([]*Stream_client, 0, len(c.active_streams))
	for _, stream := range c.active_streams {
		if stream != nil {
			streams = append(streams, stream)
		}
	}
	c.streamsMu.RUnlock()
	for _, stream := range streams {
		stream.CapUploadMTU(maxUpload)
	}
}

func sleepWithContext(ctx context.Context, delay time.Duration) bool {
	if delay <= 0 {
		return true
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func startupMTUCandidates(current int, minValue int, count int) []int {
	if current <= 0 {
		return nil
	}
	if minValue <= 0 || minValue > current {
		minValue = current
	}
	if count < 1 {
		count = 1
	}
	if count == 1 || minValue == current {
		return []int{current}
	}

	out := make([]int, 0, count)
	span := current - minValue
	last := -1
	for i := 0; i < count; i++ {
		value := current - (span*i)/(count-1)
		if value < minValue {
			value = minValue
		}
		if value == last {
			continue
		}
		out = append(out, value)
		last = value
	}
	return out
}

func (c *Client) selectStartupLossMTU(
	ctx context.Context,
	connections []Connection,
	axis mtuProbeAxis,
	candidates []int,
	uploadMTU int,
	samples int,
	maxLossPercent int,
	healthyTarget int,
	interProbeGap time.Duration,
) (int, mtuStartupLossCandidateResult, bool) {
	for _, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			return 0, mtuStartupLossCandidateResult{}, false
		}
		result := c.evaluateStartupLossCandidate(ctx, connections, axis, candidate, uploadMTU, samples, maxLossPercent, interProbeGap)
		c.logStartupLossCandidate(axis, result, maxLossPercent, healthyTarget)
		if startupLossCandidateReliable(result, maxLossPercent, healthyTarget) {
			return candidate, result, true
		}
	}
	return 0, mtuStartupLossCandidateResult{}, false
}

func (c *Client) evaluateStartupLossCandidate(
	ctx context.Context,
	connections []Connection,
	axis mtuProbeAxis,
	candidate int,
	uploadMTU int,
	samples int,
	maxLossPercent int,
	interProbeGap time.Duration,
) mtuStartupLossCandidateResult {
	result := mtuStartupLossCandidateResult{
		Value:      candidate,
		ByResolver: make(map[string]mtuLossProbeStats, len(connections)),
	}

	for _, conn := range connections {
		if err := ctx.Err(); err != nil {
			return result
		}
		if conn.Key == "" || !conn.IsValid {
			continue
		}
		stats := c.probeStartupMTULossAxis(ctx, conn, axis, candidate, uploadMTU, samples)
		if stats.Sent <= 0 {
			continue
		}
		result.ByResolver[conn.Key] = stats
		result.Total.Add(stats)
		if mtuLossPercent(stats) <= maxLossPercent {
			result.Healthy++
		}
		if interProbeGap > 0 && !sleepWithContext(ctx, interProbeGap) {
			return result
		}
	}
	return result
}

func (c *Client) probeStartupMTULossAxis(ctx context.Context, conn Connection, axis mtuProbeAxis, candidate int, uploadMTU int, samples int) mtuLossProbeStats {
	if c != nil && c.mtuStartupLossProbeFunc != nil {
		return c.mtuStartupLossProbeFunc(ctx, conn, axis, candidate, uploadMTU, samples, c.mtuTestTimeout)
	}

	var stats mtuLossProbeStats
	transport, err := newUDPQueryTransport(conn.ResolverLabel)
	if err != nil {
		stats.Sent = samples
		stats.Lost = samples
		return stats
	}
	defer transport.conn.Close()

	for sample := 0; sample < samples; sample++ {
		if err := ctx.Err(); err != nil {
			return stats
		}
		size := c.startupLossSampleSize(axis, candidate, sample)
		stats.Sent++

		var (
			passed bool
			rtt    time.Duration
		)
		if axis == mtuProbeAxisUpload {
			passed, rtt, err = c.sendUploadMTUProbe(ctx, conn, transport, size, c.mtuTestTimeout, mtuProbeOptions{
				Quiet:   true,
				IsRetry: sample > 0,
			})
		} else {
			passed, rtt, err = c.sendDownloadMTUProbe(ctx, conn, transport, size, uploadMTU, c.mtuTestTimeout, mtuProbeOptions{
				Quiet:   true,
				IsRetry: sample > 0,
			})
		}
		if err != nil || !passed {
			stats.Lost++
			continue
		}
		stats.RTTSum += rtt
	}
	return stats
}

func (c *Client) startupLossSampleSize(axis mtuProbeAxis, candidate int, sample int) int {
	if candidate <= 0 || sample == 0 {
		return candidate
	}

	floor := minUploadMTUFloor
	if axis == mtuProbeAxisDownload {
		floor = minDownloadMTUFloor
	}

	span := candidate / 8
	if span < 1 {
		span = 1
	}
	low := candidate - span
	if low < floor {
		low = floor
	}
	if low >= candidate {
		return candidate
	}

	seed := int(c.mtuProbeCounter.Add(1)) + sample*1103515245 + candidate*2654435761
	if seed < 0 {
		seed = -seed
	}
	return low + seed%(candidate-low+1)
}

func startupLossCandidateReliable(result mtuStartupLossCandidateResult, maxLossPercent int, healthyTarget int) bool {
	if result.Total.Sent <= 0 {
		return false
	}
	if healthyTarget < 1 {
		healthyTarget = 1
	}
	if result.Healthy < healthyTarget {
		return false
	}
	return mtuLossPercent(result.Total) <= maxLossPercent
}

func mtuLossPercent(stats mtuLossProbeStats) int {
	if stats.Sent <= 0 {
		return 100
	}
	return (stats.Lost*100 + stats.Sent - 1) / stats.Sent
}

func (c *Client) seedStartupLossBalancerStats(uploadResult mtuStartupLossCandidateResult, downloadResult mtuStartupLossCandidateResult) {
	if c == nil || c.balancer == nil {
		return
	}
	keys := make(map[string]struct{}, len(uploadResult.ByResolver)+len(downloadResult.ByResolver))
	for key := range uploadResult.ByResolver {
		keys[key] = struct{}{}
	}
	for key := range downloadResult.ByResolver {
		keys[key] = struct{}{}
	}

	for key := range keys {
		var stats mtuLossProbeStats
		stats.Add(uploadResult.ByResolver[key])
		stats.Add(downloadResult.ByResolver[key])
		c.balancer.SeedResolverStats(key, stats.Sent, stats.Lost, stats.RTTSum, stats.Successes())
	}
	c.debugf("startup MTU loss seeded balancer stats: resolvers=%d upload_candidate=%d download_candidate=%d", len(keys), uploadResult.Value, downloadResult.Value)
}

func (c *Client) logStartupLossCandidate(axis mtuProbeAxis, result mtuStartupLossCandidateResult, maxLossPercent int, healthyTarget int) {
	if c == nil || c.log == nil || result.Total.Sent <= 0 {
		return
	}
	axisName := "upload"
	if axis == mtuProbeAxisDownload {
		axisName = "download"
	}
	c.log.Infof(
		"<cyan>[MTU Loss]</cyan> %s candidate=%d loss=%d%% healthy=%d/%d threshold=%d%%",
		axisName,
		result.Value,
		mtuLossPercent(result.Total),
		result.Healthy,
		healthyTarget,
		maxLossPercent,
	)
	c.debugf(
		"startup MTU loss candidate details: axis=%s candidate=%d sent=%d lost=%d loss=%d healthy=%d healthy_target=%d threshold=%d",
		axisName,
		result.Value,
		result.Total.Sent,
		result.Total.Lost,
		mtuLossPercent(result.Total),
		result.Healthy,
		healthyTarget,
		maxLossPercent,
	)
}

func clampInt(value int, minValue int, maxValue int) int {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}
