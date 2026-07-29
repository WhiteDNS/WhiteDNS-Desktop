package client

import (
	"context"
	"time"
)

const mtuRecheckMinDelta = 2

func (c *Client) startMTURecheckLoop(ctx context.Context) {
	if c == nil || !c.cfg.MTURecheckEnabled || c.cfg.MTURecheckIntervalMinutes <= 0 {
		return
	}
	interval := time.Duration(c.cfg.MTURecheckIntervalMinutes) * time.Minute
	c.mtuRecheckOnce.Do(func() {
		go c.runMTURecheckLoop(ctx, interval)
	})
}

func (c *Client) runMTURecheckLoop(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		return
	}
	timer := time.NewTimer(interval)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			c.runMTURecheckPass(ctx)
			timer.Reset(interval)
		}
	}
}

func (c *Client) runMTURecheckPass(ctx context.Context) bool {
	if c == nil || c.balancer == nil {
		return false
	}
	active := c.balancer.ActiveConnections()
	if len(active) == 0 {
		return false
	}

	uploadCaps := c.precomputeUploadCaps()
	updated := false
	for _, conn := range active {
		if err := ctx.Err(); err != nil {
			return updated
		}
		if conn.Key == "" || !conn.IsValid {
			continue
		}
		result, reason := c.runMTUProbe(ctx, conn, uploadCaps[conn.Domain])
		if reason != mtuRejectNone {
			continue
		}
		if absInt(result.UploadBytes-conn.UploadMTUBytes) < mtuRecheckMinDelta &&
			absInt(result.DownloadBytes-conn.DownloadMTUBytes) < mtuRecheckMinDelta {
			continue
		}
		uploadChars := result.UploadChars
		if uploadChars <= 0 {
			uploadChars = c.encodedCharsForPayload(result.UploadBytes)
		}
		if c.balancer.SetConnectionMTU(conn.Key, result.UploadBytes, uploadChars, result.DownloadBytes) {
			updated = true
			if c.log != nil {
				c.log.Infof(
					"<cyan>[MTU Recheck]</cyan> Updated %s: upload=%d download=%d",
					conn.ResolverLabel,
					result.UploadBytes,
					result.DownloadBytes,
				)
			}
		}
	}

	if !updated {
		return false
	}

	active = c.balancer.ActiveConnections()
	valid, minUpload, minDownload, minUploadChars := summarizeValidMTUConnections(active)
	if len(valid) == 0 || minUpload <= 0 || minDownload <= 0 {
		return true
	}
	current := c.mtuStateSnapshot()
	if current.UploadMTU != minUpload || current.DownloadMTU != minDownload || current.UploadChars != minUploadChars {
		c.applySyncedMTUState(minUpload, minDownload, minUploadChars)
	}
	return true
}

func absInt(value int) int {
	if value < 0 {
		return -value
	}
	return value
}
