package client

import (
	"context"
	"math"
	"time"
)

func (c *Client) runTrafficStatsReporter(ctx context.Context) {
	interval := c.cfg.StatsReportInterval()
	if interval <= 0 {
		return
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var lastTX, lastRX uint64
	lastTime := time.Now()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			currentTX := c.txTotalBytes.Load()
			currentRX := c.rxTotalBytes.Load()

			elapsed := now.Sub(lastTime).Seconds()
			var uploadBPS, downloadBPS float64
			if elapsed > 0 {
				uploadBPS = float64(currentTX-lastTX) / elapsed
				downloadBPS = float64(currentRX-lastRX) / elapsed
			}

			lastTX = currentTX
			lastRX = currentRX
			lastTime = now

			if c.log != nil {
				c.log.Machinef(
					"WD_STATS upload_bps=%d upload_total=%d download_bps=%d download_total=%d",
					uint64(math.Round(uploadBPS)),
					currentTX,
					uint64(math.Round(downloadBPS)),
					currentRX,
				)
			}
		}
	}
}
