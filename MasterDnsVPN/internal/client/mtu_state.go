package client

import (
	fragmentStore "masterdnsvpn-go/internal/fragmentstore"
	"masterdnsvpn-go/internal/mlq"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

type mtuStateSnapshot struct {
	UploadMTU       int
	DownloadMTU     int
	UploadChars     int
	SafeUploadMTU   int
	MaxPackedBlocks int
}

func (c *Client) mtuStateSnapshot() mtuStateSnapshot {
	if c == nil {
		return mtuStateSnapshot{}
	}
	c.mtuStateMu.RLock()
	defer c.mtuStateMu.RUnlock()
	return mtuStateSnapshot{
		UploadMTU:       c.syncedUploadMTU,
		DownloadMTU:     c.syncedDownloadMTU,
		UploadChars:     c.syncedUploadChars,
		SafeUploadMTU:   c.safeUploadMTU,
		MaxPackedBlocks: c.maxPackedBlocks,
	}
}

func (c *Client) setSyncedMTUState(uploadMTU int, downloadMTU int, uploadChars int) mtuStateSnapshot {
	if c == nil {
		return mtuStateSnapshot{}
	}
	snapshot := mtuStateSnapshot{
		UploadMTU:       uploadMTU,
		DownloadMTU:     downloadMTU,
		UploadChars:     uploadChars,
		SafeUploadMTU:   computeSafeUploadMTU(uploadMTU, c.mtuCryptoOverhead),
		MaxPackedBlocks: VpnProto.CalculateMaxPackedBlocks(uploadMTU, 80, c.cfg.MaxPacketsPerBatch),
	}
	if snapshot.MaxPackedBlocks < 1 {
		snapshot.MaxPackedBlocks = 1
	}

	c.mtuStateMu.Lock()
	c.syncedUploadMTU = snapshot.UploadMTU
	c.syncedDownloadMTU = snapshot.DownloadMTU
	c.syncedUploadChars = snapshot.UploadChars
	c.safeUploadMTU = snapshot.SafeUploadMTU
	c.maxPackedBlocks = snapshot.MaxPackedBlocks
	c.mtuStateMu.Unlock()
	return snapshot
}

func (c *Client) effectiveGroupUploadMTU(connections []Connection) int {
	minUpload := 0
	for _, conn := range connections {
		if conn.UploadMTUBytes <= 0 {
			continue
		}
		minUpload = minPositive(minUpload, conn.UploadMTUBytes)
	}
	if minUpload > 0 {
		return minUpload
	}
	return c.mtuStateSnapshot().UploadMTU
}

func (c *Client) syncSessionPolicyDerivedState() {
	if c == nil {
		return
	}

	c.mtuStateMu.Lock()
	if c.syncedUploadMTU > 0 {
		c.syncedUploadMTU = min(c.syncedUploadMTU, c.cfg.MaxUploadMTU)
		c.syncedUploadChars = c.encodedCharsForPayload(c.syncedUploadMTU)
		c.safeUploadMTU = computeSafeUploadMTU(c.syncedUploadMTU, c.mtuCryptoOverhead)
		c.maxPackedBlocks = VpnProto.CalculateMaxPackedBlocks(c.syncedUploadMTU, 80, c.cfg.MaxPacketsPerBatch)
		if c.maxPackedBlocks < 1 {
			c.maxPackedBlocks = 1
		}
	} else {
		c.syncedUploadChars = 0
		c.safeUploadMTU = 0
		c.maxPackedBlocks = 1
	}

	if c.syncedDownloadMTU > 0 {
		c.syncedDownloadMTU = min(c.syncedDownloadMTU, c.cfg.MaxDownloadMTU)
	}
	c.mtuStateMu.Unlock()

	c.applySessionCompressionPolicy()

	c.closeResolverConnPools()

	if c.asyncCancel != nil {
		return
	}

	c.plannerQueue = make(chan plannerTask, max(24, c.cfg.RX_TX_Workers*24))
	c.encodedTXChannel = make(chan writerTask, max(24, c.cfg.RX_TX_Workers*24))
	c.rxChannel = make(chan asyncReadPacket, c.cfg.EffectiveRXChannelSize())
	c.orphanQueue = mlq.New[VpnProto.Packet](c.cfg.EffectiveOrphanQueueInitialCapacity())
	c.dnsResponses = fragmentStore.New[dnsFragmentKey](c.cfg.EffectiveDNSResponseFragmentStoreCap())
}
