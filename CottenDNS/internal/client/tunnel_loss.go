// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// tunnel_loss.go — real tunnel packet-loss estimate. The per-resolver DNS
// sent/acked ratio (balancer.AggregateLossPerMille) measures whether a DNS reply
// came back at all, which is ~0 on any reachable resolver and therefore useless
// as a tunnel-loss signal. This meter instead derives loss from the upload
// retransmit rate at the send funnel (STREAM_DATA originals vs STREAM_RESEND
// retransmits) — the same signal the server uses to auto-enable FEC — so it
// reflects actual data loss through the tunnel. Windowed for responsiveness.
// ==============================================================================

package client

import (
	"sync/atomic"

	Enums "cottendns-go/internal/enums"
)

const tunnelLossWindow = 200

type tunnelLossMeter struct {
	windowData    atomic.Uint64
	windowResends atomic.Uint64
	lastPerMille  atomic.Uint64
}

func (m *tunnelLossMeter) recordData() {
	if m.windowData.Add(1) >= tunnelLossWindow {
		m.flush()
	}
}

func (m *tunnelLossMeter) recordResend() {
	m.windowResends.Add(1)
}

func (m *tunnelLossMeter) flush() {
	data := m.windowData.Swap(0)
	resends := m.windowResends.Swap(0)
	total := data + resends
	if total == 0 {
		return
	}
	m.lastPerMille.Store(resends * 1000 / total)
}

func (m *tunnelLossMeter) perMille() uint64 {
	return m.lastPerMille.Load()
}

// recordUploadSample feeds the send funnel into the tunnel-loss meter. New
// STREAM_DATA counts as a fresh send; STREAM_RESEND counts as a retransmit (loss).
func (c *Client) recordUploadSample(packetType uint8) {
	if c == nil {
		return
	}
	switch packetType {
	case Enums.PACKET_STREAM_DATA:
		c.uploadLoss.recordData()
	case Enums.PACKET_STREAM_RESEND:
		c.uploadLoss.recordResend()
	}
}

// tunnelLossPerMille is the current real tunnel loss estimate (parts per 1000),
// from the upload retransmit rate.
func (c *Client) tunnelLossPerMille() uint64 {
	if c == nil {
		return 0
	}
	return c.uploadLoss.perMille()
}
