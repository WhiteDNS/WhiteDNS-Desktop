// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================

package client

import (
	"context"
	"sort"
	"time"

	Enums "cottendns-go/internal/enums"
	VpnProto "cottendns-go/internal/vpnproto"
)

// dispatchEntry is one round-robin slot: an active stream, or the orphan-queue
// sentinel (id -1, nil stream). The dispatcher keeps these sorted by id and
// rebuilds them only when the stream set changes, so the per-packet scan is a
// slice walk instead of a map lookup per stream.
//
// ponytail: the scan still walks every open stream, idle or not. The server
// side (sessionRecord.ActiveStreams) keeps a separate has-work set and walks
// only that; mirror it here if profiles show the scan mattering again beyond
// a few hundred streams.
type dispatchEntry struct {
	id     int32
	stream *Stream_client
}

func (c *Client) selectTargetConnections(packetType uint8, streamID uint16) []Connection {
	connections, err := c.selectTargetConnectionsForPacket(packetType, streamID)
	if err != nil {
		return nil
	}

	return connections
}

// asyncStreamDispatcher cycles through all active streams using a fair Round-Robin algorithm
// and transmits the highest priority packets to the TX workers, packing control blocks when possible.
func (c *Client) asyncStreamDispatcher(ctx context.Context) {
	c.log.Debugf("Stream Dispatcher started")
	defer c.asyncWG.Done()

	var rrCursor int32 = -1
	var cachedVersion uint64
	var cachedEntries []dispatchEntry
	idlePoll := c.cfg.DispatcherIdlePollInterval()
	idleTimer := time.NewTimer(idlePoll)
	defer idleTimer.Stop()

	waitForWork := func() bool {
		select {
		case <-ctx.Done():
			return false
		case <-c.txSignal:
		case <-idleTimer.C:
		}
		if !idleTimer.Stop() {
			select {
			case <-idleTimer.C:
			default:
			}
		}
		idleTimer.Reset(idlePoll)
		return true
	}

	waitForTxCapacity := func(required int) bool {
		if required <= 0 {
			return true
		}
		for {
			if c.txChannelHasCapacity(required) {
				return true
			}

			select {
			case <-ctx.Done():
				return false
			case <-c.txSpaceSignal:
			case <-idleTimer.C:
			}

			if !idleTimer.Stop() {
				select {
				case <-idleTimer.C:
				default:
				}
			}
			idleTimer.Reset(idlePoll)
		}
	}

dispatchLoop:
	for {
		currentVersion := c.streamSetVersion.Load()
		if currentVersion != cachedVersion || cachedEntries == nil {
			c.streamsMu.RLock()
			entries := make([]dispatchEntry, 0, len(c.active_streams)+1)
			for id, stream := range c.active_streams {
				entries = append(entries, dispatchEntry{id: int32(id), stream: stream})
			}
			c.streamsMu.RUnlock()
			sort.Slice(entries, func(i, j int) bool { return entries[i].id < entries[j].id })
			cachedEntries = entries
			cachedVersion = currentVersion
		}

		entries := cachedEntries

		if c.orphanQueue != nil && c.orphanQueue.FastSize() > 0 {
			entries = append(entries[:len(entries):len(entries)], dispatchEntry{id: -1})
		}

		if len(entries) == 0 {
			if !waitForWork() {
				return
			}
			continue
		}

		selected, peekedItem, selectedStreamID, selectedID := c.selectNextDispatchStream(entries, &rrCursor)

		if selectedID == -2 || peekedItem == nil {
			if !waitForWork() {
				return
			}
			continue
		}

		conns := c.selectTargetConnections(peekedItem.PacketType, selectedStreamID)
		if len(conns) == 0 {
			// No valid connections available for this packet. Don't block the
			// dispatcher — doing so would stall ALL streams until a resolver
			// comes back. Instead, pop and discard non-retriable control packets
			// so the queue doesn't jam, and leave data/resend packets for ARQ
			// retransmission.
			if peekedItem.PacketType != Enums.PACKET_STREAM_DATA && peekedItem.PacketType != Enums.PACKET_STREAM_RESEND {
				if selected != nil {
					if dropped, _, ok := selected.PopNextTXPacket(); ok && dropped != nil {
						selected.ReleaseTXPacket(dropped)
					}
				} else if selectedID == -1 {
					c.orphanQueue.Pop(func(p VpnProto.Packet) uint64 {
						return Enums.PacketTypeStreamKey(p.StreamID, p.PacketType)
					})
				}
			}
			if !waitForWork() {
				return
			}
			continue dispatchLoop
		}

		if !waitForTxCapacity(1) {
			if ctx.Err() != nil {
				return
			}
			continue dispatchLoop
		}

		var item *clientStreamTXPacket
		var ok bool
		if selected != nil {
			item, _, ok = selected.PopNextTXPacket()
			if !ok || item == nil {
				continue dispatchLoop
			}
		} else {
			p, _, ok := c.orphanQueue.Pop(func(p VpnProto.Packet) uint64 {
				return Enums.PacketTypeStreamKey(p.StreamID, p.PacketType)
			})
			if !ok {
				continue dispatchLoop
			}
			item = &clientStreamTXPacket{
				PacketType:     p.PacketType,
				SequenceNum:    p.SequenceNum,
				FragmentID:     p.FragmentID,
				TotalFragments: p.TotalFragments,
				Payload:        nil,
			}
		}

		if selected != nil &&
			(item.PacketType == Enums.PACKET_STREAM_DATA || item.PacketType == Enums.PACKET_STREAM_RESEND) &&
			!c.shouldTransmitQueuedStreamPacket(selected, item) {
			selected.ReleaseTXPacket(item)
			continue dispatchLoop
		}

		finalPacketType, finalPayload, wasPacked := c.packControlBlocks(item, selected, selectedID, selectedStreamID, entries)

		c.pingManager.NotifyPacket(finalPacketType, false)

		opts := VpnProto.BuildOptions{
			LegacySessionID: c.cfg.LegacySessionID,
			SessionID:       c.sessionID,
			SessionCookie:   c.sessionCookie,
			PacketType:      finalPacketType,
			CompressionType: func() uint8 {
				if wasPacked {
					return c.uploadCompression
				}
				return item.CompressionType
			}(),
			Payload: finalPayload,
		}

		if wasPacked {
			opts.StreamID = 0
		} else {
			opts.StreamID = selectedStreamID
			opts.SequenceNum = item.SequenceNum
			opts.FragmentID = item.FragmentID
			opts.TotalFragments = item.TotalFragments
		}

		task := rawOutboundTask{
			packetType: finalPacketType,
			payload:    finalPayload,
			opts:       opts,
			wasPacked:  wasPacked,
			item:       item,
			selected:   selected,
			conns:      conns,
		}

		select {
		case c.txChannel <- task:
		case <-ctx.Done():
			if !wasPacked && selected != nil {
				selected.ReleaseTXPacket(item)
			}
			return
		}
	}
}

// selectNextDispatchStream performs one fair round-robin scan over the active
// stream IDs (plus the orphan-queue sentinel -1), starting just past *rrCursor,
// and returns the first stream/orphan that has a packet ready to send. It peeks
// (does not pop) the chosen packet and advances *rrCursor to the id following
// the first candidate examined.
//
// A PING on the control stream (id 0) is deferred when any other stream or the
// orphan queue has work, so data/control traffic is not starved by keepalives.
//
// When nothing is ready it returns selectedID == -2 and a nil item. Note: as in
// the original inline loop, `selected` is only assigned on the stream branch and
// is intentionally not cleared when a later orphan pick wins — callers key off
// selectedID, and this preserves the pre-extraction behavior exactly.
func (c *Client) selectNextDispatchStream(
	entries []dispatchEntry,
	rrCursor *int32,
) (selected *Stream_client, peekedItem *clientStreamTXPacket, selectedStreamID uint16, selectedID int32) {
	var peekedOK bool
	selectedID = -2
	rrApplied := false

	// entries is sorted by id, so the round-robin resume point is a binary
	// search rather than a scan.
	startIndex := sort.Search(len(entries), func(i int) bool { return entries[i].id >= *rrCursor })
	if startIndex == len(entries) {
		startIndex = 0
	}

	for i := 0; i < len(entries); i++ {
		entry := entries[(startIndex+i)%len(entries)]
		id := entry.id

		if id == -1 {
			if c.orphanQueue == nil || c.orphanQueue.FastSize() == 0 {
				continue
			}
			p, _, ok := c.orphanQueue.Peek()
			if !ok {
				continue
			}

			peekedItem = &clientStreamTXPacket{
				PacketType:     p.PacketType,
				SequenceNum:    p.SequenceNum,
				FragmentID:     p.FragmentID,
				TotalFragments: p.TotalFragments,
				Payload:        nil,
			}

			selectedStreamID = p.StreamID
			selectedID = -1
			peekedOK = true
		} else {
			s := entry.stream
			if s == nil || s.txQueue == nil {
				continue
			}
			// FastSize is a lock-free atomic; Peek takes the queue mutex. Most
			// streams in a browsing session are idle, and this scan runs once
			// per dispatched packet over every stream, so skipping the lock on
			// empty queues is what keeps the dispatcher off an O(streams)
			// mutex-acquisition treadmill.
			if s.txQueue.FastSize() == 0 {
				continue
			}
			peekedItem, _, peekedOK = s.txQueue.Peek()
			if peekedOK {
				selectedStreamID = uint16(id)
				selectedID = int32(id)
				selected = s
			}
		}

		if peekedOK && peekedItem != nil {
			if !rrApplied {
				*rrCursor = id + 1
				rrApplied = true
			}

			if id == 0 && peekedItem.PacketType == Enums.PACKET_PING {
				hasOtherWork := false
				for _, other := range entries {
					if other.id == 0 {
						continue
					}
					if other.id == -1 {
						if c.orphanQueue != nil && c.orphanQueue.FastSize() > 0 {
							hasOtherWork = true
							break
						}
						continue
					}
					os := other.stream
					if os != nil && os.txQueue != nil && os.txQueue.FastSize() > 0 {
						hasOtherWork = true
						break
					}
				}
				if hasOtherWork {
					peekedItem = nil
					peekedOK = false
					continue
				}
			}

			break
		}
	}

	return selected, peekedItem, selectedStreamID, selectedID
}

// packControlBlocks attempts to coalesce the selected packet together with other
// pending packable control packets (from the selected stream, the orphan queue,
// and other streams) into a single PACKET_PACKED_CONTROL_BLOCKS frame.
//
// It returns the packet type and payload to actually transmit and whether
// packing occurred. When packing succeeds and the packet came from a real
// stream, the original item is released here (mirroring the inline behavior it
// was extracted from). When the packet is not packable, packing is disabled
// (maxPackedBlocks <= 1), or only the single block could be gathered, the
// original packet type and payload are returned unchanged.
func (c *Client) packControlBlocks(
	item *clientStreamTXPacket,
	selected *Stream_client,
	selectedID int32,
	selectedStreamID uint16,
	entries []dispatchEntry,
) (finalPacketType uint8, finalPayload []byte, wasPacked bool) {
	maxBlocks := c.maxPackedBlocks
	if maxBlocks < 1 {
		maxBlocks = 1
	}

	if !VpnProto.IsPackableControlPacket(item.PacketType, len(item.Payload)) || maxBlocks <= 1 {
		return item.PacketType, item.Payload, false
	}

	payload := make([]byte, 0, maxBlocks*VpnProto.PackedControlBlockSize)
	payload = VpnProto.AppendPackedControlBlock(payload, item.PacketType, selectedStreamID, item.SequenceNum, item.FragmentID, item.TotalFragments)
	blocks := 1

	if selected != nil {
		for blocks < maxBlocks {
			popped, poppedOK := selected.txQueue.PopAnyIf(2, func(p *clientStreamTXPacket) bool {
				return VpnProto.IsPackableControlPacket(p.PacketType, len(p.Payload))
			}, func(p *clientStreamTXPacket) uint64 {
				return Enums.PacketIdentityKey(selected.StreamID, p.PacketType, p.SequenceNum, p.FragmentID)
			})
			if !poppedOK {
				break
			}
			selected.NoteTXPacketDequeued(popped)
			payload = VpnProto.AppendPackedControlBlock(payload, popped.PacketType, selected.StreamID, popped.SequenceNum, popped.FragmentID, popped.TotalFragments)
			blocks++
			selected.ReleaseTXPacket(popped)
		}
	} else if selectedID == -1 {
		for blocks < maxBlocks {
			popped, poppedOK := c.orphanQueue.PopAnyIf(2, func(p VpnProto.Packet) bool {
				return VpnProto.IsPackableControlPacket(p.PacketType, 0)
			}, func(p VpnProto.Packet) uint64 {
				return Enums.PacketTypeStreamKey(p.StreamID, p.PacketType)
			})
			if !poppedOK {
				break
			}
			payload = VpnProto.AppendPackedControlBlock(payload, popped.PacketType, popped.StreamID, popped.SequenceNum, popped.FragmentID, popped.TotalFragments)
			blocks++
		}
	}

	if blocks < maxBlocks {
		for _, other := range entries {
			otherID := other.id
			if blocks >= maxBlocks {
				break
			}
			if otherID == selectedID {
				continue
			}

			if otherID == -1 {
				for blocks < maxBlocks {
					popped, poppedOK := c.orphanQueue.PopAnyIf(2, func(p VpnProto.Packet) bool {
						return VpnProto.IsPackableControlPacket(p.PacketType, 0)
					}, func(p VpnProto.Packet) uint64 {
						return Enums.PacketTypeStreamKey(p.StreamID, p.PacketType)
					})
					if !poppedOK {
						break
					}
					payload = VpnProto.AppendPackedControlBlock(payload, popped.PacketType, popped.StreamID, popped.SequenceNum, popped.FragmentID, popped.TotalFragments)
					blocks++
				}
				continue
			}

			otherStream := other.stream
			if otherStream == nil || otherStream.txQueue == nil {
				continue
			}
			for blocks < maxBlocks {
				popped, poppedOK := otherStream.txQueue.PopAnyIf(2, func(p *clientStreamTXPacket) bool {
					return VpnProto.IsPackableControlPacket(p.PacketType, len(p.Payload))
				}, func(p *clientStreamTXPacket) uint64 {
					return Enums.PacketIdentityKey(uint16(otherID), p.PacketType, p.SequenceNum, p.FragmentID)
				})
				if !poppedOK {
					break
				}
				otherStream.NoteTXPacketDequeued(popped)
				payload = VpnProto.AppendPackedControlBlock(payload, popped.PacketType, uint16(otherID), popped.SequenceNum, popped.FragmentID, popped.TotalFragments)
				blocks++
				otherStream.ReleaseTXPacket(popped)
			}
		}
	}

	if blocks > 1 {
		if selected != nil {
			selected.ReleaseTXPacket(item)
		}
		return Enums.PACKET_PACKED_CONTROL_BLOCKS, payload, true
	}

	return item.PacketType, item.Payload, false
}
