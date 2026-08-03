// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================

package udpserver

import (
	"context"
	"errors"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	Enums "cottendns-go/internal/enums"
	"cottendns-go/internal/logger"
)

func (s *Server) configureSocketBuffers(conn *net.UDPConn) {
	if err := conn.SetReadBuffer(s.cfg.SocketBufferSize); err != nil {
		s.log.Warnf("\U0001F4E1 <yellow>UDP Read Buffer Setup Failed, <cyan>%v</cyan></yellow>", err)
	}

	if err := conn.SetWriteBuffer(s.cfg.SocketBufferSize); err != nil {
		s.log.Warnf("\U0001F4E1 <yellow>UDP Write Buffer Setup Failed, <cyan>%v</cyan></yellow>", err)
	}
}

func (s *Server) startDNSWorkers(ctx context.Context, queues ingressQueues, workerWG *sync.WaitGroup) {
	for i := range s.cfg.DNSRequestWorkers {
		workerWG.Add(1)
		go func(workerID int) {
			defer workerWG.Done()
			s.dnsWorker(ctx, queues, workerID)
		}(i + 1)
	}
}

// udpSocketCount decides how many SO_REUSEPORT sockets to open for a given
// reader count. It is deliberately not one-per-reader.
//
// The kernel hashes each datagram to a socket by its 4-tuple, so every packet of
// one flow lands on the same socket and is therefore served by whichever readers
// sit on it. With a strict one-socket-per-reader split, a single heavy flow gets
// exactly one reader -- and the reader is not a cheap memcpy, it runs
// admitIngressPacket, which attempts decryption. That would make one busy client
// slower than it was on the old shared socket, where all readers could pull from
// the same queue. Capping sockets below the reader count leaves the surplus
// readers share sockets, so a flow can be drained by more than one decrypt loop.
//
// The cap is the CPU count because queue-splitting past the number of cores that
// can drain those queues buys nothing and only multiplies SO_RCVBUF memory.
func udpSocketCount(readers int) int {
	if readers < 3 {
		return 1
	}
	// Keep at least two readers sharing each socket. SO_REUSEPORT hashes a
	// stable resolver flow to one socket; one socket per reader would therefore
	// pin that flow to one decrypt loop and regress the old shared-socket path.
	sockets := readers / 2
	if sockets < 1 {
		sockets = 1
	}
	if cpus := runtime.NumCPU(); cpus > 0 && sockets > cpus {
		sockets = cpus
	}
	return sockets
}

// listenUDP opens the listening sockets. With SO_REUSEPORT available it opens
// several so each gets its own kernel receive queue; otherwise, or if opening
// the full set fails for any reason, it returns a single shared socket and every
// reader takes turns on it (the behaviour that shipped before). Partial sets are
// never returned: an unbalanced set would leave some readers contending while
// others run free, so anything short of the full count is torn down in favour of
// the predictable single-socket path.
func (s *Server) listenUDP(addr *net.UDPAddr) ([]*net.UDPConn, error) {
	sockets := udpSocketCount(s.cfg.UDPReaders)
	if reusePortSupported && sockets > 1 {
		conns := make([]*net.UDPConn, 0, sockets)
		for range sockets {
			conn, err := listenUDPReusePort(addr)
			if err != nil {
				for _, opened := range conns {
					_ = opened.Close()
				}
				conns = nil
				break
			}
			conns = append(conns, conn)
		}
		if len(conns) == sockets {
			return conns, nil
		}
		if s.log != nil {
			s.log.Warnf("\U0001F4E1 <yellow>SO_REUSEPORT Unavailable, Falling Back To A Single Shared Socket</yellow>")
		}
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	return []*net.UDPConn{conn}, nil
}

// startReaders runs one reader per socket when SO_REUSEPORT gave us a socket
// each, and otherwise fans every reader onto the single shared socket.
func (s *Server) startReaders(ctx context.Context, conns []*net.UDPConn, queues ingressQueues, readErrCh chan<- error, readerWG *sync.WaitGroup) {
	for i := range s.cfg.UDPReaders {
		conn := conns[i%len(conns)]
		readerWG.Add(1)
		go func(readerID int, conn *net.UDPConn) {
			defer readerWG.Done()
			if err := s.readLoop(ctx, conn, queues, readerID); err != nil {
				select {
				case readErrCh <- err:
				default:
				}
			}
		}(i+1, conn)
	}
}

func (s *Server) sessionCleanupLoop(ctx context.Context) {
	interval := s.cfg.SessionCleanupInterval()
	if interval <= 0 {
		interval = 30 * time.Second
	}
	recentlyClosedSweepInterval := 5 * time.Minute
	sessionTimeout := s.cfg.SessionTimeout()
	closedRetention := s.cfg.ClosedSessionRetention()
	invalidCookieWindow := s.invalidCookieWindow

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	lastRecentlyClosedSweep := time.Time{}

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			// Run one tick under recover() so a panic in any single sweep
			// (e.g. a malformed entry in the recently-closed table) cannot
			// take down the entire background cleanup goroutine for the
			// rest of the process lifetime.
			s.runSessionCleanupTick(now, sessionTimeout, closedRetention, invalidCookieWindow, recentlyClosedSweepInterval, &lastRecentlyClosedSweep, interval)
		}
	}
}

func (s *Server) runSessionCleanupTick(
	now time.Time,
	sessionTimeout time.Duration,
	closedRetention time.Duration,
	invalidCookieWindow time.Duration,
	recentlyClosedSweepInterval time.Duration,
	lastRecentlyClosedSweep *time.Time,
	cleanupInterval time.Duration,
) {
	defer func() {
		if recovered := recover(); recovered != nil {
			s.cleanupPanicsRecovered.Add(1)
			if s.log != nil {
				s.log.Errorf(
					"\U0001F4A5 <red>Session Cleanup Tick Panic Recovered, <yellow>%v</yellow></red>",
					recovered,
				)
			}
		}
	}()

	expired := s.sessions.Cleanup(now, sessionTimeout, closedRetention)
	idleDeferred := s.sessions.CollectIdleDeferredSessions(now, s.deferredIdleCleanupTimeout(cleanupInterval, sessionTimeout))
	s.sessions.SweepTerminalStreams(now, s.cfg.TerminalStreamRetention())
	if lastRecentlyClosedSweep.IsZero() || now.Sub(*lastRecentlyClosedSweep) >= recentlyClosedSweepInterval {
		s.sessions.SweepRecentlyClosedStreams(now)
		*lastRecentlyClosedSweep = now
	}
	s.invalidCookieTracker.Cleanup(now, invalidCookieWindow)
	s.purgeDNSQueryFragments(now)
	s.purgeSOCKS5SynFragments(now)
	for _, idleSession := range idleDeferred {
		s.cleanupIdleDeferredSession(idleSession.ID, idleSession.lastActivityNano, now)
	}
	if len(expired) == 0 {
		return
	}
	for _, expiredSession := range expired {
		s.cleanupClosedSession(expiredSession.ID, expiredSession.record)
	}
	s.log.Infof(
		"\U0001F4E1 <green>Expired Sessions Cleaned, Count: <cyan>%d</cyan></green>",
		len(expired),
	)
}

func (s *Server) deferredIdleCleanupTimeout(cleanupInterval time.Duration, sessionTimeout time.Duration) time.Duration {
	timeout := s.deferredConnectAttemptTimeout()
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	if cleanupInterval <= 0 {
		cleanupInterval = 30 * time.Second
	}
	idle := timeout + cleanupInterval
	if sessionTimeout > 0 && sessionTimeout < idle {
		return sessionTimeout
	}
	return idle
}

func (s *Server) readLoop(ctx context.Context, conn *net.UDPConn, queues ingressQueues, readerID int) error {
	for {
		buffer := s.packetPool.Get().([]byte)
		n, addr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			s.packetPool.Put(buffer)

			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}

			s.log.Debugf(
				"\U0001F4A5 <yellow>UDP Read Error, Reader: <cyan>%d</cyan>, Error: <cyan>%v</cyan></yellow>",
				readerID,
				err,
			)
			return err
		}

		// Reject ordinary DNS noise, malformed datagrams and frames that cannot
		// be decoded with the configured shared key before they can occupy the
		// worker queue. This ordering is essential on public UDP/53: queueing a
		// full-size receive buffer before classification lets a packet flood turn
		// MAX_CONCURRENT_REQUESTS into a multi-gigabyte memory reservation.
		prepared, ok := s.prepareIngressPacket(buffer[:n])
		if !ok {
			s.ingressRejectedPackets.Add(1)
			s.packetPool.Put(buffer)
			continue
		}

		req := request{buf: buffer, size: n, addr: addr, conn: conn, prepared: prepared, admitted: time.Now()}
		s.ingressPreparedPackets.Add(1)
		if s.enqueueIngressRequest(req, queues) {
			continue
		}

		select {
		case <-ctx.Done():
			s.packetPool.Put(buffer)
			return nil
		default:
			s.packetPool.Put(buffer)
			s.onDrop(addr, len(queues.control)+len(queues.data), cap(queues.control)+cap(queues.data))
		}
	}
}

func (s *Server) enqueueIngressRequest(req request, queues ingressQueues) bool {
	if isBulkIngressPacket(req.prepared.packet.PacketType) {
		select {
		case queues.data <- req:
			depth := s.ingressDataDepth.Add(1)
			updateHighWater(&s.ingressDataHighWater, uint64(depth))
			return true
		default:
			return false
		}
	}

	// Latency-sensitive traffic may borrow an idle data lane, while bulk traffic
	// cannot consume the reserved control lane. Once any data is queued, control
	// stops spilling into that FIFO; duplicated control packets therefore cannot
	// build a wall in front of user data. Concurrent readers can race this check,
	// but the spill remains bounded by the small reader count.
	select {
	case queues.control <- req:
		depth := s.ingressControlDepth.Add(1)
		updateHighWater(&s.ingressControlHighWater, uint64(depth))
		return true
	default:
	}
	if len(queues.data) != 0 {
		return false
	}
	select {
	case queues.data <- req:
		depth := s.ingressDataDepth.Add(1)
		updateHighWater(&s.ingressDataHighWater, uint64(depth))
		return true
	default:
		return false
	}
}

func isBulkIngressPacket(packetType uint8) bool {
	return packetType == Enums.PACKET_STREAM_DATA || packetType == Enums.PACKET_STREAM_RESEND || packetType == Enums.PACKET_FEC_SHARD
}

func updateHighWater(dst *atomic.Uint64, value uint64) {
	for current := dst.Load(); value > current; current = dst.Load() {
		if dst.CompareAndSwap(current, value) {
			return
		}
	}
}

func (s *Server) dnsWorker(ctx context.Context, queues ingressQueues, workerID int) {
	controlCh, dataCh := queues.control, queues.data
	controlBurst := 0
	for controlCh != nil || dataCh != nil {
		var req request
		var ok bool
		var control bool

		if controlBurst >= 4 && dataCh != nil {
			select {
			case req, ok = <-dataCh:
				if !ok {
					dataCh = nil
					continue
				}
			default:
			}
			if ok {
				s.ingressDataDepth.Add(-1)
				controlBurst = 0
				s.processIngressRequest(req, workerID)
				continue
			}
		}

		if controlBurst < 4 && controlCh != nil {
			select {
			case req, ok = <-controlCh:
				if !ok {
					controlCh = nil
					continue
				}
				control = true
			default:
			}
			if control {
				s.ingressControlDepth.Add(-1)
				controlBurst++
				s.processIngressRequest(req, workerID)
				continue
			}
		}

		select {
		case <-ctx.Done():
			return
		case req, ok = <-controlCh:
			if !ok {
				controlCh = nil
				continue
			}
			s.ingressControlDepth.Add(-1)
			controlBurst++
		case req, ok = <-dataCh:
			if !ok {
				dataCh = nil
				continue
			}
			s.ingressDataDepth.Add(-1)
			controlBurst = 0
		}
		s.processIngressRequest(req, workerID)
	}
}

func (s *Server) processIngressRequest(req request, workerID int) {
	response := s.safeHandlePreparedIngress(req.buf[:req.size], req.prepared)
	if len(response) != 0 {
		if _, err := req.conn.WriteToUDP(response, req.addr); err != nil {
			s.log.Debugf(
				"\U0001F4A5 <yellow>UDP Write Error, Worker: <cyan>%d</cyan>, Remote: <cyan>%v</cyan>, Error: <cyan>%v</cyan></yellow>",
				workerID,
				req.addr,
				err,
			)
		}
	}
	if !req.admitted.IsZero() {
		s.ingressLatencyNanos.Add(uint64(time.Since(req.admitted)))
		s.ingressLatencySamples.Add(1)
	}
	s.packetPool.Put(req.buf)
}

func (s *Server) safeHandlePacket(packet []byte) (response []byte) {
	defer func() {
		if recovered := recover(); recovered != nil {
			if s.log != nil {
				s.log.Errorf(
					"\U0001F4A5 <red>Packet Handler Panic Recovered, <yellow>%v</yellow></red>",
					recovered,
				)
			}
			response = nil
		}
	}()

	return s.handlePacket(packet)
}

func (s *Server) safeHandlePreparedIngress(packet []byte, prepared preparedIngress) (response []byte) {
	defer func() {
		if recovered := recover(); recovered != nil {
			if s.log != nil {
				s.log.Errorf("\U0001F4A5 <red>Prepared Packet Handler Panic Recovered, <yellow>%v</yellow></red>", recovered)
			}
			response = nil
		}
	}()
	return s.handlePreparedIngress(packet, prepared)
}

func (s *Server) onDrop(addr *net.UDPAddr, queueLen int, queueCap int) {
	total := s.droppedPackets.Add(1)

	now := logger.NowUnixNano()
	last := s.lastDropLogUnix.Load()
	interval := s.dropLogIntervalNanos
	if interval <= 0 {
		interval = 2_000_000_000
	}
	if now-last < interval {
		return
	}
	if !s.lastDropLogUnix.CompareAndSwap(last, now) {
		return
	}

	s.log.Warnf(
		"\U0001F6A8 <yellow>Request Queue Overloaded</yellow> <magenta>|</magenta> <blue>Dropped</blue>: <magenta>%d</magenta> <magenta>|</magenta> <blue>Queue</blue>: <cyan>%d/%d</cyan> <magenta>|</magenta> <blue>Remote</blue>: <cyan>%v</cyan>",
		total,
		queueLen,
		queueCap,
		addr,
	)
}
