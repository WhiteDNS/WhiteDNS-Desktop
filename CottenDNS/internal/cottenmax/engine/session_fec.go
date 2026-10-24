// CottenDNS optional download FEC extension, 2026-10-24. See NOTICE.cottendns.txt.
package soar

import (
	"context"
	"fmt"
	"time"
)

// configureDownloadFEC is carried by the first ordinary authenticated query.
// The echo confirms support without a new handshake or DNS round trip.
func (s *session) configureDownloadFEC(data, parity uint64) error {
	if data > 16 || parity > 4 || !validPacketFEC(int(data), int(parity)) {
		return errFrame
	}
	if s.client {
		if int(data) != s.fecData || int(parity) != s.fecParity || s.fecReady == nil {
			return errFrame
		}
		if !s.fecConfirmed {
			s.fecConfirmed = true
			close(s.fecReady)
		}
		return nil
	}
	if s.fecSend == nil {
		s.fecData, s.fecParity = int(data), int(parity)
		s.fecSend = newPacketFECEncoder(int(data), int(parity))
	} else if int(data) != s.fecData || int(parity) != s.fecParity {
		return errFrame
	}
	s.queueCtrl(ctrl{typ: frFECConfig, id: data, val: parity})
	return nil
}

func (s *session) receiveParity(fragment *fecFragment, now time.Time) error {
	if !s.client || s.fecRecv == nil || fragment == nil || fragment.parityCount != s.fecParity || len(fragment.pns) > s.fecData {
		return errFrame
	}
	recovered, err := s.fecRecv.repair(fragment, now)
	if err != nil {
		return err
	}
	return s.deliverRecovered(recovered, now)
}

func (s *session) deliverRecovered(packets []fecRecovered, now time.Time) error {
	for _, packet := range packets {
		// Only ordinary source packets can be recovered. Reject recursive parity
		// frames before feeding the standard replay/ACK machinery.
		if err := parseFrames(packet.frames, func(f *frame) error {
			if f.typ == frFECParity {
				return errFrame
			}
			return nil
		}); err != nil {
			return err
		}
		if _, err := s.receive(packet.pn, packet.frames, now); err != nil {
			return err
		}
	}
	return nil
}

func (c *Conn) waitDownloadFEC(ctx context.Context) error {
	s := c.st.s
	if s.fecReady == nil {
		return nil
	}
	select {
	case <-s.fecReady:
		return nil
	case <-s.done:
		return fmt.Errorf("soar: server did not confirm requested download FEC; update the server: %w", ErrClosed)
	case <-ctx.Done():
		return fmt.Errorf("soar: server did not confirm requested download FEC; update the server or check its DNS path: %w", ctx.Err())
	}
}
