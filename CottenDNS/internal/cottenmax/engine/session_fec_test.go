package soar

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

func TestCottenMaxDownloadFECRecoversWireLossWithoutARQ(t *testing.T) {
	for _, parity := range []int{1, 2, 4} {
		t.Run(string(rune('0'+parity)), func(t *testing.T) {
			cfg := streamConfig{StreamWindow: 256 << 10, SendBuffer: 64 << 10, MaxStreams: 4, FECDataShards: 4, FECParityShards: parity}
			cli := newSession(true, cfg, &packetCipher{}, &packetCipher{})
			cfg.FECDataShards, cfg.FECParityShards = 0, 0
			srv := newSession(false, cfg, &packetCipher{}, &packetCipher{})
			st, err := cli.openStream()
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			up, frames, _, _ := cli.build([]byte{0}, 96, now, 0)
			if _, err = srv.receive(up, frames[1:], now); err != nil {
				t.Fatal(err)
			}
			pn, frames, _, _ := srv.build([]byte{0, 0}, 96, now, up)
			if _, err = cli.receive(pn, frames[2:], now); err != nil {
				t.Fatal(err)
			}
			if !cli.fecConfirmed || srv.fecSend == nil {
				t.Fatal("FEC was not negotiated in ordinary stream setup")
			}
			peer := srv.streams[st.id]
			if peer == nil {
				t.Fatal("server stream missing")
			}
			payload := bytes.Repeat([]byte("byte-exact-loss-recovery-"), 29)
			peer.sbuf = append([]byte(nil), payload...)
			peer.spending.add(0, uint64(len(payload)))
			var dropped []uint64
			sentOriginal := false
			for i := 0; i < 160 && len(st.rbuf) < len(payload); i++ {
				budget := 96
				if i%2 == 1 {
					budget = 63
				}
				pn, frames, _, pkt := srv.build([]byte{0, 0}, budget, now, up)
				if len(frames)-2 > budget {
					t.Fatalf("DNS frame budget exceeded: %d > %d", len(frames)-2, budget)
				}
				if pkt != nil && len(pkt.streams) > 0 {
					sentOriginal = true
					if len(dropped) < parity {
						dropped = append(dropped, pn)
						continue
					}
				}
				if _, err = cli.receive(pn, frames[2:], now); err != nil {
					t.Fatalf("packet %d: %v", pn, err)
				}
			}
			// No declareLost, timeout, retransmission, or artificial source delivery is
			// invoked. Only surviving originals and actual parity frame packets arrive.
			if !sentOriginal || !bytes.Equal(st.rbuf, payload) {
				t.Fatalf("wire FEC did not restore exact stream: %d/%d bytes", len(st.rbuf), len(payload))
			}
			for _, pn := range dropped {
				if !cli.toAck.contains(pn) {
					t.Fatalf("recovered packet %d was not acknowledged", pn)
				}
			}
		})
	}
}

func TestCottenMaxDownloadFECDeliversOriginalImmediately(t *testing.T) {
	cfg := streamConfig{StreamWindow: 256 << 10, SendBuffer: 64 << 10, MaxStreams: 4}
	srv := newSession(false, cfg, &packetCipher{}, &packetCipher{})
	if err := srv.configureDownloadFEC(16, 1); err != nil {
		t.Fatal(err)
	}
	peer := srv.peerStream(0)
	peer.sbuf = bytes.Repeat([]byte{7}, 1000)
	peer.spending.add(0, 1000)
	_, frames, _, pkt := srv.build([]byte{0, 0}, 64, time.Now(), 0)
	if pkt == nil || len(pkt.streams) == 0 || len(frames) <= 2 {
		t.Fatal("FEC buffered original stream data waiting for a full block")
	}
}

func TestCottenMaxFECDisabledHasNoWireExtension(t *testing.T) {
	cfg := streamConfig{StreamWindow: 256 << 10, SendBuffer: 64 << 10, MaxStreams: 4}
	s := newSession(true, cfg, &packetCipher{}, &packetCipher{})
	if s.fecReady != nil || s.fecRecv != nil || s.fecSend != nil || len(s.ctrlQ) != 0 {
		t.Fatal("disabled FEC allocated negotiated state or changed the wire")
	}
	if err := (&Conn{st: newStream(s, 0)}).waitDownloadFEC(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestCottenMaxFECNeedsServerConfirmation(t *testing.T) {
	cfg := streamConfig{StreamWindow: 256 << 10, SendBuffer: 64 << 10, MaxStreams: 4, FECDataShards: 4, FECParityShards: 1}
	s := newSession(true, cfg, &packetCipher{}, &packetCipher{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := (&Conn{st: newStream(s, 0)}).waitDownloadFEC(ctx)
	if err == nil || !strings.Contains(err.Error(), "server did not confirm") {
		t.Fatalf("missing explicit server support error: %v", err)
	}
}

func TestCottenMaxSingleFlightScoutsWhenVerifiedPathStalls(t *testing.T) {
	c, good, _, pc := schedulerFixture(t, 10, 1)
	now := time.Now()
	good.consec = 2
	good.lastSuccess = now.Add(-10 * time.Second)
	c.fillLocked(now)
	if len(pc.writes) != 1 || pc.writes[0].addr == good.addr {
		t.Fatal("stalled single-slot flight never tried an alternate resolver")
	}
	if c.liveQueriesLocked() != 1 {
		t.Fatal("alternate scout exceeded single-slot bound")
	}
}
