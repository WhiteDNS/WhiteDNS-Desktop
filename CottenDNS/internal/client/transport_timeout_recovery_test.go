package client

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"
)

// A timeout can consume a DNS frame's length and part of its body. The next
// MTU probe must either finish/discard that frame or reconnect; treating its
// remaining body bytes as a fresh length poisons all subsequent probes.
func TestTCPQueryTransportRecoversAfterPartialResponseTimeout(t *testing.T) {
	for _, tc := range []struct {
		name  string
		bytes int
	}{{"partial_length", 1}, {"partial_body", 5}} {
		t.Run(tc.name, func(t *testing.T) {
			testTCPQueryTransportRecoversAfterPartialResponseTimeout(t, tc.bytes)
		})
	}
}

func testTCPQueryTransportRecoversAfterPartialResponseTimeout(t *testing.T, partialBytes int) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	query1, query2 := make([]byte, 12), make([]byte, 12)
	binary.BigEndian.PutUint16(query1, 0x1111)
	binary.BigEndian.PutUint16(query2, 0x2222)
	response1, response2 := make([]byte, 24), make([]byte, 24)
	copy(response1, query1)
	copy(response2, query2)
	response1[2], response1[3], response2[2], response2[3] = 0x81, 0x80, 0x81, 0x80
	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err = readTCPDNSFramed(conn); err != nil {
			serverDone <- err
			return
		}
		partial := binary.BigEndian.AppendUint16(nil, uint16(len(response1)))
		partial = append(partial, response1...)
		partial = partial[:partialBytes]
		if _, err = conn.Write(partial); err != nil {
			serverDone <- err
			return
		}
		// Read the retry before completing the first reply. A repaired transport
		// may instead close the damaged connection and dial a fresh one.
		if _, err = readTCPDNSFramed(conn); err != nil {
			_ = conn.Close()
			conn, err = listener.Accept()
			if err != nil {
				serverDone <- err
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			if _, err = readTCPDNSFramed(conn); err != nil {
				serverDone <- err
				return
			}
			serverDone <- writeTCPDNSFramed(conn, response2)
			return
		}
		remaining := binary.BigEndian.AppendUint16(nil, uint16(len(response1)))
		remaining = append(remaining, response1...)
		remaining = append([]byte(nil), remaining[partialBytes:]...)
		remaining = binary.BigEndian.AppendUint16(remaining, uint16(len(response2)))
		remaining = append(remaining, response2...)
		_, err = conn.Write(remaining)
		serverDone <- err
	}()
	transport, err := newTCPQueryTransport(listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()
	if _, err = transport.exchange(query1, 100*time.Millisecond); err == nil {
		t.Fatal("expected first partial reply to time out")
	}
	response, err := transport.exchange(query2, time.Second)
	if err != nil || !bytes.Equal(response, response2) {
		t.Fatalf("valid next query could not recover from previous partial-frame timeout: response=%x err=%v", response, err)
	}
	if err = <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestTCPQueryTransportReconnectSharesExchangeDeadlineAndCloseIsFinal(t *testing.T) {
	dials := 0
	var reconnectBudget time.Duration
	var exchangeDeadline time.Time
	transport, err := newStreamQueryTransport(func(timeout time.Duration) (net.Conn, error) {
		dials++
		conn, peer := net.Pipe()
		if dials == 1 {
			_ = peer.Close()
			return conn, nil
		}
		reconnectBudget = timeout
		// Spend part of this exchange's budget establishing the replacement.
		time.Sleep(40 * time.Millisecond)
		go func() {
			defer peer.Close()
			_, _ = readTCPDNSFramed(peer)
			// Keep the socket open without a response. The read deadline must
			// still be the original exchange deadline, not a fresh budget.
			_, _ = peer.Read(make([]byte, 1))
		}()
		return &tcpQueryDeadlineConn{Conn: conn, deadline: &exchangeDeadline}, nil
	}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()
	query := []byte{0x12, 0x34}
	if _, err = transport.exchange(query, time.Second); err == nil {
		t.Fatal("expected the closed first connection to fail")
	}
	start := time.Now()
	_, err = transport.exchange(query, 100*time.Millisecond)
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("expected an exchange timeout, got %v", err)
	}
	if reconnectBudget <= 0 || reconnectBudget > 100*time.Millisecond {
		t.Fatalf("reconnect got a separate timeout budget: %s", reconnectBudget)
	}
	if budget := exchangeDeadline.Sub(start); budget <= 0 || budget > 110*time.Millisecond {
		t.Fatalf("dial time was added to the exchange deadline: %s", budget)
	}
	if err = transport.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = transport.exchange(query, time.Second); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("exchange after Close returned %v", err)
	}
	if dials != 2 {
		t.Fatalf("closed transport redialed: %d dials", dials)
	}
}

type tcpQueryDeadlineConn struct {
	net.Conn
	deadline *time.Time
}

func (c *tcpQueryDeadlineConn) SetDeadline(deadline time.Time) error {
	*c.deadline = deadline
	return c.Conn.SetDeadline(deadline)
}

func TestTCPQueryTransportCloseInterruptsExchange(t *testing.T) {
	for i := 0; i < 16; i++ {
		conn, peer := net.Pipe()
		transport := &tcpQueryTransport{conn: conn}
		queryRead := make(chan struct{})
		go func() {
			defer peer.Close()
			_, _ = readTCPDNSFramed(peer)
			close(queryRead)
			_, _ = peer.Read(make([]byte, 1))
		}()
		done := make(chan error, 1)
		go func() {
			_, err := transport.exchange([]byte{0x12, 0x34}, time.Minute)
			done <- err
		}()
		<-queryRead
		if err := transport.Close(); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("closed exchange succeeded")
			}
		case <-time.After(time.Second):
			t.Fatal("Close failed to interrupt the active exchange")
		}
	}
}

func TestTCPQueryTransportToleratesSevenMismatchedResponseIDs(t *testing.T) {
	conn, peer := net.Pipe()
	transport := &tcpQueryTransport{conn: conn}
	defer transport.Close()
	serverDone := make(chan error, 1)
	go func() {
		defer peer.Close()
		if _, err := readTCPDNSFramed(peer); err != nil {
			serverDone <- err
			return
		}
		for i := 0; i < 8; i++ {
			id := uint16(i)
			if i == 7 {
				id = 0x1234
			}
			if err := writeTCPDNSFramed(peer, binary.BigEndian.AppendUint16(nil, id)); err != nil {
				serverDone <- err
				return
			}
		}
		serverDone <- nil
	}()
	query := []byte{0x12, 0x34}
	response, err := transport.exchange(query, time.Second)
	if err != nil || !bytes.Equal(response, query) {
		t.Fatalf("response ID filtering changed: response=%x err=%v", response, err)
	}
	if err = <-serverDone; err != nil {
		t.Fatal(err)
	}
}
