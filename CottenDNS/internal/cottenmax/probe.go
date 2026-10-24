package cottenmax

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// ProbeTarget is an authenticated, bounded in-process diagnostic endpoint.
// It opens no outbound connection and needs no separate listener or credential.
const ProbeTarget = "probe:0"
const maxProbeBytes = 64 << 10

// Authenticate checks the server identity using the live engine's DNS paths.
func (c *Client) Authenticate(ctx context.Context) error {
	if c.failover != nil {
		return c.failover.authenticate(ctx)
	}
	return c.engine.Authenticate(ctx)
}

// Probe transfers and verifies a bounded challenge through the same encrypted
// streams as real traffic. PathStats then reports observed wire sizes, rather
// than mistaking a configured answer-size ceiling for a measured MTU.
func (c *Client) Probe(ctx context.Context, size int) error {
	if size < 32 || size > maxProbeBytes {
		return fmt.Errorf("cottenmax: invalid probe size")
	}
	conn, err := c.Dial(ctx, ProbeTarget)
	if err != nil {
		return fmt.Errorf("cottenmax probe opening stream: %w", err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	request := make([]byte, 36)
	binary.BigEndian.PutUint32(request, uint32(size))
	if _, err = rand.Read(request[4:]); err != nil {
		return fmt.Errorf("cottenmax probe creating challenge: %w", err)
	}
	for rest := request; len(rest) > 0; {
		n, e := conn.Write(rest)
		if e != nil {
			return fmt.Errorf("cottenmax probe writing challenge: %w", e)
		}
		if n == 0 {
			return fmt.Errorf("cottenmax probe writing challenge: %w", io.ErrShortWrite)
		}
		rest = rest[n:]
	}
	reply := make([]byte, size)
	if _, err = io.ReadFull(conn, reply); err != nil {
		return fmt.Errorf("cottenmax probe reading reply: %w", err)
	}
	want := bytes.Repeat(request[4:], (size+31)/32)[:size]
	if !bytes.Equal(reply, want) {
		return fmt.Errorf("cottenmax: probe reply mismatch")
	}
	return nil
}

func newProbeConn(ctx context.Context) net.Conn {
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		stop := context.AfterFunc(ctx, func() { server.Close() })
		defer stop()
		server.SetDeadline(time.Now().Add(30 * time.Second))
		var request [36]byte
		if _, err := io.ReadFull(server, request[:]); err != nil {
			return
		}
		size := int(binary.BigEndian.Uint32(request[:4]))
		if size < 32 || size > maxProbeBytes {
			return
		}
		data := bytes.Repeat(request[4:], (size+31)/32)[:size]
		_, _ = io.Copy(server, bytes.NewReader(data))
	}()
	return client
}
