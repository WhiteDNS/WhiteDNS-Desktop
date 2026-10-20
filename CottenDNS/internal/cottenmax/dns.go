package cottenmax

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"cottendns-go/internal/dnsparser"
)

// DNSTarget is an authenticated internal service, not an arbitrary destination.
const DNSTarget = "dns:0"

func ReadDNSFrame(reader io.Reader) ([]byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}
	size := int(binary.BigEndian.Uint16(header[:]))
	if size < 12 {
		return nil, fmt.Errorf("cottenmax: invalid DNS frame size")
	}
	packet := make([]byte, size)
	_, err := io.ReadFull(reader, packet)
	return packet, err
}

func WriteDNSFrame(writer io.Writer, packet []byte) error {
	if len(packet) < 12 || len(packet) > 65535 {
		return fmt.Errorf("cottenmax: invalid DNS frame size")
	}
	frame := binary.BigEndian.AppendUint16(nil, uint16(len(packet)))
	frame = append(frame, packet...)
	for len(frame) > 0 {
		n, err := writer.Write(frame)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		frame = frame[n:]
	}
	return nil
}

// ExchangeDNS uses the established Max session and the normal server resolver.
// A stream carries one framed exchange so concurrent queries cannot cross IDs.
func (c *Client) ExchangeDNS(ctx context.Context, query []byte) ([]byte, error) {
	request, err := dnsparser.ParseDNSRequestLite(query)
	if err != nil || !request.HasQuestion {
		return nil, fmt.Errorf("cottenmax: invalid DNS query")
	}
	conn, err := c.DialStream(ctx, DNSTarget)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	if err := WriteDNSFrame(conn, query); err != nil {
		return nil, err
	}
	response, err := ReadDNSFrame(conn)
	if err != nil {
		return nil, err
	}
	reply, err := dnsparser.ParsePacketLite(response)
	if err != nil || !reply.HasQuestion || reply.Header.QR != 1 || reply.Header.ID != request.Header.ID ||
		!strings.EqualFold(reply.FirstQuestion.Name, request.FirstQuestion.Name) || reply.FirstQuestion.Type != request.FirstQuestion.Type || reply.FirstQuestion.Class != request.FirstQuestion.Class {
		return nil, fmt.Errorf("cottenmax: DNS response does not match query")
	}
	return response, nil
}
