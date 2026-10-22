package udpserver

import (
	"net"
	"time"

	"cottendns-go/internal/cottenmax"
)

func (s *Server) cottenMaxDNSStream() net.Conn {
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		// The engine cancels its dial context immediately after Dial returns.
		// The relay owns client.Close; a bounded deadline protects partial frames.
		server.SetDeadline(time.Now().Add(60 * time.Second))
		query, err := cottenmax.ReadDNSFrame(server)
		if err != nil {
			return
		}
		response := s.buildDNSQueryResponsePayload(query, 0, 0)
		if len(response) > 0 {
			_ = cottenmax.WriteDNSFrame(server, response)
		}
	}()
	return client
}
