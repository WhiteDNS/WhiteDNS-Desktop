package cottenmax

import (
	"context"
	"net"
)

// receiveBufferForFlight leaves room for a complete answer flight plus kernel
// packet accounting and scheduling margin. The old fixed 256KiB could be
// smaller than 256 full-size DNS answers. Requests are bounded even when a caller
// supplies settings outside the engine's eventual clamps.
func receiveBufferForFlight(inflight, answer int) int {
	if inflight <= 0 {
		inflight = 256
	}
	inflight = min(inflight, 4096)
	if answer <= 0 {
		answer = 1232
	}
	answer = min(max(answer, 512), 1232)
	return min(16<<20, max(256<<10, inflight*(answer+512)*2))
}

func sizedPacketListener(listen func(context.Context, string, string) (net.PacketConn, error), inflight, answer int) func(context.Context, string, string) (net.PacketConn, error) {
	readBytes := receiveBufferForFlight(inflight, answer)
	return func(ctx context.Context, network, address string) (net.PacketConn, error) {
		pc, err := listen(ctx, network, address)
		if err != nil {
			return nil, err
		}
		// NewClient applies this only to its default socket factory. Injected
		// VPN/protected or encrypted transport factories retain their own sizing
		// contract. The OS may cap the requested size.
		if socket, ok := pc.(interface{ SetReadBuffer(int) error }); ok {
			_ = socket.SetReadBuffer(readBytes)
		}
		if socket, ok := pc.(interface{ SetWriteBuffer(int) error }); ok {
			_ = socket.SetWriteBuffer(256 << 10)
		}
		return pc, nil
	}
}
