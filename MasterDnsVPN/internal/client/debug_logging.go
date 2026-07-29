package client

import (
	"fmt"
	"strings"
)

func (c *Client) debugf(format string, args ...any) {
	if c == nil || c.log == nil {
		return
	}
	c.log.Debugf("Debug "+format, args...)
}

func (b *Balancer) debugf(format string, args ...any) {
	if b == nil || b.log == nil {
		return
	}
	b.log.Debugf("Debug "+format, args...)
}

func debugConnectionSummary(conns []Connection, limit int) string {
	if len(conns) == 0 {
		return "count=0 sample=-"
	}
	if limit <= 0 {
		limit = 5
	}
	if limit > len(conns) {
		limit = len(conns)
	}

	parts := make([]string, 0, limit)
	for i := 0; i < limit; i++ {
		conn := conns[i]
		label := conn.ResolverLabel
		if label == "" {
			label = conn.Resolver
		}
		parts = append(parts, fmt.Sprintf(
			"%s/%s/up=%d/down=%d/valid=%t",
			label,
			conn.Domain,
			conn.UploadMTUBytes,
			conn.DownloadMTUBytes,
			conn.IsValid,
		))
	}

	suffix := ""
	if len(conns) > limit {
		suffix = fmt.Sprintf(" +%d more", len(conns)-limit)
	}
	return fmt.Sprintf("count=%d sample=%s%s", len(conns), strings.Join(parts, ","), suffix)
}
