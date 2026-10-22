package client

import (
	"context"
	"time"

	"cottendns-go/internal/cottenmax"
	dnsParser "cottendns-go/internal/dnsparser"
)

func (c *Client) dispatchCottenMaxDNS(engine *cottenmax.Client, query []byte, key string, group *dnsPendingGroup) {
	// The local SOCKS listener reuses its input buffer immediately.
	query = append([]byte(nil), query...)
	go func() {
		timeout := c.cfg.DNSResponseFragmentTimeout()
		if timeout <= 0 {
			timeout = 30 * time.Second
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		response, err := engine.ExchangeDNS(ctx, query)
		if err != nil {
			if group != nil {
				c.expirePendingDNS(key, group)
			}
			return
		}
		parsed, err := dnsParser.ParsePacketLite(response)
		if err != nil || !parsed.HasQuestion {
			if group != nil {
				c.expirePendingDNS(key, group)
			}
			return
		}
		c.txTotalBytes.Add(uint64(len(query)))
		c.rxTotalBytes.Add(uint64(len(response)))
		c.completePendingDNS(response, parsed.FirstQuestion)
	}()
}
