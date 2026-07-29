package client

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

const (
	resolverRuntimeStateHeartbeatInterval = 30 * time.Second
	resolverRuntimeStateSampleLimit       = 4096
)

type resolverRuntimeListSnapshot struct {
	Sample   []string
	Count    int
	Complete bool
}

func (c *Client) finalizeValidResolvers(validConns []Connection) ([]Connection, int, int, int) {
	if c == nil {
		return nil, 0, 0, 0
	}

	c.balancer.RefreshValidConnections()
	_, minUpload, minDownload, minUploadChars := summarizeValidMTUConnections(c.connections)
	c.logResolverRuntimeState()
	return validConns, minUpload, minDownload, minUploadChars
}

func (c *Client) logResolverRuntimeState() {
	if c == nil || c.log == nil {
		return
	}
	active, standby, valid, counts := c.resolverRuntimeSnapshot()
	line := c.resolverRuntimeStateLogLine(active, standby, valid, counts)
	if !c.shouldEmitResolverRuntimeState(line, c.now()) {
		return
	}
	c.log.Machinef("%s", line)
}

func (c *Client) resolverRuntimeStateLogLine(active resolverRuntimeListSnapshot, standby resolverRuntimeListSnapshot, valid resolverRuntimeListSnapshot, counts resolverClassificationCounts) string {
	return fmt.Sprintf(
		"WD_RESOLVERS total_count=%d active_count=%d active_sample=%s active_complete=%t standby_count=%d standby_sample=%s standby_complete=%t valid_count=%d valid_sample=%s valid_complete=%t rejected_count=%d pending_count=%d",
		counts.Total,
		active.Count,
		formatResolverRuntimeList(active.Sample),
		active.Complete,
		standby.Count,
		formatResolverRuntimeList(standby.Sample),
		standby.Complete,
		valid.Count,
		formatResolverRuntimeList(valid.Sample),
		valid.Complete,
		counts.Rejected,
		counts.Pending,
	)
}

func (c *Client) shouldEmitResolverRuntimeState(line string, now time.Time) bool {
	if c == nil || line == "" {
		return false
	}
	c.resolverRuntimeLogMu.Lock()
	defer c.resolverRuntimeLogMu.Unlock()

	isHeartbeatDue := c.lastResolverRuntimeLogAt.IsZero() ||
		now.Sub(c.lastResolverRuntimeLogAt) >= resolverRuntimeStateHeartbeatInterval
	if line == c.lastResolverRuntimeLog && !isHeartbeatDue {
		return false
	}

	c.lastResolverRuntimeLog = line
	c.lastResolverRuntimeLogAt = now
	return true
}

func (c *Client) resolverRuntimeSnapshot() (active resolverRuntimeListSnapshot, standby resolverRuntimeListSnapshot, valid resolverRuntimeListSnapshot, counts resolverClassificationCounts) {
	if c == nil {
		return active, standby, valid, counts
	}
	classifications := c.resolverClassificationSnapshot()
	for _, conn := range c.connections {
		if conn.Key == "" || conn.ResolverLabel == "" {
			continue
		}
		counts.Total++
		classification, ok := classifications[conn.Key]
		if !ok {
			classification = fallbackResolverClassification(conn)
		}
		switch classification {
		case resolverClassificationValid:
			counts.Valid++
			addResolverRuntimeSample(&valid, conn.ResolverLabel)
		case resolverClassificationRejected:
			counts.Rejected++
		default:
			counts.Pending++
		}
		if conn.IsValid {
			addResolverRuntimeSample(&active, conn.ResolverLabel)
		}
	}

	finalizeResolverRuntimeSnapshot(&active)
	finalizeResolverRuntimeSnapshot(&standby)
	finalizeResolverRuntimeSnapshot(&valid)
	return active, standby, valid, counts
}

func addResolverRuntimeSample(snapshot *resolverRuntimeListSnapshot, resolver string) {
	snapshot.Count++
	if len(snapshot.Sample) < resolverRuntimeStateSampleLimit {
		snapshot.Sample = append(snapshot.Sample, resolver)
	}
}

func finalizeResolverRuntimeSnapshot(snapshot *resolverRuntimeListSnapshot) {
	slices.Sort(snapshot.Sample)
	snapshot.Complete = snapshot.Count == len(snapshot.Sample)
}

func formatResolverRuntimeList(values []string) string {
	if len(values) == 0 {
		return "-"
	}
	return strings.Join(values, ",")
}
