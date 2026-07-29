package client

type resolverClassification uint8

const (
	resolverClassificationPending resolverClassification = iota
	resolverClassificationValid
	resolverClassificationRejected
)

type resolverClassificationCounts struct {
	Total    int
	Valid    int
	Rejected int
	Pending  int
}

func (c *Client) resetResolverClassificationsPending() {
	if c == nil {
		return
	}
	c.resolverClassificationMu.Lock()
	defer c.resolverClassificationMu.Unlock()

	c.resolverClassifications = make(map[string]resolverClassification, len(c.connections))
	for _, conn := range c.connections {
		if conn.Key == "" {
			continue
		}
		c.resolverClassifications[conn.Key] = resolverClassificationPending
	}
}

func (c *Client) resetResolverClassificationsFromConnections() {
	if c == nil {
		return
	}
	c.resolverClassificationMu.Lock()
	defer c.resolverClassificationMu.Unlock()

	c.resolverClassifications = make(map[string]resolverClassification, len(c.connections))
	for _, conn := range c.connections {
		if conn.Key == "" {
			continue
		}
		if conn.IsValid || (conn.UploadMTUBytes > 0 && conn.DownloadMTUBytes > 0) {
			c.resolverClassifications[conn.Key] = resolverClassificationValid
			continue
		}
		c.resolverClassifications[conn.Key] = resolverClassificationPending
	}
}

func (c *Client) markResolverValid(key string) {
	if c == nil || key == "" {
		return
	}
	c.resolverClassificationMu.Lock()
	defer c.resolverClassificationMu.Unlock()

	if c.resolverClassifications == nil {
		c.resolverClassifications = make(map[string]resolverClassification)
	}
	c.resolverClassifications[key] = resolverClassificationValid
}

func (c *Client) markResolverRejected(key string) {
	if c == nil || key == "" {
		return
	}
	c.resolverClassificationMu.Lock()
	defer c.resolverClassificationMu.Unlock()

	if c.resolverClassifications == nil {
		c.resolverClassifications = make(map[string]resolverClassification)
	}
	if c.resolverClassifications[key] == resolverClassificationValid {
		return
	}
	c.resolverClassifications[key] = resolverClassificationRejected
}

func (c *Client) resolverClassificationSnapshot() map[string]resolverClassification {
	if c == nil {
		return nil
	}
	c.resolverClassificationMu.RLock()
	defer c.resolverClassificationMu.RUnlock()

	if len(c.resolverClassifications) == 0 {
		return nil
	}
	snapshot := make(map[string]resolverClassification, len(c.resolverClassifications))
	for key, classification := range c.resolverClassifications {
		snapshot[key] = classification
	}
	return snapshot
}

func fallbackResolverClassification(conn Connection) resolverClassification {
	if conn.IsValid || (conn.UploadMTUBytes > 0 && conn.DownloadMTUBytes > 0) {
		return resolverClassificationValid
	}
	return resolverClassificationPending
}
