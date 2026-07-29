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

func (c *Client) resetResolverClassificationsPending(connections []Connection) {
	if c == nil {
		return
	}
	c.resolverClassMu.Lock()
	defer c.resolverClassMu.Unlock()

	c.resolverClass = make(map[string]resolverClassification, len(connections))
	for _, conn := range connections {
		if conn.Key == "" {
			continue
		}
		c.resolverClass[conn.Key] = resolverClassificationPending
	}
}

func (c *Client) markResolverValid(key string) {
	if c == nil || key == "" {
		return
	}
	c.resolverClassMu.Lock()
	defer c.resolverClassMu.Unlock()

	if c.resolverClass == nil {
		c.resolverClass = make(map[string]resolverClassification)
	}
	c.resolverClass[key] = resolverClassificationValid
}

func (c *Client) markResolverRejected(key string) {
	if c == nil || key == "" {
		return
	}
	c.resolverClassMu.Lock()
	defer c.resolverClassMu.Unlock()

	if c.resolverClass == nil {
		c.resolverClass = make(map[string]resolverClassification)
	}
	if c.resolverClass[key] == resolverClassificationValid {
		return
	}
	c.resolverClass[key] = resolverClassificationRejected
}

func (c *Client) resolverClassificationSnapshot() map[string]resolverClassification {
	if c == nil {
		return nil
	}
	c.resolverClassMu.RLock()
	defer c.resolverClassMu.RUnlock()

	if len(c.resolverClass) == 0 {
		return nil
	}
	snapshot := make(map[string]resolverClassification, len(c.resolverClass))
	for key, classification := range c.resolverClass {
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
