package client

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"cottendns-go/internal/cottenmax"
)

const (
	cottenMaxDiscoveryCacheVersion = 1
	cottenMaxDiscoveryCacheEntries = 256
	cottenMaxDiscoveryCacheBytes   = 64 << 10
	cottenMaxDiscoveryCacheTTL     = 24 * time.Hour
)

// cottenMaxDiscovery does no network work. The engine tries candidates lazily,
// without waiting for a scan, and authenticates each path on every run. A cache
// is a startup hint, never a source of trusted sessions or server identities.
func (c *Client) cottenMaxDiscovery(resolvers []string) cottenmax.Discovery {
	d := cottenmax.Discovery{
		Enabled:        c.cfg.ResolverDiscoveryEnabled,
		Country:        c.cfg.ResolverDiscoveryCountry,
		SampleRanges:   c.cfg.ResolverDiscoverySampleRanges,
		Want:           c.cfg.ResolverDiscoveryWant,
		Concurrency:    c.cfg.ResolverDiscoveryConcurrency,
		Pace:           time.Duration(c.cfg.ResolverDiscoveryPaceMilliseconds) * time.Millisecond,
		Candidates:     filterCottenMaxResolvers(c.cfg.ResolverDiscoveryCandidates, c.cfg.ResolverIPMode),
		AcceptResolver: c.cottenMaxResolverAllowed,
	}
	// The caller keeps its explicitly configured resolvers ahead of discovery;
	// include them in this bounded candidate list too, preserving port diversity
	// when a future engine starts discovery without any initial active paths.
	d.Candidates = filterCottenMaxResolvers(append(append([]string(nil), resolvers...), d.Candidates...), c.cfg.ResolverIPMode)
	if !d.Enabled {
		return d
	}
	path := strings.TrimSpace(c.cfg.ResolverDiscoveryCacheFile)
	if path == "" {
		return d
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(c.cfg.ConfigDir, path)
	}
	d.Cache = &cottenMaxResolverCache{path: path, scope: c.cottenMaxDiscoveryScope(), family: c.cfg.ResolverIPMode}
	return d
}

// A backup domain may be reachable through a different resolver set. Keep its
// hints independent, and construct this lazily when failover first needs it.
// CacheFile is a user-selected base path; the short opaque scope suffix avoids
// domains, credentials and explicit network labels overwriting one another.
func (c *Client) cottenMaxDiscoveryForDomain(domain string, resolvers []string) cottenmax.Discovery {
	profile := &Client{cfg: c.cfg}
	profile.cfg.Domains = []string{domain}
	if base := strings.TrimSpace(profile.cfg.ResolverDiscoveryCacheFile); base != "" {
		profile.cfg.ResolverDiscoveryCacheFile = base + "." + profile.cottenMaxDiscoveryScope()[:24]
	}
	return profile.cottenMaxDiscovery(resolvers)
}

func (c *Client) cottenMaxResolverAllowed(resolver string) bool {
	_, ok := cottenMaxResolverEndpoint(resolver, c.cfg.ResolverIPMode)
	return ok
}

func cottenMaxResolverEndpoint(text, family string) (string, bool) {
	text = strings.TrimSpace(text)
	ap, err := netip.ParseAddrPort(text)
	if err != nil {
		a, parseErr := netip.ParseAddr(text)
		if parseErr != nil {
			return "", false
		}
		ap = netip.AddrPortFrom(a, 53)
	}
	a := ap.Addr().Unmap()
	if ap.Port() == 0 || a.IsUnspecified() || a.IsMulticast() ||
		(family == "ipv4" && !a.Is4()) || (family == "ipv6" && !a.Is6()) {
		return "", false
	}
	return netip.AddrPortFrom(a, ap.Port()).String(), true
}

func filterCottenMaxResolvers(in []string, family string) []string {
	seen := make(map[string]struct{}, min(len(in), cottenMaxDiscoveryCacheEntries))
	out := make([]string, 0, min(len(in), cottenMaxDiscoveryCacheEntries))
	for _, text := range in {
		endpoint, ok := cottenMaxResolverEndpoint(text, family)
		if !ok {
			continue
		}
		if _, duplicate := seen[endpoint]; duplicate {
			continue
		}
		seen[endpoint] = struct{}{}
		out = append(out, endpoint)
		if len(out) == cottenMaxDiscoveryCacheEntries {
			break
		}
	}
	return out
}

// The optional network label is supplied by the user/app; it is not a claim
// that CottenDNS can reliably infer a network identity. Changing networks may
// reuse stale candidates without a label; fresh authentication is still needed.
// Store only this digest, never the credential or a raw network identifier.
func (c *Client) cottenMaxDiscoveryScope() string {
	domains := make([]string, 0, len(c.cfg.Domains))
	for _, domain := range c.cfg.Domains {
		domains = append(domains, strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), "."))
	}
	parts := []string{
		"CottenDNS CottenMax resolver discovery cache v1", strings.Join(domains, ","),
		c.cfg.EncryptionKey, c.cfg.CottenMaxServerPublicKey,
		c.cfg.ResolverTransport, c.cfg.ResolverIPMode,
		c.cfg.ResolverTLSServerName, c.cfg.ResolverTLSPin,
		strconv.FormatBool(c.cfg.ResolverTLSInsecureSkipVerify),
		strconv.Itoa(c.cfg.ResolverDoTPort), strconv.Itoa(c.cfg.ResolverDoHPort), c.cfg.ResolverDoHPath,
		strconv.Itoa(c.cfg.ResolverDoQPort), strconv.FormatBool(c.cfg.ResolverHTTP3Fallback),
		strconv.Itoa(c.cfg.DNSPaddingBlockSize),
		strings.TrimSpace(c.cfg.ResolverDiscoveryNetworkID),
	}
	raw, _ := json.Marshal(parts)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

type cottenMaxResolverCache struct {
	path, scope, family string
	now                 func() time.Time // test clock; nil means time.Now
}

type cottenMaxResolverCacheFile struct {
	Version   int       `json:"version"`
	Scope     string    `json:"scope"`
	StoredAt  time.Time `json:"stored_at"`
	Resolvers []string  `json:"resolvers"`
}

func (c *cottenMaxResolverCache) currentTime() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

func (c *cottenMaxResolverCache) Load() []string {
	lock := cottenMaxCacheLock(c.path)
	lock.Lock()
	defer lock.Unlock()
	// Ignore symlinks, special files and oversized files. Cache failure never
	// prevents use of an explicit resolver or another discovery candidate.
	info, err := os.Lstat(c.path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > cottenMaxDiscoveryCacheBytes {
		return nil
	}
	f, err := os.Open(c.path)
	if err != nil {
		return nil
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, cottenMaxDiscoveryCacheBytes+1))
	if err != nil || len(raw) > cottenMaxDiscoveryCacheBytes {
		return nil
	}
	var saved cottenMaxResolverCacheFile
	if json.Unmarshal(raw, &saved) != nil || saved.Version != cottenMaxDiscoveryCacheVersion || saved.Scope != c.scope ||
		len(saved.Resolvers) > cottenMaxDiscoveryCacheEntries || saved.StoredAt.IsZero() {
		return nil
	}
	// Refuse stale and substantially future-dated data after clock changes.
	age := c.currentTime().Sub(saved.StoredAt)
	if age < -5*time.Minute || age >= cottenMaxDiscoveryCacheTTL {
		return nil
	}
	return filterCottenMaxResolvers(saved.Resolvers, c.family)
}

// Store runs on the engine's cache goroutine after an authenticated response.
// Use an independent temporary file and atomic rename so interrupted writes
// cannot replace a working cache with a partially written JSON document.
func (c *cottenMaxResolverCache) Store(resolvers []string) {
	lock := cottenMaxCacheLock(c.path)
	lock.Lock()
	defer lock.Unlock()
	saved := cottenMaxResolverCacheFile{
		Version: cottenMaxDiscoveryCacheVersion, Scope: c.scope,
		StoredAt: c.currentTime().UTC(), Resolvers: filterCottenMaxResolvers(resolvers, c.family),
	}
	raw, err := json.Marshal(saved)
	if err != nil || len(raw) > cottenMaxDiscoveryCacheBytes {
		return
	}
	dir := filepath.Dir(c.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return
	}
	f, err := os.CreateTemp(dir, ".cottenmax-resolvers-*")
	if err != nil {
		return
	}
	temp := f.Name()
	defer os.Remove(temp)
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return
	}
	if _, err := f.Write(raw); err != nil {
		f.Close()
		return
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return
	}
	if err := f.Close(); err != nil {
		return
	}
	if err := os.Rename(temp, c.path); err != nil {
		return
	}
	// Best effort directory sync on systems that support it.
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}

// Fixed lock striping bounds memory and coordinates separate cache instances.
// Windows replacement is not guaranteed atomic while another handle is open.
var cottenMaxCacheLocks [64]sync.Mutex

func cottenMaxCacheLock(path string) *sync.Mutex {
	if absolute, err := filepath.Abs(path); err == nil {
		path = absolute
	}
	key := sha256.Sum256([]byte(strings.ToLower(filepath.Clean(path))))
	return &cottenMaxCacheLocks[int(key[0])%len(cottenMaxCacheLocks)]
}
