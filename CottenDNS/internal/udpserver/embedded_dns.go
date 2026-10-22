package udpserver

import (
	"crypto/sha256"
	"encoding/binary"
	"time"

	DnsParser "cottendns-go/internal/dnsparser"
)

// The shared cache's retention is an idle eviction interval. Embedded replies
// additionally expire at their DNS TTL, even when repeatedly requested.
type embeddedDNSCacheEntry struct {
	storedAt  time.Time
	expiresAt time.Time
	ttlFields []int
}

func (s *Server) dnsAccountAllowed() bool {
	return s != nil && (s.embeddedAllowed == nil || s.embeddedAllowed())
}

// Include all policy-bearing request bytes (CD, DO, EDNS options and size),
// excluding only the transaction ID and the case of an uncompressed QNAME.
func embeddedDNSQueryKey(query []byte, base string) string {
	canonical := append([]byte(nil), query...)
	if len(canonical) >= 2 {
		canonical[0], canonical[1] = 0, 0
	}
	if len(canonical) < 12 || binary.BigEndian.Uint16(canonical[4:6]) != 1 {
		hash := sha256.Sum256(canonical)
		return base + string(hash[:])
	}
	for offset := 12; offset < len(canonical); {
		n := int(canonical[offset])
		offset++
		if n == 0 || n > 63 || offset+n > len(canonical) {
			break
		}
		for i := offset; i < offset+n; i++ {
			if canonical[i] >= 'A' && canonical[i] <= 'Z' {
				canonical[i] += 'a' - 'A'
			}
		}
		offset += n
	}
	hash := sha256.Sum256(canonical)
	return base + string(hash[:])
}

func patchEmbeddedDNSQuestion(response, query []byte) []byte {
	r, re := DnsParser.ParsePacketLite(response)
	q, qe := DnsParser.ParseDNSRequestLite(query)
	if re == nil && qe == nil && r.Header.QDCount == 1 && q.Header.QDCount == 1 && r.FirstQuestion == q.FirstQuestion && r.QuestionEndOffset == q.QuestionEndOffset {
		copy(response[12:r.QuestionEndOffset], query[12:q.QuestionEndOffset])
	}
	return response
}

func (s *Server) cachedDNSResponse(key string, query []byte, now time.Time) ([]byte, bool) {
	if !s.dnsAccountAllowed() {
		return nil, false
	}
	if s.embeddedDNSExchange == nil {
		return s.dnsCache.GetReady(key, query, now)
	}
	s.embeddedDNSCacheMu.Lock()
	defer s.embeddedDNSCacheMu.Unlock()
	entry, ok := s.embeddedDNSCache[key]
	if !ok || !now.Before(entry.expiresAt) {
		delete(s.embeddedDNSCache, key)
		return nil, false
	}
	response, ok := s.dnsCache.GetReady(key, query, now)
	if !ok {
		delete(s.embeddedDNSCache, key)
		return nil, false
	}
	age := uint32(max(now.Sub(entry.storedAt)/time.Second, 0))
	remaining := uint32(max(entry.expiresAt.Sub(now)/time.Second, 0))
	for _, offset := range entry.ttlFields {
		ttl := binary.BigEndian.Uint32(response[offset : offset+4])
		binary.BigEndian.PutUint32(response[offset:offset+4], min(ttl-min(ttl, age), remaining))
	}
	return patchEmbeddedDNSQuestion(response, query), true
}

func (s *Server) cacheEmbeddedDNSResponse(key string, query, response []byte, question DnsParser.Question, now time.Time) {
	parsed, err := DnsParser.ParsePacketLite(response)
	if err != nil || parsed.Header.QR != 1 || parsed.Header.TC != 0 || parsed.Header.QDCount != 1 || parsed.FirstQuestion != question || (parsed.Header.RCode != 0 && parsed.Header.RCode != 3) {
		return
	}
	if len(query) < 2 || len(response) < 2 || binary.BigEndian.Uint16(query[:2]) != binary.BigEndian.Uint16(response[:2]) || (s.cfg.MaxDNSResponseBytes > 0 && len(response) > s.cfg.MaxDNSResponseBytes) {
		return
	}
	fields, ttl, ok := embeddedDNSTTLFields(response, parsed)
	if !ok || ttl == 0 {
		return
	}
	lifetime := time.Duration(ttl) * time.Second
	if configured := time.Duration(s.cfg.DNSCacheTTLSeconds * float64(time.Second)); configured > 0 && configured < lifetime {
		lifetime = configured
	}
	s.embeddedDNSCacheMu.Lock()
	defer s.embeddedDNSCacheMu.Unlock()
	if s.embeddedDNSCache == nil {
		s.embeddedDNSCache = make(map[string]embeddedDNSCacheEntry)
	}
	for existingKey, entry := range s.embeddedDNSCache {
		if !now.Before(entry.expiresAt) {
			delete(s.embeddedDNSCache, existingKey)
		}
	}
	limit := max(s.cfg.DNSCacheMaxRecords, 32)
	if _, exists := s.embeddedDNSCache[key]; !exists && len(s.embeddedDNSCache) >= limit {
		var oldestKey string
		var oldest time.Time
		for existingKey, entry := range s.embeddedDNSCache {
			if oldestKey == "" || entry.storedAt.Before(oldest) {
				oldestKey, oldest = existingKey, entry.storedAt
			}
		}
		delete(s.embeddedDNSCache, oldestKey)
	}
	s.dnsCache.SetReady(key, question.Name, question.Type, question.Class, response, now)
	s.embeddedDNSCache[key] = embeddedDNSCacheEntry{storedAt: now, expiresAt: now.Add(lifetime), ttlFields: fields}
}

func embeddedDNSNameEnd(wire []byte, offset int) (int, bool) {
	for offset < len(wire) {
		n := int(wire[offset])
		offset++
		if n == 0 {
			return offset, true
		}
		if n&0xc0 == 0xc0 {
			return offset + 1, offset < len(wire)
		}
		if n > 63 || offset+n > len(wire) {
			return 0, false
		}
		offset += n
	}
	return 0, false
}

func embeddedDNSTTLFields(wire []byte, parsed DnsParser.LitePacket) ([]int, uint32, bool) {
	var fields []int
	ttl := ^uint32(0)
	negative := parsed.Header.RCode == 3 || parsed.Header.ANCount == 0
	hasSOA := false
	offset := parsed.QuestionEndOffset
	count := int(parsed.Header.ANCount) + int(parsed.Header.NSCount) + int(parsed.Header.ARCount)
	for i := 0; i < count; i++ {
		var ok bool
		offset, ok = embeddedDNSNameEnd(wire, offset)
		if !ok || offset+10 > len(wire) {
			return nil, 0, false
		}
		kind := binary.BigEndian.Uint16(wire[offset : offset+2])
		rdlen := int(binary.BigEndian.Uint16(wire[offset+8 : offset+10]))
		end := offset + 10 + rdlen
		if end > len(wire) {
			return nil, 0, false
		}
		if kind != 41 { // OPT's TTL field holds EDNS flags, not an RR lifetime.
			rrTTL := binary.BigEndian.Uint32(wire[offset+4 : offset+8])
			fields = append(fields, offset+4)
			ttl = min(ttl, rrTTL)
			if kind == 6 && rdlen >= 20 { // RFC 2308 negative SOA lifetime.
				hasSOA = true
				if negative {
					ttl = min(ttl, binary.BigEndian.Uint32(wire[end-4:end]))
				}
			}
		}
		offset = end
	}
	return fields, ttl, len(fields) != 0 && (!negative || hasSOA)
}
