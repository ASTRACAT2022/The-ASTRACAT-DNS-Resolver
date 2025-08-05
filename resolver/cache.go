package resolver

import (
	"sync"
	"time"
)

type CacheEntry struct {
	Response    []byte
	ExpiresAt   time.Time
	OriginalTTL time.Duration
	QueryName   string
	QueryType   string
}

type Cache struct {
	mu      sync.RWMutex
	entries map[string]CacheEntry
}

func NewCache() *Cache {
	c := &Cache{
		entries: make(map[string]CacheEntry),
	}
	go c.cleanupLoop()
	return c
}

func (c *Cache) Get(key string) ([]byte, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, found := c.entries[key]
	if !found {
		return nil, false
	}
	if time.Now().After(entry.ExpiresAt) {
		delete(c.entries, key)
		return nil, false
	}
	return entry.Response, true
}

func (c *Cache) Set(key string, response []byte, ttlSeconds uint32, queryName, queryType string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[key] = CacheEntry{
		Response:    response,
		ExpiresAt:   time.Now().Add(time.Duration(ttlSeconds) * time.Second),
		OriginalTTL: time.Duration(ttlSeconds) * time.Second,
		QueryName:   queryName,
		QueryType:   queryType,
	}
}

func (c *Cache) GetSoonToExpireEntries(ratio float64) []*CacheEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var soonToExpire []*CacheEntry
	now := time.Now()
	for _, entry := range c.entries {
		ttlRemaining := entry.ExpiresAt.Sub(now)
		if ttlRemaining > 0 && float64(ttlRemaining)/float64(entry.OriginalTTL) <= ratio {
			soonToExpire = append(soonToExpire, &entry)
		}
	}
	return soonToExpire
}

func (c *Cache) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		for key, entry := range c.entries {
			if time.Now().After(entry.ExpiresAt) {
				delete(c.entries, key)
			}
		}
		c.mu.Unlock()
	}
}
