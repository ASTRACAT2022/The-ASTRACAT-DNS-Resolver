package resolver

import (
	"log"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// CacheEntry - structure for storing cached DNS responses.
type CacheEntry struct {
	Response    []byte
	ExpiresAt   time.Time
	OriginalTTL time.Duration
	QueryName   string
	QueryType   string
}

// Cache - a structure for caching DNS responses with read/write locks for goroutine safety.
type Cache struct {
	mu      sync.RWMutex
	entries map[string]CacheEntry
	// prefetcher is a channel used to signal pre-fetch tasks.
	prefetcher chan string
	// cleanupInterval - the interval at which the background cleanup runs.
	cleanupInterval time.Duration
}

// NewCache creates a new Cache instance and starts the background cleanup loop.
func NewCache(cleanupInterval time.Duration) *Cache {
	c := &Cache{
		entries:         make(map[string]CacheEntry),
		prefetcher:      make(chan string, 100), // Buffered channel for prefetch tasks
		cleanupInterval: cleanupInterval,
	}
	go c.cleanupLoop()
	return c
}

// Get retrieves a cached entry by key.
func (c *Cache) Get(key string) ([]byte, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, found := c.entries[key]
	if !found {
		return nil, false
	}
	// If the entry has expired, delete it and return false.
	if time.Now().After(entry.ExpiresAt) {
		delete(c.entries, key)
		return nil, false
	}
	// Check if the entry is nearing expiration and needs pre-fetching.
	ttlRemaining := entry.ExpiresAt.Sub(time.Now())
	if ttlRemaining > 0 && float64(ttlRemaining)/float64(entry.OriginalTTL) < prefetchThresholdRatio {
		// Non-blocking send to the prefetcher channel.
		select {
		case c.prefetcher <- entry.QueryName + "/" + entry.QueryType:
		default:
			// Channel is full, do nothing to avoid blocking.
		}
	}
	
	return entry.Response, true
}

// Set stores an entry in the cache with a given TTL.
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

// cleanupLoop periodically removes expired entries from the cache to keep it clean.
func (c *Cache) cleanupLoop() {
	ticker := time.NewTicker(c.cleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for key, entry := range c.entries {
			if now.After(entry.ExpiresAt) {
				delete(c.entries, key)
			}
		}
		c.mu.Unlock()
	}
}

// GetSoonToExpireEntries returns a list of entries that are about to expire.
func (c *Cache) GetSoonToExpireEntries(ratio float64) []*CacheEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var soonToExpire []*CacheEntry
	now := time.Now()
	for _, entry := range c.entries {
		ttlRemaining := entry.ExpiresAt.Sub(now)
		if ttlRemaining > 0 && float64(ttlRemaining)/float64(entry.OriginalTTL) < ratio {
			soonToExpire = append(soonToExpire, &entry)
		}
	}
	return soonToExpire
}

