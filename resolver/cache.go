package resolver

import (
	"log"
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
	// Добавлено поле для периодической очистки
	cleanupInterval time.Duration
}

// NewCache создает новый кэш и запускает цикл очистки.
func NewCache(cleanupInterval time.Duration) *Cache {
	c := &Cache{
		entries:         make(map[string]CacheEntry),
		cleanupInterval: cleanupInterval,
	}
	// Запускаем горутину очистки только если интервал задан
	if cleanupInterval > 0 {
		go c.cleanupLoop()
	}
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

// Изменено: цикл очистки теперь использует cleanupInterval
func (c *Cache) cleanupLoop() {
	if c.cleanupInterval == 0 {
		log.Printf("Debug: Cache cleanup loop is not running for this cache.")
		return
	}
	
	ticker := time.NewTicker(c.cleanupInterval)
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
