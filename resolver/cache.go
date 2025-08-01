package resolver

import (
	"sync"
	"time"
)

// CacheEntry - структура для хранения кэшированных DNS-ответов.
type CacheEntry struct {
	Response    []byte
	ExpiresAt   time.Time
	OriginalTTL time.Duration
	QueryName   string
	QueryType   string
}

// Cache - структура для кэширования DNS-ответов с блокировками для безопасности горутин.
type Cache struct {
	mu      sync.RWMutex
	entries map[string]CacheEntry
	// cleanupInterval - интервал, с которым запускается фоновая очистка.
	cleanupInterval time.Duration
}

// NewCache создает новый экземпляр Cache и запускает фоновый цикл очистки.
// Теперь принимает интервал для цикла очистки.
func NewCache(cleanupInterval time.Duration) *Cache {
	c := &Cache{
		entries:         make(map[string]CacheEntry),
		cleanupInterval: cleanupInterval,
	}
	go c.cleanupLoop()
	return c
}

// Get извлекает запись из кэша по ключу.
func (c *Cache) Get(key string) ([]byte, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, found := c.entries[key]
	if !found {
		return nil, false
	}
	// Если запись истекла, удаляем её и возвращаем false.
	if time.Now().After(entry.ExpiresAt) {
		delete(c.entries, key)
		return nil, false
	}
	return entry.Response, true
}

// Set сохраняет запись в кэше с заданным TTL.
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

// GetSoonToExpireEntries возвращает список записей, которые скоро истекут.
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

// cleanupLoop - фоновый цикл для периодической очистки устаревших записей.
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
