package resolver

import (
	"sync"
	"time"
)

// CacheEntry представляет собой запись в кэше
type CacheEntry struct {
	Response  []byte
	ExpiresAt time.Time
}

// Cache представляет DNS-кэш
type Cache struct {
	mu    sync.RWMutex // Мьютекс для безопасного доступа к карте
	entries map[string]CacheEntry
}

// NewCache создает новый экземпляр кэша
func NewCache() *Cache {
	c := &Cache{
		entries: make(map[string]CacheEntry),
	}
	// Запускаем горутину для периодической очистки устаревших записей
	go c.cleanupLoop()
	return c
}

// Get извлекает запись из кэша
func (c *Cache) Get(key string) ([]byte, bool) {
	c.mu.RLock() // Используем RLock для чтения
	defer c.mu.RUnlock()

	entry, found := c.entries[key]
	if !found {
		return nil, false
	}
	if time.Now().After(entry.ExpiresAt) {
		// Запись устарела, удаляем ее
		delete(c.entries, key)
		return nil, false
	}
	return entry.Response, true
}

// Set добавляет запись в кэш
func (c *Cache) Set(key string, response []byte, ttlSeconds uint32) {
	c.mu.Lock() // Используем Lock для записи
	defer c.mu.Unlock()

	c.entries[key] = CacheEntry{
		Response:  response,
		ExpiresAt: time.Now().Add(time.Duration(ttlSeconds) * time.Second),
	}
}

// cleanupLoop периодически очищает устаревшие записи из кэша
func (c *Cache) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute) // Проверяем кэш каждую минуту
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
