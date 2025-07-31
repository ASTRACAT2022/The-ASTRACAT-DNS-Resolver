package resolver

import (
	"container/list" // Импортируем пакет list для реализации LRU
	"sync"
	"time"
)

// CacheEntry представляет собой запись в кэше
type CacheEntry struct {
	Response  []byte
	ExpiresAt time.Time
	OriginalTTL uint32 // Добавлено: оригинальный TTL записи
	QueryName   string // Добавлено: имя запроса
	QueryType   string // Добавлено: тип запроса
	element   *list.Element // Ссылка на элемент в списке LRU
}

// Cache представляет DNS-кэш с поддержкой LRU
type Cache struct {
	mu        sync.RWMutex          // Мьютекс для безопасного доступа к карте и списку
	entries   map[string]*CacheEntry // Теперь храним указатели на CacheEntry
	lruList   *list.List            // Список для отслеживания порядка использования (LRU)
	capacity  int                   // Максимальное количество записей в кэше
}

// NewCache создает новый экземпляр кэша с заданной емкостью
func NewCache() *Cache {
	// Для простоты, установим дефолтную емкость кэша.
	// В реальном приложении это должно быть настраиваемым параметром.
	const defaultCacheCapacity = 10000 // Например, 10 000 записей
	c := &Cache{
		entries:   make(map[string]*CacheEntry),
		lruList:   list.New(),
		capacity:  defaultCacheCapacity,
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
		c.removeElement(entry.element) // Удаляем из LRU списка
		delete(c.entries, key)         // Удаляем из карты
		return nil, false
	}

	// Перемещаем элемент в начало списка (самый недавно использованный)
	c.lruList.MoveToFront(entry.element)
	return entry.Response, true
}

// Set добавляет запись в кэш
func (c *Cache) Set(key string, response []byte, ttlSeconds uint32, queryName, queryType string) {
	c.mu.Lock() // Используем Lock для записи
	defer c.mu.Unlock()

	// Если запись уже существует, обновляем ее и перемещаем в начало
	if entry, found := c.entries[key]; found {
		entry.Response = response
		entry.ExpiresAt = time.Now().Add(time.Duration(ttlSeconds) * time.Second)
		entry.OriginalTTL = ttlSeconds // Обновляем оригинальный TTL
		entry.QueryName = queryName
		entry.QueryType = queryType
		c.lruList.MoveToFront(entry.element)
		return
	}

	// Если кеш переполнен, удаляем наименее используемый элемент (из хвоста списка)
	if c.lruList.Len() >= c.capacity {
		oldest := c.lruList.Back() // Получаем самый старый элемент
		if oldest != nil {
			oldestKey := oldest.Value.(string) // Ключ хранится в элементе списка
			c.removeElement(oldest)            // Удаляем из LRU списка
			delete(c.entries, oldestKey)       // Удаляем из карты по ключу
		}
	}

	// Добавляем новую запись
	entry := &CacheEntry{
		Response:    response,
		ExpiresAt:   time.Now().Add(time.Duration(ttlSeconds) * time.Second),
		OriginalTTL: ttlSeconds,
		QueryName:   queryName,
		QueryType:   queryType,
	}
	// Добавляем новый элемент в начало списка LRU
	entry.element = c.lruList.PushFront(key) // Храним ключ в элементе списка
	c.entries[key] = entry
}

// Remove удаляет запись из кэша по ключу
func (c *Cache) Remove(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if entry, found := c.entries[key]; found {
		c.removeElement(entry.element)
		delete(c.entries, key)
	}
}

// GetSoonToExpireEntries возвращает список записей, которые скоро истекут
func (c *Cache) GetSoonToExpireEntries(prefetchThresholdRatio float64) []*CacheEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var soonToExpire []*CacheEntry
	now := time.Now()

	for _, entry := range c.entries {
		// Рассчитываем оставшееся время жизни
		remainingTime := entry.ExpiresAt.Sub(now)
		originalDuration := time.Duration(entry.OriginalTTL) * time.Second

		// Если запись уже истекла, но еще не удалена cleanupLoop, или скоро истечет
		if remainingTime <= 0 || (originalDuration > 0 && remainingTime.Seconds()/originalDuration.Seconds() < prefetchThresholdRatio) {
			soonToExpire = append(soonToExpire, entry)
		}
	}
	return soonToExpire
}

// removeElement удаляет элемент из LRU списка
func (c *Cache) removeElement(e *list.Element) {
	c.lruList.Remove(e)
}

// cleanupLoop периодически очищает устаревшие записи из кэша
func (c *Cache) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute) // Проверяем кэш каждую минуту
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock() // Блокируем для записи
		now := time.Now()
		for key, entry := range c.entries {
			if now.After(entry.ExpiresAt) {
				c.removeElement(entry.element) // Удаляем из LRU списка
				delete(c.entries, key)         // Удаляем из карты
			}
		}
		c.mu.Unlock()
	}
}
