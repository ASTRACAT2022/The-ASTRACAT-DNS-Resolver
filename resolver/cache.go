package resolver

import (
	"container/list"
	"sync"
	"time"
)

// RR - структура, представляющая DNS-запись.
type RR struct {
	Name    string
	Type    string
	Value   string
	Expiry  time.Time
	TTL     uint32
}

// RRs - срез DNS-записей.
type RRs []*RR

// CacheEntry - структура для хранения кэшированных DNS-ответов.
type CacheEntry struct {
	// Value представляет DNS-ответы.
	Value       RRs
	// ExpiresAt - время истечения TTL.
	ExpiresAt   time.Time
	// OriginalTTL - исходный TTL записи.
	OriginalTTL time.Duration
	// Key - ключ в кэше, обычно "qname/qtype".
	Key         string
}

// cache - структура для LRU-кэша DNS-ответов.
type cache struct {
	// mu обеспечивает безопасный доступ к полям структуры из разных горутин.
	mu       sync.RWMutex
	// capacity - максимальное количество записей в кэше.
	capacity int
	// expire - флаг, указывающий на использование TTL.
	expire   bool
	// entries - map для быстрого доступа к элементам списка LRU.
	entries  map[string]*list.Element
	// lruList - двусвязный список для отслеживания порядка использования (LRU).
	lruList  *list.List
}

const MinCacheCapacity = 1000

// newCache инициализирует и возвращает новый экземпляр LRU-кэша.
// Он использует комбинацию map и двусвязного списка для высокой производительности.
func newCache(capacity int, expire bool) *cache {
	if capacity <= 0 {
		capacity = MinCacheCapacity
	}
	return &cache{
		capacity: capacity,
		expire:   expire,
		entries:  make(map[string]*list.Element),
		lruList:  list.New(),
	}
}

// get извлекает запись из кэша по ключу.
// Если запись найдена и не истекла, она перемещается в начало списка LRU.
func (c *cache) get(key string) RRs {
	c.mu.RLock()
	defer c.mu.RUnlock()

	element, found := c.entries[key]
	if !found {
		return nil
	}

	entry := element.Value.(*CacheEntry)
	
	// Если запись истекла, удаляем её и возвращаем nil.
	if c.expire && time.Now().After(entry.ExpiresAt) {
		c._removeElement(element)
		return nil
	}
	
	// Перемещаем элемент в начало списка (самый "недавно использованный").
	c.lruList.MoveToFront(element)
	
	return entry.Value
}

// add сохраняет запись в кэше. Если кэш заполнен, удаляет самую старую запись.
func (c *cache) add(key string, rrs RRs, ttl uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if element, found := c.entries[key]; found {
		// Обновляем существующую запись.
		entry := element.Value.(*CacheEntry)
		entry.Value = rrs
		if c.expire {
			entry.ExpiresAt = time.Now().Add(time.Duration(ttl) * time.Second)
			entry.OriginalTTL = time.Duration(ttl) * time.Second
		}
		c.lruList.MoveToFront(element)
		return
	}
	
	// Если кэш достиг максимальной ёмкости, удаляем самую старую запись.
	if c.lruList.Len() >= c.capacity {
		c._evictOldest()
	}

	// Добавляем новую запись в кэш и в начало списка LRU.
	entry := &CacheEntry{
		Key:   key,
		Value: rrs,
	}
	if c.expire {
		entry.ExpiresAt = time.Now().Add(time.Duration(ttl) * time.Second)
		entry.OriginalTTL = time.Duration(ttl) * time.Second
	}
	element := c.lruList.PushFront(entry)
	c.entries[key] = element
}

// addNX добавляет запись NXDOMAIN в кэш с заданным TTL.
func (c *cache) addNX(key string, ttl uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Добавляем пустую запись с TTL, чтобы избежать повторных запросов NXDOMAIN.
	if element, found := c.entries[key]; found {
		c.lruList.MoveToFront(element)
		return
	}
	
	if c.lruList.Len() >= c.capacity {
		c._evictOldest()
	}

	entry := &CacheEntry{
		Key:   key,
		Value: nil,
	}
	if c.expire {
		entry.ExpiresAt = time.Now().Add(time.Duration(ttl) * time.Second)
		entry.OriginalTTL = time.Duration(ttl) * time.Second
	}
	element := c.lruList.PushFront(entry)
	c.entries[key] = element
}

// _evictOldest удаляет самую старую (Least Recently Used) запись из кэша.
// Небезопасен для конкурентного использования, должен вызываться с блокировкой.
func (c *cache) _evictOldest() {
	element := c.lruList.Back()
	if element != nil {
		c._removeElement(element)
	}
}

// _removeElement удаляет элемент из кэша.
// Небезопасен для конкурентного использования, должен вызываться с блокировкой.
func (c *cache) _removeElement(e *list.Element) {
	c.lruList.Remove(e)
	delete(c.entries, e.Value.(*CacheEntry).Key)
}

// GetSoonToExpireEntries возвращает список записей, которые скоро истекут.
func (c *cache) GetSoonToExpireEntries(ratio float64) []*CacheEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var soonToExpire []*CacheEntry
	now := time.Now()
	for _, element := range c.entries {
		entry := element.Value.(*CacheEntry)
		if c.expire {
			ttlRemaining := entry.ExpiresAt.Sub(now)
			// Проверяем, если осталось меньше 10% от исходного TTL.
			if ttlRemaining > 0 && float64(ttlRemaining)/float64(entry.OriginalTTL) < ratio {
				soonToExpire = append(soonToExpire, entry)
			}
		}
	}
	return soonToExpire
}

// GetStats возвращает статистику кэша.
func (c *cache) GetStats() (int, int) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lruList.Len(), c.capacity
}
