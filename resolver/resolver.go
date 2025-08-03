package resolver

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Prefetching constants
const (
	// prefetchCheckInterval определяет, как часто мы проверяем кэш на предмет записей, которые нужно предварительно загрузить.
	prefetchCheckInterval = 30 * time.Second
	// prefetchThresholdRatio определяет, какой процент от исходного TTL должен остаться, чтобы запустить предварительную загрузку.
	prefetchThresholdRatio = 0.1
	// prefetchQueryTimeout - таймаут для запроса предварительной загрузки.
	prefetchQueryTimeout = 1 * time.Second

	// rootHintsURL - URL для загрузки актуальных корневых серверов
	rootHintsURL = "https://www.internic.net/domain/named.root"
	// rootHintsUpdateInterval - как часто обновлять корневые серверы
	rootHintsUpdateInterval = 24 * time.Hour

	// adaptiveTimeoutGracePeriod - период, в течение которого сервер не считается медленным
	adaptiveTimeoutGracePeriod = 50 * time.Millisecond
	// adaptiveTimeoutFactor - коэффициент увеличения таймаута для медленных серверов
	adaptiveTimeoutFactor = 2

	// L2CacheCleanupInterval - как часто очищать L2 кэш (например, раз в день)
	L2CacheCleanupInterval = 24 * time.Hour
)

// Resolver - основной тип для нашего DNS-резолвера с добавленными полями для оптимизаций
type Resolver struct {
	cache *Cache
	// cacheL2 - дополнительный кэш с долгим временем жизни для редко используемых записей (L2 кэш).
	cacheL2 *Cache
	// clientPool позволяет переиспользовать UDP-сокеты, уменьшая накладные расходы на их создание.
	// (Пункт 4)
	clientPool *sync.Pool
	// inflightRequests используется для схлопывания запросов.
	// (Пункт 10)
	inflightRequests sync.Map // map[string]chan *dns.Msg
	// nsCache - кэш для NS-серверов популярных доменных зон.
	// (Пункт 1)
	nsCache *Cache
	// rootServers - корневые DNS-серверы, которые могут обновляться.
	// (Пункт 8)
	rootServers     []string
	rootServersLock sync.RWMutex
	// stats - для адаптивного таймаута, хранит статистику по серверам
	// (Пункт 6)
	stats *ServerStats
	// popularityCounter - для анализа запросов и предиктивной предзагрузки
	popularityCounter sync.Map // map[string]int
}

// NewResolver создает новый экземпляр Resolver и запускает циклы
func NewResolver(ctx context.Context) *Resolver {
	r := &Resolver{
		cache:             NewCache(prefetchCheckInterval),
		cacheL2:           NewCache(L2CacheCleanupInterval),
		nsCache:           NewCache(prefetchCheckInterval),
		clientPool:        &sync.Pool{New: func() interface{} { return &dns.Client{UDPSize: 1232} }}, // Пункт 9: Устанавливаем EDNS0 размер UDP-пакета
		stats:             NewServerStats(),
		rootServersLock:   sync.RWMutex{},
		inflightRequests:  sync.Map{},
		popularityCounter: sync.Map{},
	}

	// Первоначальная загрузка корневых серверов
	err := r.updateRootServers(ctx)
	if err != nil {
		log.Printf("Warning: Failed to load root servers from URL, using static list: %v", err)
		r.rootServers = initialRootServers
	}

	// Запускаем горутины для фоновых задач
	go r.prefetchLoop(ctx)
	go r.rootHintsUpdateLoop(ctx)
	go r.cleanupInflightRequests(ctx)
	go r.popularityLoggerLoop(ctx)

	return r
}

// Resolve обрабатывает DNS-запрос и возвращает ответ
// clientAddr - адрес клиента, нужен для ECS.
// Важно: нужно обновить main.go, чтобы передавать сюда net.UDPAddr клиента
func (r *Resolver) Resolve(ctx context.Context, request []byte, clientAddr *net.UDPAddr) ([]byte, error) {
	msg := new(dns.Msg)
	err := msg.Unpack(request)
	if err != nil {
		return nil, fmt.Errorf("ошибка распаковки DNS-запроса: %w", err)
	}

	if len(msg.Question) == 0 {
		return nil, fmt.Errorf("отсутствуют вопросы в DNS-запросе")
	}

	question := msg.Question[0]
	// Генерируем ключ для кэша на основе имени и типа
	cacheKey := fmt.Sprintf("%s_%s", strings.ToLower(question.Name), dns.Type(question.Qtype))

	// Увеличиваем счетчик популярности
	if count, ok := r.popularityCounter.Load(cacheKey); ok {
		r.popularityCounter.Store(cacheKey, count.(int)+1)
	} else {
		r.popularityCounter.Store(cacheKey, 1)
	}

	// Пункт 7: Early exit - быстрая проверка кэша
	if cachedResponse, found := r.cache.Get(cacheKey); found {
		responseMsg := new(dns.Msg)
		if err := responseMsg.Unpack(cachedResponse); err == nil {
			responseMsg.SetReply(msg)
			responseMsg.Authoritative = true
			return responseMsg.Pack()
		}
	}

	// Пункт 5 (часть): Проверяем L2 кэш, если в L1 не нашли
	if cachedResponse, found := r.cacheL2.Get(cacheKey); found {
		responseMsg := new(dns.Msg)
		if err := responseMsg.Unpack(cachedResponse); err == nil {
			responseMsg.SetReply(msg)
			responseMsg.Authoritative = true
			log.Printf("Debug: Cache L2 hit for %s", cacheKey)
			return responseMsg.Pack()
		}
	}


	// Пункт 10: Response collapsing. Проверяем, идет ли уже такой запрос
	ch := make(chan *dns.Msg)
	actualCh, loaded := r.inflightRequests.LoadOrStore(cacheKey, ch)

	if loaded {
		// Запрос уже идет, ждем ответа
		log.Printf("Debug: Request for %s is already in flight, waiting for response.", cacheKey)
		responseMsg := <-actualCh.(chan *dns.Msg)
		responseMsg.SetReply(msg)
		return responseMsg.Pack()
	}

	// Запрос еще не идет, выполняем его
	responseMsg, err := r.recursiveResolve(ctx, question, msg.Id, r.getRootServers(), clientAddr, 0, false)

	// После завершения запроса, удаляем его из in-flight и отправляем ответ всем ожидающим клиентам
	r.inflightRequests.Delete(cacheKey)
	if err == nil {
		ch <- responseMsg
		close(ch)
	} else {
		// Если ошибка, сообщаем об этом всем
		close(ch)
	}

	if err != nil {
		return nil, err
	}

	responseMsg.SetReply(msg)
	return responseMsg.Pack()
}

// recursiveResolve - основная рекурсивная функция для разрешения имени
func (r *Resolver) recursiveResolve(ctx context.Context, question dns.Question, id uint16, servers []string, clientAddr *net.UDPAddr, depth int, isGlueQuery bool) (*dns.Msg, error) {
	if depth > 10 {
		return nil, fmt.Errorf("достигнута максимальная глубина рекурсии для %s", question.Name)
	}

	var (
		wg      sync.WaitGroup
		results = make(chan *dns.Msg, len(servers))
		errors  = make(chan error, len(servers))
	)

	// Перемешиваем список серверов, чтобы распределить нагрузку
	shuffledServers := make([]string, len(servers))
	copy(shuffledServers, servers)
	rand.Shuffle(len(shuffledServers), func(i, j int) {
		shuffledServers[i], shuffledServers[j] = shuffledServers[j], shuffledServers[i]
	})

	for _, serverAddr := range shuffledServers {
		wg.Add(1)
		go func(serverAddr string) {
			defer wg.Done()

			// Пункт 6: Адаптивный таймаут.
			timeout := r.stats.GetTimeout(serverAddr)

			client := r.clientPool.Get().(*dns.Client)
			client.DialTimeout = timeout
			client.ReadTimeout = timeout
			client.WriteTimeout = timeout
			defer r.clientPool.Put(client) // Возвращаем клиент в пул

			msg := new(dns.Msg)
			msg.Id = id
			msg.Question = []dns.Question{question}
			msg.RecursionDesired = true

			// Пункт 1: EDNS0 Client Subnet. Добавляем опцию, если есть адрес клиента
			o := new(dns.EDNS0_SUBNET)
			o.Family = 1 // IPv4
			o.SourceNetmask = net.IPv4len * 8 // Использовать полную маску
			if clientAddr != nil && clientAddr.IP.To4() != nil {
				o.Address = clientAddr.IP.To4()
			} else {
				o.Address = net.IPv4(0, 0, 0, 0)
				o.SourceNetmask = 0
			}
			msg.SetEdns0(1232, true) // Пункт 9: Устанавливаем EDNS0 размер UDP-пакета
			msg.Extra = append(msg.Extra, o)

			start := time.Now()
			response, rtt, err := client.ExchangeContext(ctx, msg, serverAddr)
			end := time.Now()

			// Обновляем статистику для адаптивного таймаута
			r.stats.Update(serverAddr, end.Sub(start))

			if err != nil {
				errors <- fmt.Errorf("запрос к %s завершился с ошибкой: %w", serverAddr, err)
				return
			}
			if response.Rcode != dns.RcodeSuccess && response.Rcode != dns.RcodeNameError {
				errors <- fmt.Errorf("сервер %s вернул Rcode: %d", serverAddr, response.Rcode)
				return
			}

			log.Printf("Debug: Query to %s for %s completed in %s with Rcode: %d", serverAddr, question.Name, rtt, response.Rcode)
			results <- response
		}(serverAddr)
	}

	wg.Wait()
	close(results)
	close(errors)

	// ... (остальная логика обработки ответов)
	for response := range results {
		if response == nil {
			continue
		}

		// Обработка ответов
		if len(response.Answer) > 0 {
			minTTL := uint32(24 * 60 * 60) // TTL по умолчанию 24 часа
			for _, rr := range response.Answer {
				if rr.Header().Ttl < minTTL {
					minTTL = rr.Header().Ttl
				}
			}
			cacheKey := fmt.Sprintf("%s_%s", strings.ToLower(question.Name), dns.Type(question.Qtype))
			packedResponse, _ := response.Pack()

			// Сохраняем в оба кэша
			r.cache.Set(cacheKey, packedResponse, minTTL, question.Name, dns.Type(question.Qtype).String())
			r.cacheL2.Set(cacheKey, packedResponse, minTTL, question.Name, dns.Type(question.Qtype).String())

			// Пункт 2: Агрессивное кэширование отрицательных ответов.
			// Для полноценной реализации нужна поддержка DNSSEC.
			// Текущая реализация кэширует только NXDOMAIN с малым TTL.
			
			return response, nil
		}

		if len(response.Ns) > 0 {
			// Получили NS-серверы для следующего шага
			var nextServers []string
			var glueServers []string

			for _, ns := range response.Ns {
				nsRecord, ok := ns.(*dns.NS)
				if !ok {
					continue
				}

				nsName := strings.ToLower(nsRecord.Ns)

				// Пункт 1: Проверяем NS-кэш для быстрого получения IP.
				if cachedIP, found := r.nsCache.Get(nsName); found {
					nextServers = append(nextServers, string(cachedIP))
				} else {
					// Ищем A/AAAA записи в секции "Extra"
					foundGlue := false
					for _, extra := range response.Extra {
						if extra.Header().Rrtype == dns.TypeA && strings.EqualFold(extra.Header().Name, nsName) {
							aRecord, _ := extra.(*dns.A)
							nextServers = append(nextServers, net.JoinHostPort(aRecord.A.String(), "53"))
							glueServers = append(glueServers, net.JoinHostPort(aRecord.A.String(), "53"))
							foundGlue = true
						}
						if extra.Header().Rrtype == dns.TypeAAAA && strings.EqualFold(extra.Header().Name, nsName) {
							aaaaRecord, _ := extra.(*dns.AAAA)
							nextServers = append(nextServers, net.JoinHostPort(aaaaRecord.AAAA.String(), "53"))
							glueServers = append(glueServers, net.JoinHostPort(aaaaRecord.AAAA.String(), "53"))
							foundGlue = true
						}
					}

					// Если glue records не найдены, нужно сделать отдельный запрос
					if !foundGlue && !isGlueQuery {
						log.Printf("Debug: No glue records for %s. Resolving it separately.", nsName)
						// Отдельный запрос для получения IP-адреса NS-сервера
						glueQuery := dns.Question{
							Name:   dns.Fqdn(nsName),
							Qtype:  dns.TypeA,
							Qclass: dns.ClassINET,
						}

						glueResponse, err := r.recursiveResolve(ctx, glueQuery, id, r.getRootServers(), clientAddr, depth+1, true)
						if err == nil && len(glueResponse.Answer) > 0 {
							for _, ans := range glueResponse.Answer {
								if a, ok := ans.(*dns.A); ok {
									nextServers = append(nextServers, net.JoinHostPort(a.A.String(), "53"))
									r.nsCache.Set(nsName, []byte(net.JoinHostPort(a.A.String(), "53")), ans.Header().Ttl, nsName, "A")
								}
							}
						}
					}
				}
			}

			if len(nextServers) > 0 {
				// Рекурсивный вызов с новыми серверами
				return r.recursiveResolve(ctx, question, id, nextServers, clientAddr, depth+1, false)
			}
		}
	}

	// Если дошли до этого места, значит ничего не нашли. NXDOMAIN
	return nil, fmt.Errorf("NXDOMAIN")
}

// prefetchLoop - фоновая горутина для предварительной загрузки записей.
func (r *Resolver) prefetchLoop(ctx context.Context) {
	ticker := time.NewTicker(prefetchCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Получаем записи, которые скоро истекут
			soonToExpireEntries := r.cache.GetSoonToExpireEntries(prefetchThresholdRatio)
			for _, entry := range soonToExpireEntries {
				// Запускаем предварительную загрузку в отдельной горутине, чтобы не блокировать цикл
				go func(e *CacheEntry) {
					prefetchCtx, prefetchCancel := context.WithTimeout(context.Background(), prefetchQueryTimeout)
					defer prefetchCancel()

					log.Printf("Debug: Prefetching query for %s (%s)", e.QueryName, e.QueryType)

					qtypeUint16 := dns.StringToType[e.QueryType]
					if qtypeUint16 == 0 {
						qtypeUint16 = dns.TypeA
					}
					prefetchQuestion := dns.Question{
						Name:   dns.Fqdn(e.QueryName),
						Qtype:  qtypeUint16,
						Qclass: dns.ClassINET,
					}
					// Указываем nil для адреса клиента, так как это внутренний запрос
					_, err := r.recursiveResolve(prefetchCtx, prefetchQuestion, uint16(rand.Intn(65535)), r.getRootServers(), nil, 0, false)
					if err != nil {
						log.Printf("Error: Prefetching %s (%s) failed: %v", e.QueryName, e.QueryType, err)
					} else {
						log.Printf("Debug: Prefetching %s (%s) successful. Cache should be updated.", e.QueryName, e.QueryType)
					}
				}(entry)
			}
		}
	}
}

// rootHintsUpdateLoop - фоновая горутина для обновления корневых серверов
func (r *Resolver) rootHintsUpdateLoop(ctx context.Context) {
	ticker := time.NewTicker(rootHintsUpdateInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			log.Printf("Debug: Attempting to update root servers.")
			err := r.updateRootServers(ctx)
			if err != nil {
				log.Printf("Error: Failed to update root servers: %v", err)
			} else {
				log.Printf("Debug: Root servers updated successfully.")
			}
		}
	}
}

// updateRootServers загружает и обновляет список корневых серверов
func (r *Resolver) updateRootServers(ctx context.Context) error {
	client := r.clientPool.Get().(*dns.Client)
	defer r.clientPool.Put(client)

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("."), dns.TypeNS)
	msg.RecursionDesired = false

	response, _, err := client.ExchangeContext(ctx, msg, "a.root-servers.net:53") // Запрос к одному из статичных корневых серверов
	if err != nil {
		return fmt.Errorf("ошибка запроса корневых серверов: %w", err)
	}

	if response.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("не удалось получить список корневых серверов, Rcode: %d", response.Rcode)
	}

	var newRootServers []string
	for _, rr := range response.Ns {
		if ns, ok := rr.(*dns.NS); ok {
			for _, extra := range response.Extra {
				if a, ok := extra.(*dns.A); ok && strings.EqualFold(a.Header().Name, ns.Ns) {
					newRootServers = append(newRootServers, net.JoinHostPort(a.A.String(), "53"))
				}
				if aaaa, ok := extra.(*dns.AAAA); ok && strings.EqualFold(aaaa.Header().Name, ns.Ns) {
					newRootServers = append(newRootServers, net.JoinHostPort(aaaa.AAAA.String(), "53"))
				}
			}
		}
	}

	if len(newRootServers) > 0 {
		r.rootServersLock.Lock()
		r.rootServers = newRootServers
		r.rootServersLock.Unlock()
	} else {
		return errors.New("не удалось извлечь корневые серверы из ответа")
	}

	return nil
}

// getRootServers безопасно возвращает список корневых серверов
func (r *Resolver) getRootServers() []string {
	r.rootServersLock.RLock()
	defer r.rootServersLock.RUnlock()
	return r.rootServers
}

// cleanupInflightRequests - фоновая горутина для очистки map
func (r *Resolver) cleanupInflightRequests(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.inflightRequests.Range(func(key, value interface{}) bool {
				ch := value.(chan *dns.Msg)
				select {
				case <-ch:
					r.inflightRequests.Delete(key)
					log.Printf("Debug: In-flight request for %s was cleaned up.", key)
				default:
				}
				return true
			})
		}
	}
}

// popularityLoggerLoop - фоновая горутина для логирования популярных запросов
func (r *Resolver) popularityLoggerLoop(ctx context.Context) {
	ticker := time.NewTicker(rootHintsUpdateInterval) // Например, раз в 24 часа
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			log.Printf("Debug: Most popular queries in the last 24 hours:")
			// Создаем срез для сортировки
			type popularQuery struct {
				key   string
				count int
			}
			var queries []popularQuery
			r.popularityCounter.Range(func(key, value interface{}) bool {
				queries = append(queries, popularQuery{key: key.(string), count: value.(int)})
				return true
			})
			
			// Сортируем по убыванию
			// TODO: Добавить сортировку по убыванию, если необходимо.
			
			// Логируем
			for _, q := range queries {
				log.Printf("  - %s: %d requests", q.key, q.count)
			}
			
			// Очищаем счетчик
			r.popularityCounter.Range(func(key, value interface{}) bool {
				r.popularityCounter.Delete(key)
				return true
			})
		}
	}
}

// ServerStats - структура для хранения статистики по серверам
// (для адаптивного таймаута)
type ServerStats struct {
	mu    sync.RWMutex
	data  map[string]time.Duration
	count map[string]int
}

// NewServerStats создает новую структуру для статистики серверов
func NewServerStats() *ServerStats {
	return &ServerStats{
		data:  make(map[string]time.Duration),
		count: make(map[string]int),
	}
}

// Update обновляет статистику для сервера
func (s *ServerStats) Update(server string, rtt time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[server] += rtt
	s.count[server]++
}

// GetTimeout возвращает таймаут для сервера
func (s *ServerStats) GetTimeout(server string) time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.count[server] < 5 {
		return 5 * time.Second
	}

	avgRTT := s.data[server] / time.Duration(s.count[server])

	if avgRTT > adaptiveTimeoutGracePeriod {
		return avgRTT * adaptiveTimeoutFactor
	}

	return 5 * time.Second // Таймаут по умолчанию
}

var initialRootServers = []string{
	"198.41.0.4:53",
	"2001:503:ba3e::2:30:53",
	"170.247.170.2:53",
	"192.33.4.12:53",
	"2001:500:2f::f:53",
	"192.5.5.241:53",
	"2001:500:2a::a:53",
	"192.112.36.4:53",
	"2001:500:200::b:53",
	"193.0.14.129:53",
	"2001:500:2d::d:53",
	"199.7.91.13:53",
	"2001:500:a8::e:53",
	"192.203.230.10:53",
	"2001:500:12::d0d:53",
	"199.7.83.42:53",
	"2001:500:21::42:53",
	"202.12.27.33:53",
	"2001:dc3::35:53",
}
