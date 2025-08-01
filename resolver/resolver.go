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
	prefetchCheckInterval = 10 * time.Second
	// prefetchThresholdRatio определяет, какой процент от исходного TTL должен остаться, чтобы запустить предварительную загрузку.
	prefetchThresholdRatio = 0.2
	// prefetchQueryTimeout - таймаут для запроса предварительной загрузки.
	prefetchQueryTimeout = 500 * time.Millisecond // Уменьшаем таймаут для префетча
	
	// rootHintsUpdateInterval - как часто обновлять корневые серверы (можно увеличить для стабильных систем)
	rootHintsUpdateInterval = 24 * time.Hour
	
	// adaptiveTimeoutGracePeriod - период, в течение которого сервер не считается медленным
	adaptiveTimeoutGracePeriod = 20 * time.Millisecond // Более агрессивный порог
	// adaptiveTimeoutFactor - коэффициент увеличения таймаута для медленных серверов
	adaptiveTimeoutFactor = 1.5 // Менее агрессивное увеличение
	
	// L2CacheCleanupInterval - как часто очищать L2 кэш (например, раз в неделю)
	L2CacheCleanupInterval = 7 * 24 * time.Hour
)

// enableDebugLogging - переключатель для отладочного логирования.
// Для максимальной производительности всегда false
const enableDebugLogging = false

// maxConcurrentRecursiveQueries - ограничиваем количество одновременных рекурсивных запросов,
// чтобы избежать "взрыва" горутин и перегрузки внешних DNS-серверов.
const maxConcurrentRecursiveQueries = 1000

// Resolver - основной тип для нашего DNS-резолвера с добавленными полями для оптимизаций
type Resolver struct {
	cache *Cache
	// cacheL2 - дополнительный кэш с долгим временем жизни для редко используемых записей (L2 кэш).
	cacheL2 *Cache
	// clientPool позволяет переиспользовать UDP-сокеты, уменьшая накладные расходы на их создание.
	clientPool *sync.Pool
	// inflightRequests используется для схлопывания запросов.
	inflightRequests sync.Map // map[string]chan *dns.Msg
	// nsCache - кэш для NS-серверов популярных доменных зон.
	nsCache *Cache
	// rootServers - корневые DNS-серверы, которые могут обновляться.
	rootServers     []string
	rootServersLock sync.RWMutex
	// stats - для адаптивного таймаута, хранит статистику по серверам
	stats *ServerStats
	// concurrencyLimiter - семафор для ограничения количества одновременных рекурсивных запросов
	concurrencyLimiter chan struct{}
}

// NewResolver создает новый экземпляр Resolver и запускает циклы
func NewResolver(ctx context.Context) *Resolver {
	r := &Resolver{
		// Теперь NewCache принимает интервал очистки
		cache:              NewCache(prefetchCheckInterval),
		cacheL2:            NewCache(L2CacheCleanupInterval),
		nsCache:            NewCache(prefetchCheckInterval),
		clientPool:         &sync.Pool{New: func() interface{} { return &dns.Client{UDPSize: 1232} }},
		stats:              NewServerStats(),
		rootServersLock:    sync.RWMutex{},
		inflightRequests:   sync.Map{},
		concurrencyLimiter: make(chan struct{}, maxConcurrentRecursiveQueries),
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

	return r
}

// Resolve обрабатывает DNS-запрос и возвращает ответ
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
	cacheKey := strings.ToLower(fmt.Sprintf("%s_%s", question.Name, dns.Type(question.Qtype)))

	if cachedResponse, found := r.cache.Get(cacheKey); found {
		responseMsg := new(dns.Msg)
		if err := responseMsg.Unpack(cachedResponse); err == nil {
			responseMsg.Id = msg.Id
			return responseMsg.Pack()
		}
	}

	if cachedResponse, found := r.cacheL2.Get(cacheKey); found {
		responseMsg := new(dns.Msg)
		if err := responseMsg.Unpack(cachedResponse); err == nil {
			responseMsg.Id = msg.Id
			if enableDebugLogging {
				log.Printf("Debug: Cache L2 hit for %s", cacheKey)
			}
			return responseMsg.Pack()
		}
	}

	ch := make(chan *dns.Msg, 1)
	actualCh, loaded := r.inflightRequests.LoadOrStore(cacheKey, ch)

	if loaded {
		if enableDebugLogging {
			log.Printf("Debug: Request for %s is already in flight, waiting for response.", cacheKey)
		}
		responseMsg := <-actualCh.(chan *dns.Msg)
		responseMsg.Id = msg.Id
		return responseMsg.Pack()
	}

	r.concurrencyLimiter <- struct{}{}
	responseMsg, err := r.recursiveResolve(ctx, question, msg.Id, r.getRootServers(), clientAddr, 0, false)
	<-r.concurrencyLimiter

	r.inflightRequests.Delete(cacheKey)
	if err == nil {
		actualCh.(chan *dns.Msg) <- responseMsg
		close(actualCh.(chan *dns.Msg))
	} else {
		close(actualCh.(chan *dns.Msg))
	}

	if err != nil {
		return nil, err
	}

	responseMsg.Id = msg.Id
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

	shuffledServers := make([]string, len(servers))
	copy(shuffledServers, servers)
	rand.Shuffle(len(shuffledServers), func(i, j int) {
		shuffledServers[i], shuffledServers[j] = shuffledServers[j], shuffledServers[i]
	})

	for _, serverAddr := range shuffledServers {
		wg.Add(1)
		go func(serverAddr string) {
			defer wg.Done()

			timeout := r.stats.GetTimeout(serverAddr)
			client := r.clientPool.Get().(*dns.Client)
			client.DialTimeout = timeout
			client.ReadTimeout = timeout
			client.WriteTimeout = timeout
			defer r.clientPool.Put(client)

			msg := new(dns.Msg)
			msg.Id = id
			msg.Question = []dns.Question{question}
			msg.RecursionDesired = true

			o := new(dns.EDNS0_SUBNET)
			o.Family = 1
			o.SourceNetmask = net.IPv4len * 8
			if clientAddr != nil && clientAddr.IP.To4() != nil {
				o.Address = clientAddr.IP.To4()
			} else {
				o.Address = net.IPv4(0, 0, 0, 0)
				o.SourceNetmask = 0
			}
			
			// Исправлено: добавление опции EDNS0
			msg.SetEdns0(1232, true)
			msg.IsEdns0().Option = append(msg.IsEdns0().Option, o)

			start := time.Now()
			response, rtt, err := client.ExchangeContext(ctx, msg, serverAddr)
			end := time.Now()
			r.stats.Update(serverAddr, end.Sub(start))

			if err != nil {
				errors <- fmt.Errorf("запрос к %s завершился с ошибкой: %w", serverAddr, err)
				return
			}
			if response.Rcode != dns.RcodeSuccess && response.Rcode != dns.RcodeNameError {
				errors <- fmt.Errorf("сервер %s вернул Rcode: %d", serverAddr, response.Rcode)
				return
			}

			if enableDebugLogging {
				log.Printf("Debug: Query to %s for %s completed in %s with Rcode: %d", serverAddr, question.Name, rtt, response.Rcode)
			}
			results <- response
		}(serverAddr)
	}

	wg.Wait()
	close(results)
	close(errors)

	for response := range results {
		if response == nil {
			continue
		}

		if len(response.Answer) > 0 {
			minTTL := uint32(24 * 60 * 60)
			for _, rr := range response.Answer {
				if rr.Header().Ttl < minTTL {
					minTTL = rr.Header().Ttl
				}
			}
			cacheKey := strings.ToLower(fmt.Sprintf("%s_%s", question.Name, dns.Type(question.Qtype)))
			packedResponse, _ := response.Pack()

			r.cache.Set(cacheKey, packedResponse, minTTL, question.Name, dns.Type(question.Qtype).String())
			r.cacheL2.Set(cacheKey, packedResponse, minTTL, question.Name, dns.Type(question.Qtype).String())

			return response, nil
		}

		if len(response.Ns) > 0 {
			var nextServers []string
			for _, ns := range response.Ns {
				nsRecord, ok := ns.(*dns.NS)
				if !ok {
					continue
				}

				nsName := strings.ToLower(nsRecord.Ns)

				if cachedIP, found := r.nsCache.Get(nsName); found {
					nextServers = append(nextServers, string(cachedIP))
				} else {
					foundGlue := false
					for _, extra := range response.Extra {
						if extra.Header().Rrtype == dns.TypeA && strings.EqualFold(extra.Header().Name, nsName) {
							aRecord, _ := extra.(*dns.A)
							nextServers = append(nextServers, net.JoinHostPort(aRecord.A.String(), "53"))
							foundGlue = true
						}
						if extra.Header().Rrtype == dns.TypeAAAA && strings.EqualFold(extra.Header().Name, nsName) {
							aaaaRecord, _ := extra.(*dns.AAAA)
							nextServers = append(nextServers, net.JoinHostPort(aaaaRecord.AAAA.String(), "53"))
							foundGlue = true
						}
					}

					if !foundGlue && !isGlueQuery {
						if enableDebugLogging {
							log.Printf("Debug: No glue records for %s. Resolving it separately.", nsName)
						}
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
				return r.recursiveResolve(ctx, question, id, nextServers, clientAddr, depth+1, false)
			}
		}
	}

	return nil, fmt.Errorf("NXDOMAIN")
}

func (r *Resolver) prefetchLoop(ctx context.Context) {
	ticker := time.NewTicker(prefetchCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			soonToExpireEntries := r.cache.GetSoonToExpireEntries(prefetchThresholdRatio)
			for _, entry := range soonToExpireEntries {
				go func(e *CacheEntry) {
					prefetchCtx, prefetchCancel := context.WithTimeout(context.Background(), prefetchQueryTimeout)
					defer prefetchCancel()

					if enableDebugLogging {
						log.Printf("Debug: Prefetching query for %s (%s)", e.QueryName, e.QueryType)
					}

					qtypeUint16 := dns.StringToType[e.QueryType]
					if qtypeUint16 == 0 {
						qtypeUint16 = dns.TypeA
					}
					prefetchQuestion := dns.Question{
						Name:   dns.Fqdn(e.QueryName),
						Qtype:  qtypeUint16,
						Qclass: dns.ClassINET,
					}
					_, err := r.recursiveResolve(prefetchCtx, prefetchQuestion, uint16(rand.Intn(65535)), r.getRootServers(), nil, 0, false)
					if err != nil && enableDebugLogging {
						log.Printf("Error: Prefetching %s (%s) failed: %v", e.QueryName, e.QueryType, err)
					} else if enableDebugLogging {
						log.Printf("Debug: Prefetching %s (%s) successful. Cache should be updated.", e.QueryName, e.QueryType)
					}
				}(entry)
			}
		}
	}
}

func (r *Resolver) rootHintsUpdateLoop(ctx context.Context) {
	ticker := time.NewTicker(rootHintsUpdateInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if enableDebugLogging {
				log.Printf("Debug: Attempting to update root servers.")
			}
			err := r.updateRootServers(ctx)
			if err != nil {
				log.Printf("Error: Failed to update root servers: %v", err)
			} else if enableDebugLogging {
				log.Printf("Debug: Root servers updated successfully.")
			}
		}
	}
}

func (r *Resolver) updateRootServers(ctx context.Context) error {
	client := r.clientPool.Get().(*dns.Client)
	defer r.clientPool.Put(client)

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("."), dns.TypeNS)
	msg.RecursionDesired = false

	response, _, err := client.ExchangeContext(ctx, msg, "a.root-servers.net:53")
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

func (r *Resolver) getRootServers() []string {
	r.rootServersLock.RLock()
	defer r.rootServersLock.RUnlock()
	return r.rootServers
}

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
					if enableDebugLogging {
						log.Printf("Debug: In-flight request for %s was cleaned up.", key)
					}
				default:
				}
				return true
			})
		}
	}
}

// ServerStats - структура для хранения статистики по серверам
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

	// Исправлено: приведение типов для корректного умножения
	if avgRTT > adaptiveTimeoutGracePeriod {
		return time.Duration(float64(avgRTT) * adaptiveTimeoutFactor)
	}

	return 5 * time.Second
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
