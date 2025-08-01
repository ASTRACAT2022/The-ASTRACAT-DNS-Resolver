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
	prefetchThresholdRatio = 0.1 // 10% от исходного TTL
	// prefetchQueryTimeout - таймаут для запроса предварительной загрузки.
	prefetchQueryTimeout = 500 * time.Millisecond
	
	// rootHintsUpdateInterval - как часто обновлять корневые серверы.
	rootHintsUpdateInterval = 24 * time.Hour
	
	// adaptiveTimeoutGracePeriod - период, в течение которого сервер не считается медленным.
	adaptiveTimeoutGracePeriod = 20 * time.Millisecond
	// adaptiveTimeoutFactor - коэффициент увеличения таймаута для медленных серверов.
	adaptiveTimeoutFactor = 1.5
)

// DNS Resolution configuration.
var (
	Timeout             = 2000 * time.Millisecond
	MaxRecursion        = 10
	MaxNameservers      = 2 // Максимальное количество параллельных запросов к серверам
	MaxIPs              = 2 // Максимальное количество IP, которые мы пробуем для каждого nameserver
)

// Resolver errors.
var (
	NXDOMAIN = fmt.Errorf("NXDOMAIN")

	ErrMaxRecursion = fmt.Errorf("maximum recursion depth reached: %d", MaxRecursion)
	ErrNoARecords   = fmt.Errorf("no A records found for name server")
	ErrNoResponse   = fmt.Errorf("no responses received")
)

// ContextDialer implements the DialContext method, e.g. net.Dialer.
type ContextDialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// Option specifies a configuration option for a Resolver.
type Option func(*Resolver)

// WithCache specifies a cache with capacity cap.
func WithCache(cap int) Option {
	return func(r *Resolver) { r.capacity = cap }
}

// WithDialer specifies a network dialer.
func WithDialer(d ContextDialer) Option {
	return func(r *Resolver) { r.dialer = d }
}

// WithExpiry specifies that the Resolver will delete stale cache entries.
func WithExpiry() Option {
	return func(r *Resolver) { r.expire = true }
}

// WithTimeout specifies the timeout for network operations.
func WithTimeout(timeout time.Duration) Option {
	return func(r *Resolver) { r.timeout = timeout }
}

// WithTCPRetry specifies that requests should be retried with TCP if responses
// are truncated.
func WithTCPRetry() Option {
	return func(r *Resolver) { r.tcpRetry = true }
}

// Resolver implements a primitive, non-recursive, caching DNS resolver.
type Resolver struct {
	dialer      ContextDialer
	timeout     time.Duration
	cache       *cache
	capacity    int
	expire      bool
	tcpRetry    bool
	
	serverStats *ServerStats
	prefetchWork chan string
	ctx context.Context
	rootServers []string
	
	nsCache *cache
}

// NewResolver returns an initialized Resolver with options.
func NewResolver(ctx context.Context, options ...Option) *Resolver {
	r := &Resolver{
		timeout:      Timeout,
		rootServers:  initialRootServers,
		serverStats:  NewServerStats(),
		prefetchWork: make(chan string, 1000),
		ctx:          ctx,
		nsCache:      newCache(10000, true), // NS-кэш для делегаций
	}
	for _, o := range options {
		o(r)
	}
	r.cache = newCache(r.capacity, r.expire)
	
	go r.prefetchLoop()
	go r.rootHintsUpdater()

	return r
}

// ResolveContext находит DNS-записи типа qtype для домена qname.
func (r *Resolver) ResolveContext(ctx context.Context, qname, qtype string) (RRs, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	return r.resolveIterative(ctx, toLowerFQDN(qname), qtype)
}

// resolveIterative реализует итеративный процесс разрешения DNS.
func (r *Resolver) resolveIterative(ctx context.Context, qname, qtype string) (RRs, error) {
	var (
		delegations RRs
		err error
	)

	// Начинаем с корневых серверов.
	delegations = make(RRs, len(r.rootServers))
	for i, ip := range r.rootServers {
		delegations[i] = &RR{Value: ip, Type: "A"}
	}

	for depth := 0; depth < MaxRecursion; depth++ {
		// Проверяем кэш на каждой итерации.
		if rrs := r.cacheGet(qname, qtype); len(rrs) > 0 {
			return rrs, nil
		}
		
		log.Printf("Debug: Iterative resolving %s %s at depth %d", qname, qtype, depth)

		// Выполняем параллельный запрос к делегированным серверам.
		rmsg, err := r.exchangeParallel(ctx, qname, qtype, delegations)
		if err != nil {
			return nil, err
		}
		
		// Обрабатываем ответ.
		if rmsg.Rcode == dns.RcodeNameError {
			r.cache.addNX(qname + "/" + qtype, rmsg.Ns[0].Header().Ttl)
			return nil, NXDOMAIN
		} else if rmsg.Rcode != dns.RcodeSuccess {
			return nil, errors.New(dns.RcodeToString[rmsg.Rcode])
		}
		
		// Если ответ содержит искомые записи, кэшируем и возвращаем их.
		if len(rmsg.Answer) > 0 {
			rrs := r.saveDNSRR(rmsg.Answer, qname, qtype)
			if len(rrs) > 0 {
				return rrs, nil
			}
		}

		// Если в ответе есть делегация (NS-записи), обновляем список серверов.
		if len(rmsg.Ns) > 0 {
			nextQname := qname
			if len(rmsg.Ns) > 0 && dns.CountLabel(qname) > dns.CountLabel(rmsg.Ns[0].Header().Name) {
				nextQname = rmsg.Ns[0].Header().Name
			}
			
			delegations, err = r.processDelegation(ctx, nextQname, rmsg.Ns, rmsg.Extra)
			if err != nil {
				return nil, err
			}
			continue
		}
		
		return nil, ErrNoResponse
	}
	
	return nil, ErrMaxRecursion
}

// exchangeParallel выполняет параллельные запросы к нескольким серверам.
func (r *Resolver) exchangeParallel(ctx context.Context, qname, qtype string, servers RRs) (*dns.Msg, error) {
	// Ограничиваем количество параллельных запросов.
	if len(servers) > MaxNameservers {
		rand.Shuffle(len(servers), func(i, j int) { servers[i], servers[j] = servers[j], servers[i] })
		servers = servers[:MaxNameservers]
	}
	
	var wg sync.WaitGroup
	resultChan := make(chan *dns.Msg, len(servers))
	
	for _, server := range servers {
		wg.Add(1)
		go func(server *RR) {
			defer wg.Done()
			rmsg, err := r.exchangeIP(ctx, server.Value, qname, qtype)
			if err == nil {
				resultChan <- rmsg
			} else {
				log.Printf("Warning: Query to %s failed: %v", server.Value, err)
			}
		}(server)
	}
	
	wg.Wait()
	close(resultChan)
	
	// Возвращаем первый полученный ответ.
	for rmsg := range resultChan {
		return rmsg, nil
	}
	
	return nil, ErrNoResponse
}

// exchangeIP отправляет DNS-запрос на один IP-адрес.
func (r *Resolver) exchangeIP(ctx context.Context, ip, qname, qtype string) (*dns.Msg, error) {
	dtype := dns.StringToType[qtype]
	if dtype == 0 {
		dtype = dns.TypeA
	}
	var qmsg dns.Msg
	qmsg.SetQuestion(qname, dtype)
	qmsg.MsgHdr.RecursionDesired = false
	
	timeout := r.serverStats.GetTimeout(ip)
	client := &dns.Client{Timeout: timeout, Net: "udp"}
	
	addr := net.JoinHostPort(ip, "53")
	
	rmsg, dur, err := client.ExchangeContext(ctx, &qmsg, addr)
	
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	
	if err != nil {
		return nil, err
	}
	
	r.serverStats.Update(ip, dur)
	
	if r.tcpRetry && rmsg != nil && rmsg.MsgHdr.Truncated {
		client.Net = "tcp"
		rmsg, dur, err = client.ExchangeContext(ctx, &qmsg, addr)
		if err != nil {
			return nil, err
		}
		r.serverStats.Update(ip, dur)
	}
	
	return rmsg, nil
}

// processDelegation обрабатывает делегирование и возвращает IP-адреса следующих NS.
func (r *Resolver) processDelegation(ctx context.Context, qname string, nsRecords, extraRecords []dns.RR) (RRs, error) {
	var delegatedServers RRs
	
	r.saveDNSRR(nsRecords, qname, "NS")
	
	for _, drr := range nsRecords {
		nsName := drr.(*dns.NS).Ns
		
		for _, extra := range extraRecords {
			if aRec, ok := extra.(*dns.A); ok && aRec.Header().Name == nsName {
				delegatedServers = append(delegatedServers, &RR{Value: aRec.A.String(), Type: "A", Name: aRec.Header().Name, TTL: aRec.Header().Ttl})
			}
		}
	}
	
	if len(delegatedServers) == 0 {
		for _, drr := range nsRecords {
			nsName := drr.(*dns.NS).Ns
			if cachedIPs := r.nsCache.get(nsName + "/A"); len(cachedIPs) > 0 {
				delegatedServers = append(delegatedServers, cachedIPs...)
			} else {
				ips, err := r.ResolveContext(ctx, nsName, "A")
				if err == nil {
					r.nsCache.add(nsName + "/A", ips, ips[0].TTL)
					delegatedServers = append(delegatedServers, ips...)
				} else {
					log.Printf("Warning: Failed to resolve IP for nameserver %s: %v", nsName, err)
				}
			}
		}
	}
	
	if len(delegatedServers) == 0 {
		return nil, ErrNoARecords
	}
	
	return delegatedServers, nil
}

// saveDNSRR сохраняет DNS-записи в кэш.
func (r *Resolver) saveDNSRR(drrs []dns.RR, qname, qtype string) RRs {
	var rrs RRs
	for _, drr := range drrs {
		rr, ok := convertRR(drr)
		if !ok {
			continue
		}
		
		if dns.CountLabel(rr.Name) < dns.CountLabel(qname) && !strings.HasSuffix(qname, "." + rr.Name) {
			log.Printf("Warning: potential poisoning from %s: %s", qname, drr.String())
			continue
		}
		
		r.cache.add(rr.Name + "/" + rr.Type, RRs{rr}, rr.TTL)
		
		if rr.Name == qname && rr.Type == qtype {
			rrs = append(rrs, rr)
		}
	}
	
	return rrs
}

// cacheGet получает записи из кэша.
func (r *Resolver) cacheGet(qname, qtype string) RRs {
	key := qname + "/" + qtype
	
	cachedRRs := r.cache.get(key)
	
	if cachedRRs == nil {
		cachedRRs = r.nsCache.get(key)
	}
	
	return cachedRRs
}

// prefetchLoop проверяет кэш и запускает предзагрузку.
func (r *Resolver) prefetchLoop() {
	ticker := time.NewTicker(prefetchCheckInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			soonToExpire := r.cache.GetSoonToExpireEntries(prefetchThresholdRatio)
			for _, entry := range soonToExpire {
				go r.prefetch(entry.Key)
			}
		case <-r.ctx.Done():
			return
		}
	}
}

// prefetch выполняет DNS-запрос для записи, срок действия которой скоро истечет.
func (r *Resolver) prefetch(query string) {
	parts := strings.Split(query, "/")
	if len(parts) != 2 {
		return
	}
	qname := parts[0]
	qtypeStr := parts[1]
	
	ctx, cancel := context.WithTimeout(r.ctx, prefetchQueryTimeout)
	defer cancel()
	
	_, err := r.resolveIterative(ctx, qname, qtypeStr)
	if err != nil {
		log.Printf("Warning: Prefetch for %s failed: %v", qname, err)
	}
}

// rootHintsUpdater периодически обновляет список корневых серверов.
func (r *Resolver) rootHintsUpdater() {
	ticker := time.NewTicker(rootHintsUpdateInterval)
	defer ticker.Stop()
	
	r.updateRootServers()
	
	for range ticker.C {
		r.updateRootServers()
	}
}

// updateRootServers - заглушка для обновления списка корневых серверов.
func (r *Resolver) updateRootServers() {
	log.Println("Updating root server hints...")
}

// ServerStats - структура для хранения статистики по серверам.
type ServerStats struct {
	mu    sync.RWMutex
	data  map[string]time.Duration
	count map[string]int
}

// NewServerStats создает новую структуру для статистики серверов.
func NewServerStats() *ServerStats {
	return &ServerStats{
		data:  make(map[string]time.Duration),
		count: make(map[string]int),
	}
}

// Update обновляет статистику для сервера.
func (s *ServerStats) Update(server string, rtt time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[server] += rtt
	s.count[server]++
}

// GetTimeout возвращает таймаут для сервера, адаптируясь к его производительности.
func (s *ServerStats) GetTimeout(server string) time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	if s.count[server] < 5 {
		return 5 * time.Second
	}
	
	avgRTT := s.data[server] / time.Duration(s.count[server])
	
	if avgRTT > adaptiveTimeoutGracePeriod {
		return time.Duration(float64(avgRTT) * adaptiveTimeoutFactor)
	}
	
	return 5 * time.Second
}

var initialRootServers = []string{
	"198.41.0.4",
	"170.247.170.2",
	"192.33.4.12",
	"199.7.91.13",
	"192.203.230.10",
	"192.5.5.241",
	"192.112.36.4",
	"198.97.190.53",
	"192.36.148.17",
	"192.58.128.30",
	"193.0.14.129",
	"199.7.83.42",
	"202.12.27.33",
}

// toLowerFQDN конвертирует имя домена в нижний регистр и гарантирует, что оно полностью квалифицировано.
func toLowerFQDN(name string) string {
	return dns.Fqdn(strings.ToLower(name))
}

// convertRR - вспомогательная функция для конвертации dns.RR в пользовательскую структуру RR.
func convertRR(drr dns.RR) (*RR, bool) {
	header := drr.Header()
	name := header.Name
	rrType := dns.Type(header.Rrtype).String()
	
	var value string
	switch v := drr.(type) {
	case *dns.A:
		value = v.A.String()
	case *dns.AAAA:
		value = v.AAAA.String()
	case *dns.NS:
		value = v.Ns
	case *dns.CNAME:
		value = v.Target
	case *dns.SOA:
		value = fmt.Sprintf("%s %d", v.Mbox, v.Serial)
	case *dns.TXT:
		value = strings.Join(v.Txt, " ")
	case *dns.MX:
		value = fmt.Sprintf("%d %s", v.Preference, v.Mx)
	default:
		return nil, false
	}
	
	rr := &RR{
		Name: name,
		Type: rrType,
		Value: value,
		TTL: header.Ttl,
	}
	
	return rr, true
}
