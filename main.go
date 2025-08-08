package main

import (
	"fmt"
	"log"
	"sync"
	"time"
    "net/http"
	"github.com/domainr/dnsr"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/time/rate"
)

// Инициализируем резолвер с кэшем
var resolver = dnsr.NewResolver(dnsr.WithExpiry()) // Убрали аргумент, используем значение по умолчанию

// Определяем метрики Prometheus
var (
	dnsQueriesTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dns_queries_total",
			Help: "Total number of DNS queries received.",
		},
	)
	dnsQueriesErrors = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dns_queries_errors_total",
			Help: "Total number of DNS queries that resulted in an error.",
		},
	)
	dnsLoopDetected = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dns_loops_detected_total",
			Help: "Total number of detected DNS query loops.",
		},
	)
	dnsQueryDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "dns_query_duration_seconds",
			Help:    "Time taken to process DNS queries",
			Buckets: prometheus.DefBuckets,
		},
	)
)

// Структура для обработки запросов
type handler struct {
	mu            sync.Mutex
	seenQueries   map[string]int
	maxIterations int
	limiter       *rate.Limiter
}

// Новый обработчик с rate limiting (100 запросов в секунду, burst 200)
func newHandler() *handler {
	return &handler{
		seenQueries:   make(map[string]int),
		maxIterations: 10,
		limiter:       rate.NewLimiter(100, 200),
	}
}

// Метод ServeDNS
func (h *handler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	start := time.Now()
	dnsQueriesTotal.Inc()

	// Проверка rate limiting
	clientIP := w.RemoteAddr().String()
	if !h.limiter.Allow() {
		log.Printf("Rate limit exceeded for client: %s", clientIP)
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		w.WriteMsg(m)
		dnsQueriesErrors.Inc()
		return
	}

	// Проверка на зацикливание
	if len(r.Question) == 0 {
		log.Printf("Invalid query: no questions provided")
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		w.WriteMsg(m)
		dnsQueriesErrors.Inc()
		return
	}

	question := r.Question[0]
	queryKey := fmt.Sprintf("%s-%d", question.Name, question.Qtype)
	h.mu.Lock()
	h.seenQueries[queryKey]++
	iteration := h.seenQueries[queryKey]
	h.mu.Unlock()

	if iteration > h.maxIterations {
		log.Printf("DNS loop detected for query: %s", queryKey)
		dnsLoopDetected.Inc()
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		w.WriteMsg(m)
		return
	}

	go func() {
		defer func() {
			// Очистка счётчика запросов
			h.mu.Lock()
			h.seenQueries[queryKey]--
			if h.seenQueries[queryKey] <= 0 {
				delete(h.seenQueries, queryKey)
			}
			h.mu.Unlock()
			// Записываем время обработки
			dnsQueryDuration.Observe(time.Since(start).Seconds())
		}()

		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		m.RecursionAvailable = true

		rrTypeStr := dns.TypeToString[question.Qtype]
		records := resolver.Resolve(question.Name, rrTypeStr)
		if records == nil {
			log.Printf("Resolver returned nil for %s (%s)", question.Name, rrTypeStr)
			m.SetRcode(r, dns.RcodeServerFailure)
			w.WriteMsg(m)
			dnsQueriesErrors.Inc()
			return
		}

		if len(records) == 0 {
			log.Printf("No records found for %s (%s)", question.Name, rrTypeStr)
			m.SetRcode(r, dns.RcodeNameError)
			w.WriteMsg(m)
			dnsQueriesErrors.Inc()
			return
		}

		// Фильтрация дубликатов и ненужных записей
		seen := make(map[string]struct{})
		for _, rr := range records {
			if rr.Type != rrTypeStr {
				continue
			}
			rrString := fmt.Sprintf("%s %d IN %s %s", rr.Name, int(rr.TTL.Seconds()), rr.Type, rr.Value)
			if _, exists := seen[rrString]; exists {
				continue
			}
			seen[rrString] = struct{}{}
			parsedRR, err := dns.NewRR(rrString)
			if err != nil {
				log.Printf("Error parsing RR '%s': %s", rrString, err)
				dnsQueriesErrors.Inc()
				continue
			}
			m.Answer = append(m.Answer, parsedRR)
		}

		if err := w.WriteMsg(m); err != nil {
			log.Printf("Error writing message: %s", err)
			dnsQueriesErrors.Inc()
		}
	}()
}

func main() {
	// Регистрируем метрики Prometheus
	prometheus.MustRegister(dnsQueriesTotal)
	prometheus.MustRegister(dnsQueriesErrors)
	prometheus.MustRegister(dnsLoopDetected)
	prometheus.MustRegister(dnsQueryDuration)

	// Запускаем HTTP-сервер для метрик на порту 9090
	go func() {
		http.Handle("/metrics", promhttp.Handler())
		fmt.Println("Prometheus metrics available at :9090/metrics")
		log.Fatal(http.ListenAndServe(":9090", nil))
	}()

	// Настройка UDP и TCP серверов
	udpServer := &dns.Server{
		Addr:         ":8153",
		Net:          "udp",
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}
	tcpServer := &dns.Server{
		Addr:         ":8153",
		Net:          "tcp",
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	handler := newHandler()
	udpServer.Handler = handler
	tcpServer.Handler = handler

	// Запускаем UDP сервер
	go func() {
		fmt.Println("UDP DNS server is listening on :8153")
		if err := udpServer.ListenAndServe(); err != nil {
			log.Fatalf("Failed to start UDP DNS server: %s", err)
		}
	}()

	// Запускаем TCP сервер
	go func() {
		fmt.Println("TCP DNS server is listening on :8153")
		if err := tcpServer.ListenAndServe(); err != nil {
			log.Fatalf("Failed to start TCP DNS server: %s", err)
		}
	}()

	// Блокируем основной поток
	select {}
}
