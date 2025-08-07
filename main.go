package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/domainr/dnsr"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Инициализируем наш рекурсивный резолвер с кэшем
var resolver = dnsr.NewResolver(dnsr.WithExpiry())

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
)

// Структура для обработки запросов
type handler struct{}

// Метод ServeDNS
func (h *handler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	// Инкрементируем счётчик общего количества запросов
	dnsQueriesTotal.Inc()

	go func() {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		m.RecursionAvailable = true

		if len(r.Question) == 0 {
			m.SetRcode(r, dns.RcodeRefused)
			w.WriteMsg(m)
			// Инкрементируем счётчик ошибок, если запрос некорректен
			dnsQueriesErrors.Inc()
			return
		}

		question := r.Question[0]
		rrTypeStr := dns.TypeToString[question.Qtype]
		records := resolver.Resolve(question.Name, rrTypeStr)

		if len(records) == 0 {
			m.SetRcode(r, dns.RcodeNameError)
			w.WriteMsg(m)
			// Инкрементируем счётчик ошибок, если запись не найдена
			dnsQueriesErrors.Inc()
			return
		}

		// ----- ИСПРАВЛЕННЫЙ БЛОК (ВЕРСИЯ 2) -----
		for _, rr := range records {
			// Вручную собираем RR-запись в правильном формате, чтобы избежать ошибки парсинга.
			// Стандартный формат: Name TTL IN Type Value
			rrString := fmt.Sprintf("%s %d IN %s %s", rr.Name, int(rr.TTL.Seconds()), rr.Type, rr.Value)

			parsedRR, err := dns.NewRR(rrString)
			if err != nil {
				// Этот лог теперь будет более информативным в случае ошибки
				log.Printf("Error parsing manually constructed RR '%s': %s", rrString, err)
				dnsQueriesErrors.Inc()
				continue
			}
			m.Answer = append(m.Answer, parsedRR)
		}
		// ------------------------------------

		if err := w.WriteMsg(m); err != nil {
			log.Printf("Error writing message: %s", err)
			dnsQueriesErrors.Inc()
		}
	}()
}

// Главная функция
func main() {
	// Регистрируем наши метрики в Prometheus
	prometheus.MustRegister(dnsQueriesTotal)
	prometheus.MustRegister(dnsQueriesErrors)

	// Запускаем HTTP-сервер для метрик на порту 9090
	go func() {
		http.Handle("/metrics", promhttp.Handler())
		fmt.Println("Prometheus metrics available at :9090/metrics")
		log.Fatal(http.ListenAndServe(":9090", nil))
	}()

	// Запускаем DNS-сервер на порту 8053
	server := &dns.Server{
		Addr:         ":8053",
		Net:          "udp",
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	server.Handler = &handler{}
	fmt.Println("DNS server is listening on :8053")

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Failed to start DNS server: %s", err)
	}
}
