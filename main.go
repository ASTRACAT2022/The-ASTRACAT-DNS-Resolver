package main

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/miekg/dns" // Убедитесь, что вы используете эту библиотеку
)

// Logger для отладочных сообщений
var logger = log.New(log.Writer(), "", log.Ldate|log.Ltime|log.Lshortfile)

// Cache - простая заглушка для кэша
type Cache struct {
	mu    sync.RWMutex
	store map[dns.Question]*dns.Msg
}

func NewCache() *Cache {
	return &Cache{
		store: make(map[dns.Question]*dns.Msg),
	}
}

func (c *Cache) Get(q dns.Question) *dns.Msg {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.store[q]
}

func (c *Cache) Set(q dns.Question, msg *dns.Msg) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.store[q] = msg
}

// Resolver - основной тип для нашего DNS-резолвера
type Resolver struct {
	cache       *Cache
	rootServers []string // Начальные корневые серверы
}

func NewResolver() *Resolver {
	// Список корневых DNS-серверов (актуальный на момент написания)
	rootServers := []string{
		"198.41.0.4:53",    // a.root-servers.net
		"199.9.14.201:53",  // b.root-servers.net
		"192.33.4.12:53",   // c.root-servers.net
		"199.7.91.13:53",   // d.root-servers.net
		"192.203.230.10:53",// e.root-servers.net
		"192.5.5.241:53",   // f.root-servers.net
		"192.112.36.4:53",  // g.root-servers.net
		"198.97.190.53:53", // h.root-servers.net
		"192.36.148.17:53", // i.root-servers.net
		"192.58.128.30:53", // j.root-servers.net
		"193.0.14.129:53",  // k.root-servers.net
		"199.7.83.42:53",   // l.root-servers.net
		"202.12.27.33:53",  // m.root-servers.net
		// Добавляем IPv6 адреса корневых серверов для полноты
		"[2001:503:ba3e::2:30]:53", // a.root-servers.net IPv6
		"[2001:500:200::b]:53",    // b.root-servers.net IPv6
		"[2001:500:2::c]:53",     // c.root-servers.net IPv6
		"[2001:500:2d::d]:53",    // d.root-servers.net IPv6
		"[2001:500:a8::e]:53",    // e.root-servers.net IPv6
		"[2001:500:2f::f]:53",    // f.root-servers.net IPv6
		"[2001:500:12::d0d]:53",  // g.root-servers.net IPv6
		"[2001:500:1::53]:53",    // h.root-servers.net IPv6
		"[2001:500:3::42]:53",    // i.root-servers.net IPv6
		"[2001:500:5::53]:53",    // j.root-servers.net IPv6
		"[2001:7fd::1]:53",       // k.root-servers.net IPv6
		"[2001:500:9f::42]:53",   // l.root-servers.net IPv6
		"[2001:dc3::35]:53",      // m.root-servers.net IPv6
	}
	return &Resolver{
		cache:       NewCache(),
		rootServers: rootServers,
	}
}

func (r *Resolver) handleDNSRequest(w dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) == 0 {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		w.WriteMsg(m)
		return
	}

	q := req.Question[0]
	logger.Printf("DEBUG: Получен запрос от %s: %d байт. Начинаем обработку.", w.RemoteAddr(), len(req.Raw))
	logger.Printf("DEBUG: Resolve: Запрос поступил в функцию Resolve.")

	// Проверяем кэш
	if cachedMsg := r.cache.Get(q); cachedMsg != nil {
		logger.Printf("DEBUG: Кэш попал. Возвращаем кэшированный ответ для %s.", q.Name)
		cachedMsg.SetRcode(req, dns.RcodeSuccess) // Устанавливаем код успеха для кэшированного ответа
		w.WriteMsg(cachedMsg)
		return
	}

	logger.Printf("DEBUG: Кэш промахнулся. Начинаем рекурсивное разрешение для %s (Type%s).", q.Name, dns.Type(q.Qtype).String())

	resolvedMsg, err := r.recursiveResolve(q, r.rootServers, 0)
	if err != nil {
		logger.Printf("ERROR: Ошибка резолвинга запроса от %s: %v", w.RemoteAddr(), err)
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		w.WriteMsg(m)
		return
	}

	resolvedMsg.SetRcode(req, dns.RcodeSuccess) // Устанавливаем код успеха
	r.cache.Set(q, resolvedMsg)                 // Кэшируем успешный ответ
	w.WriteMsg(resolvedMsg)
}

// recursiveResolve рекурсивно разрешает DNS-запрос.
// q - вопрос, для которого ищем ответ.
// nameServers - текущий список авторитетных серверов для зоны.
// attempts - счетчик попыток, чтобы избежать бесконечных циклов.
func (r *Resolver) recursiveResolve(q dns.Question, nameServers []string, attempts int) (*dns.Msg, error) {
	if attempts > 5 { // Ограничиваем количество попыток для предотвращения бесконечной рекурсии
		return nil, fmt.Errorf("не удалось разрешить домен %s после нескольких попыток", q.Name)
	}

	logger.Printf("DEBUG: recursiveResolve: Начинаем рекурсию для %s (ID: %d)", q.Name, attempts)
	logger.Printf("DEBUG: recursiveResolve: Попытка %d. Текущие серверы для %s: %v", attempts+1, q.Name, nameServers)

	client := new(dns.Client)
	// Устанавливаем таймаут для каждого запроса
	client.Timeout = 3 * time.Second

	for _, serverAddr := range nameServers {
		logger.Printf("DEBUG: recursiveResolve: Попытка запроса к %s для %s.", serverAddr, q.Name)

		m := new(dns.Msg)
		m.SetQuestion(q.Name, q.Qtype)
		m.RecursionDesired = false // Отключаем рекурсию для авторитетного запроса

		in, _, err := client.Exchange(m, serverAddr)
		if err != nil {
			logger.Printf("ERROR: Ошибка обмена с %s: %v", serverAddr, err)
			continue // Пробуем следующий сервер
		}

		if in == nil {
			logger.Printf("DEBUG: Ответ от %s пустой. Пробуем следующий сервер.", serverAddr)
			continue
		}

		// Если это окончательный ответ (Answers не пустые)
		if len(in.Answer) > 0 {
			logger.Printf("DEBUG: Найдены ответы для %s от %s. Завершаем рекурсию.", q.Name, serverAddr)
			return in, nil // Успех! Возвращаем ответ
		}

		// Если есть делегирование (NS записи в секции Authority)
		if len(in.Ns) > 0 {
			newNSAddresses := []string{}
			nsToResolve := make(map[string]struct{}) // Для хранения уникальных NS, требующих разрешения

			for _, rr := range in.Ns {
				if ns, ok := rr.(*dns.NS); ok {
					logger.Printf("DEBUG: Найден NS-сервер: %s.", ns.Ns)
					foundIP := false
					// Ищем A/AAAA записи для этого NS в секции Additional
					for _, extra := range in.Extra {
						if a, ok := extra.(*dns.A); ok && a.Hdr.Name == ns.Ns {
							// Важно: здесь мы используем net.JoinHostPort
							newNSAddresses = append(newNSAddresses, net.JoinHostPort(a.A.String(), "53"))
							logger.Printf("DEBUG: Найден A-запись для %s: %s", ns.Ns, a.A.String())
							foundIP = true
						}
						if aaaa, ok := extra.(*dns.AAAA); ok && aaaa.Hdr.Name == ns.Ns {
							// Важно: здесь мы используем net.JoinHostPort
							newNSAddresses = append(newNSAddresses, net.JoinHostPort(aaaa.AAAA.String(), "53"))
							logger.Printf("DEBUG: Найден AAAA-запись для %s: %s", ns.Ns, aaaa.AAAA.String())
							foundIP = true
						}
					}
					if !foundIP {
						// Добавляем NS-сервер в список для последующего разрешения, если IP не найден
						logger.Printf("DEBUG: Не удалось найти IP-адрес для NS-сервера %s в Additional-секции. Возможно, потребуется отдельный запрос на его разрешение.", ns.Ns)
						nsToResolve[ns.Ns] = struct{}{}
					}
				}
			}

			// Разрешаем NS-серверы, для которых не было "glue records"
			for nsName := range nsToResolve {
				logger.Printf("DEBUG: Выполняем отдельный запрос для разрешения IP-адреса NS-сервера: %s", nsName)
				// Выполняем рекурсивный запрос для разрешения IP-адреса NS-сервера
				// Начинаем поиск IP-адреса с корневых серверов (или с тех, которые нам известны)
				// Важно: здесь мы запрашиваем A И AAAA записи, чтобы получить оба типа IP
				nsQueryA := dns.Question{Name: nsName, Qtype: dns.TypeA, Qclass: dns.ClassINET}
				nsQueryAAAA := dns.Question{Name: nsName, Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}

				// Пытаемся разрешить A запись
				nsMsgA, errA := r.recursiveResolve(nsQueryA, r.rootServers, attempts+1) // Передаем rootServers для разрешения
				if errA == nil && nsMsgA != nil {
					for _, ans := range nsMsgA.Answer {
						if a, ok := ans.(*dns.A); ok {
							newNSAddresses = append(newNSAddresses, net.JoinHostPort(a.A.String(), "53"))
							logger.Printf("DEBUG: Успешно разрешен IP (A) для %s: %s", nsName, a.A.String())
						}
					}
				} else {
					logger.Printf("DEBUG: Не удалось разрешить A-запись для %s: %v", nsName, errA)
				}

				// Пытаемся разрешить AAAA запись
				nsMsgAAAA, errAAAA := r.recursiveResolve(nsQueryAAAA, r.rootServers, attempts+1) // Передаем rootServers для разрешения
				if errAAAA == nil && nsMsgAAAA != nil {
					for _, ans := range nsMsgAAAA.Answer {
						if aaaa, ok := ans.(*dns.AAAA); ok {
							newNSAddresses = append(newNSAddresses, net.JoinHostPort(aaaa.AAAA.String(), "53"))
							logger.Printf("DEBUG: Успешно разрешен IP (AAAA) для %s: %s", nsName, aaaa.AAAA.String())
						}
					}
				} else {
					logger.Printf("DEBUG: Не удалось разрешить AAAA-запись для %s: %v", nsName, errAAAA)
				}
			}

			if len(newNSAddresses) > 0 {
				logger.Printf("DEBUG: Найдены %d потенциальных новых серверов для %s. Переходим к следующей попытке.", len(newNSAddresses), q.Name)
				return r.recursiveResolve(q, newNSAddresses, attempts+1) // Следующая попытка с новыми серверами
			} else {
				logger.Printf("DEBUG: Найдены NS-записи, но не удалось получить IP-адреса для %s от %s. Пробуем следующий сервер в текущем списке.", q.Name, serverAddr)
			}
		}

		// Если нет ответов и нет делегирования, или если делегирование не привело к новым IP
		logger.Printf("DEBUG: Не удалось найти NS-записи или их IP для %s от %s. Пробуем следующий сервер в текущем списке.", q.Name, serverAddr)
	}

	logger.Printf("DEBUG: Не найдено новых серверов для продолжения рекурсии. Завершаем текущую попытку.")
	return nil, fmt.Errorf("не удалось разрешить домен %s после нескольких попыток", q.Name)
}

func main() {
	resolver := NewResolver()

	// Настройка DNS-сервера
	udpServer := &dns.Server{Addr: ":5353", Net: "udp"}
	tcpServer := &dns.Server{Addr: ":5353", Net: "tcp"}

	// Регистрация обработчика для всех типов запросов
	dns.HandleFunc(".", resolver.handleDNSRequest)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		logger.Printf("The ASTRACAT DNS Resolver запущен на %s (UDP)", udpServer.Addr)
		err := udpServer.ListenAndServe()
		if err != nil {
			logger.Fatalf("Не удалось запустить UDP сервер: %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		logger.Printf("The ASTRACAT DNS Resolver запущен на %s (TCP)", tcpServer.Addr)
		err := tcpServer.ListenAndServe()
		if err != nil {
			logger.Fatalf("Не удалось запустить TCP сервер: %v", err)
		}
	}()

	wg.Wait() // Ждем завершения обоих серверов (что в данном случае не произойдет, так как они слушают бесконечно)
}
