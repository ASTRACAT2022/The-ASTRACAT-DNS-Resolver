package resolver

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"sync" // Импортируем пакет sync для WaitGroup
	"time"

	"github.com/miekg/dns" // Используем miekg/dns
)

// Prefetching constants
const (
	prefetchCheckInterval = 30 * time.Second // Как часто проверять кеш на предмет предзагрузки
	prefetchThresholdRatio = 0.1             // Предзагружать, если осталось менее 10% от OriginalTTL
	prefetchQueryTimeout   = 1 * time.Second  // Таймаут для каждого запроса предзагрузки
)

// Resolver - основной тип для нашего DNS-резолвера
type Resolver struct {
	cache *Cache
}

// NewResolver создает новый экземпляр Resolver и запускает цикл предзагрузки
func NewResolver(ctx context.Context) *Resolver {
	r := &Resolver{
		cache: NewCache(),
	}
	go r.prefetchLoop(ctx) // Запускаем цикл предзагрузки в фоновой горутине
	return r
}

// Resolve обрабатывает DNS-запрос и возвращает ответ
func (r *Resolver) Resolve(ctx context.Context, request []byte) ([]byte, error) {
	log.Printf("Debug: Resolve: Запрос поступил в функцию Resolve.")

	msg := new(dns.Msg)
	err := msg.Unpack(request)
	if err != nil {
		return nil, fmt.Errorf("ошибка распаковки DNS-запроса: %w", err)
	}

	if len(msg.Question) == 0 {
		return nil, fmt.Errorf("отсутствуют вопросы в DNS-запросе")
	}
	if len(msg.Question) > 1 {
		log.Printf("Warning: Получен DNS-запрос с более чем одним вопросом (%d). Обрабатываем только первый.", len(msg.Question))
	}

	q := msg.Question[0]
	queryName := q.Name
	queryType := dns.Type(q.Qtype).String() // Преобразуем Qtype в строку для ключа кэша
	cacheKey := fmt.Sprintf("%s_%s", queryName, queryType)

	// 1. Проверяем кэш
	if cachedResponse, found := r.cache.Get(cacheKey); found {
		log.Printf("Debug: Ответ для %s (%s) найден в кэше", queryName, queryType)

		// Важно: в кэшированном ответе нужно изменить ID запроса на тот, что пришел от клиента
		// Иначе клиент может отклонить ответ.
		cachedMsg := new(dns.Msg)
		err := cachedMsg.Unpack(cachedResponse)
		if err != nil {
			log.Printf("Error: Ошибка распаковки кэшированного ответа: %v. Попытка рекурсивного разрешения.", err)
			// Передаем bool-значение для edns0Present
			respMsg, resolveErr := r.recursiveResolve(ctx, msg.Question[0], msg.Id, rootServers, msg.IsEdns0() != nil, msg.Extra, 0)
			if resolveErr != nil {
				return nil, resolveErr
			}
			respMsg.RecursionAvailable = true // Устанавливаем флаг RA
			packedResp, packErr := respMsg.Pack()
			if packErr != nil {
				return nil, fmt.Errorf("ошибка упаковки рекурсивного ответа: %w", packErr)
			}
			return packedResp, nil
		}

		cachedMsg.Id = msg.Id                 // Устанавливаем ID из оригинального запроса
		cachedMsg.Question = msg.Question     // Устанавливаем оригинальные вопросы
		cachedMsg.RecursionAvailable = true   // Мы рекурсивный резолвер
		cachedMsg.RecursionDesired = true     // Должно быть true, так как клиент запрашивал рекурсию

		finalResponse, err := cachedMsg.Pack()
		if err != nil {
			log.Printf("Error: Ошибка пересборки кэшированного ответа: %v. Попытка рекурсивного разрешения.", err)
			// Передаем bool-значение для edns0Present
			respMsg, resolveErr := r.recursiveResolve(ctx, msg.Question[0], msg.Id, rootServers, msg.IsEdns0() != nil, msg.Extra, 0)
			if resolveErr != nil {
				return nil, resolveErr
			}
			respMsg.RecursionAvailable = true // Устанавливаем флаг RA
			packedResp, packErr := respMsg.Pack()
			if packErr != nil {
				return nil, fmt.Errorf("ошибка упаковки рекурсивного ответа: %w", packErr)
			}
			return packedResp, nil
		}
		log.Printf("Debug: Возвращаем кэшированный ответ для %s (%s)", queryName, queryType)
		return finalResponse, nil
	}

	// 2. Если нет в кэше, начинаем рекурсивное разрешение
	log.Printf("Debug: Кэш промахнулся. Начинаем рекурсивное разрешение для %s (%s)", queryName, queryType)
	// Передаем информацию EDNS(0) из входящего запроса
	// Передаем bool-значение для edns0Present
	responseMsg, err := r.recursiveResolve(ctx, q, msg.Id, rootServers, msg.IsEdns0() != nil, msg.Extra, 0)
	if err != nil {
		return nil, err
	}

	// 3. Парсим ответ, чтобы извлечь TTL и закэшировать
	minTTL := uint32(3600) // Дефолтный TTL, если не найдем ничего лучше

	// Ищем минимальный TTL среди ответов, авторитетов и дополнительных записей
	for _, rr := range responseMsg.Answer {
		if rr.Header().Ttl < minTTL {
			minTTL = rr.Header().Ttl
		}
	}
	for _, rr := range responseMsg.Ns {
		if rr.Header().Ttl < minTTL {
			minTTL = rr.Header().Ttl
		}
	}
	for _, rr := range responseMsg.Extra {
		if rr.Header().Ttl < minTTL {
			minTTL = rr.Header().Ttl
		}
	}

	packedResponse, err := responseMsg.Pack()
	if err != nil {
		log.Printf("Error: Ошибка упаковки финального ответа для кэширования: %v", err)
		return nil, err // Возвращаем ошибку, если не можем упаковать
	}

	if minTTL > 0 { // Кэшируем только если TTL больше 0
		r.cache.Set(cacheKey, packedResponse, minTTL, queryName, queryType) // Передаем queryName и queryType
		log.Printf("Debug: Ответ для %s (%s) закэширован на %d секунд", queryName, queryType, minTTL)
	}

	return packedResponse, nil
}

// recursiveResolve выполняет рекурсивный запрос к DNS-серверам.
// Теперь он отправляет запросы к нескольким серверам параллельно и ждет первый успешный ответ.
// Добавлены параметры edns0Present и incomingExtra для обработки EDNS(0) опций.
func (r *Resolver) recursiveResolve(ctx context.Context, question dns.Question, originalID uint16, currentServers []string, edns0Present bool, incomingExtra []dns.RR, depth int) (*dns.Msg, error) {
	log.Printf("Debug: recursiveResolve: Начинаем рекурсию для %s (Тип: %s, ID: %d, Глубина: %d, EDNS0: %t)", question.Name, dns.Type(question.Qtype).String(), originalID, depth, edns0Present)

	const maxRecursionDepth = 10 // Максимальное количество итераций рекурсии
	if depth > maxRecursionDepth {
		log.Printf("Error: Достигнута максимальная глубина рекурсии (%d) для %s", maxRecursionDepth, question.Name)
		return nil, fmt.Errorf("достигнута максимальная глубина рекурсии")
	}

	// Копируем currentServers, чтобы не изменять исходный слайс
	serversToQuery := make([]string, len(currentServers))
	copy(serversToQuery, currentServers)

	// Перемешиваем список серверов для лучшего распределения нагрузки
	rand.Shuffle(len(serversToQuery), func(i, j int) {
		serversToQuery[i], serversToQuery[j] = serversToQuery[j], serversToQuery[i]
	})

	var lastError error

	// Создаем дочерний контекст для всех параллельных запросов
	// Он будет отменен, как только один из запросов завершится успешно
	parallelCtx, cancelParallel := context.WithCancel(ctx)
	defer cancelParallel() // Убедимся, что контекст отменен при выходе из функции

	// WaitGroup для отслеживания завершения всех горутин
	var wg sync.WaitGroup
	// Канал для получения успешных ответов
	responseChan := make(chan *dns.Msg, len(serversToQuery))
	// Канал для получения ошибок
	errorChan := make(chan error, len(serversToQuery))

	// Отправляем запросы ко всем серверам параллельно
	for _, serverAddr := range serversToQuery {
		wg.Add(1) // Увеличиваем счетчик WaitGroup для каждой горутины
		go func(addr string) {
			defer wg.Done() // Уменьшаем счетчик WaitGroup при завершении горутины

			select {
			case <-parallelCtx.Done():
				// Если контекст уже отменен, не отправляем запрос
				log.Printf("Debug: Запрос к %s для %s отменен до отправки.", addr, question.Name)
				return
			default:
				// Продолжаем
			}

			log.Printf("Debug: recursiveResolve: Отправка запроса к %s для %s в горутине.", addr, question.Name)
			client := new(dns.Client)
			client.Net = "udp"
			client.Timeout = 2 * time.Second // Таймаут для каждого отдельного запроса

			reqMsg := new(dns.Msg)
			reqMsg.SetQuestion(question.Name, question.Qtype)
			reqMsg.Id = originalID
			reqMsg.RecursionDesired = true

			// --- EDNS(0) ---
			// Если входящий запрос содержал EDNS(0), добавляем его и к исходящему запросу
			if edns0Present {
				reqMsg.SetEdns0(4096, true) // Устанавливаем размер буфера 4096 байт, флаг DO (DNSSEC OK)
				// Копируем опции EDNS(0) из входящего запроса, если они есть
				for _, rr := range incomingExtra {
					if opt, ok := rr.(*dns.OPT); ok {
						reqMsg.Extra = append(reqMsg.Extra, opt)
						break // Предполагаем, что OPT-запись одна
					}
				}
			}

			respMsg, rtt, err := client.ExchangeContext(parallelCtx, reqMsg, addr) // Используем parallelCtx
			if err != nil {
				log.Printf("Error: Ошибка обмена DNS с %s: %v (RTT: %s)", addr, err, rtt)
				errorChan <- err
				return
			}

			if respMsg.Id != originalID {
				log.Printf("Warning: ID ответа (%d) от %s не совпадает с ID запроса (%d). Пропускаем.", respMsg.Id, addr, originalID)
				errorChan <- fmt.Errorf("ID ответа не совпадает")
				return
			}

			// Обработка усеченных ответов (Truncated)
			if respMsg.Truncated && client.Net == "udp" {
				log.Printf("Debug: Ответ от %s усечен. Попытка повторной отправки по TCP.", addr)
				client.Net = "tcp"
				respMsg, rtt, err = client.ExchangeContext(parallelCtx, reqMsg, addr) // Используем parallelCtx
				if err != nil {
					log.Printf("Error: Ошибка обмена DNS по TCP с %s после усечения: %v (RTT: %s)", addr, err, rtt)
					errorChan <- err
					return
				}
				if respMsg.Truncated {
					log.Printf("Warning: Ответ от %s усечен даже по TCP. Пропускаем.", addr)
					errorChan <- errors.New("ответ усечен даже по TCP")
					return
				}
			}

			if respMsg.Rcode != dns.RcodeSuccess {
				if respMsg.Rcode == dns.RcodeNameError {
					log.Printf("Debug: Получен NXDOMAIN для %s от %s", question.Name, addr)
					errorChan <- errors.New("NXDOMAIN")
					return
				}
				log.Printf("Warning: Получен Rcode %s для %s от %s. Пропускаем.", dns.RcodeToString[respMsg.Rcode], question.Name, addr)
				errorChan <- fmt.Errorf("DNS Rcode: %s", dns.RcodeToString[respMsg.Rcode])
				return
			}

			responseChan <- respMsg // Отправляем успешный ответ в канал
		}(serverAddr)
	}

	// Горутина для закрытия каналов после завершения всех запросов
	go func() {
		wg.Wait() // Ждем завершения всех горутин
		close(responseChan)
		close(errorChan)
	}()

	// Ждем первый успешный ответ или все ошибки
	for {
		select {
		case <-ctx.Done(): // Общий таймаут или отмена контекста
			return nil, ctx.Err()
		case respMsg, ok := <-responseChan:
			if !ok { // Канал закрыт, и ответов больше нет
				if lastError != nil {
					return nil, fmt.Errorf("не удалось разрешить домен %s после нескольких попыток: %w", question.Name, lastError)
				}
				return nil, fmt.Errorf("не удалось разрешить домен %s после нескольких попыток (нет ответа)", question.Name)
			}

			// Если есть ответы, это окончательный ответ или делегирование
			if len(respMsg.Answer) > 0 {
				log.Printf("Debug: Получен окончательный ответ для %s от одного из серверов. Обработка CNAME.", question.Name)
				cancelParallel() // Отменяем все остальные параллельные запросы
				finalResp, err := r.resolveCNAMEs(ctx, respMsg, originalID, depth+1)
				if err != nil {
					return nil, err
				}
				finalResp.RecursionAvailable = true // Устанавливаем флаг RA
				return finalResp, nil
			}

			// Если нет ответов, ищем NS-записи для продолжения рекурсии
			var nextServers []string
			foundReferral := false

			for _, rr := range respMsg.Ns {
				if ns, ok := rr.(*dns.NS); ok {
					nsName := ns.Ns
					log.Printf("Debug: Найден NS-сервер (Authority): %s", nsName)
					foundReferral = true

					foundIPForNS := false
					for _, extraRR := range respMsg.Extra {
						if extraRR.Header().Name == nsName {
							if a, ok := extraRR.(*dns.A); ok {
								nextServers = append(nextServers, net.JoinHostPort(a.A.String(), "53"))
								foundIPForNS = true
								log.Printf("Debug: Найден A-запись для NS %s: %s", nsName, a.A.String())
							} else if aaaa, ok := extraRR.(*dns.AAAA); ok {
								nextServers = append(nextServers, net.JoinHostPort(aaaa.AAAA.String(), "53"))
								foundIPForNS = true
								log.Printf("Debug: Найден AAAA-запись для NS %s: %s", nsName, aaaa.AAAA.String())
							}
						}
					}

					if !foundIPForNS {
						log.Printf("Debug: IP для NS %s не найден в Additional-секции. Попытка рекурсивного разрешения NS-имени.", nsName)
						// Передаем edns0Present
						nsIPs, err := r.resolveNSIP(ctx, nsName, originalID, rootServers, edns0Present, incomingExtra, depth+1)
						if err != nil {
							log.Printf("Error: Не удалось разрешить IP для NS %s: %v", nsName, err)
						} else {
							for _, ip := range nsIPs {
								nextServers = append(nextServers, net.JoinHostPort(ip, "53"))
								log.Printf("Debug: Разрешен IP для NS %s: %s", nsName, ip)
							}
						}
					}
				}
			}

			if foundReferral && len(nextServers) > 0 {
				log.Printf("Debug: Найдены %d потенциальных новых серверов для %s: %v. Продолжаем рекурсию.", len(nextServers), question.Name, nextServers)
				cancelParallel() // Отменяем все остальные параллельные запросы
				// Передаем edns0Present
				return r.recursiveResolve(ctx, question, originalID, nextServers, edns0Present, incomingExtra, depth+1)
			} else if foundReferral && len(nextServers) == 0 {
				log.Printf("Warning: Найдены NS-записи, но не удалось найти IP-адреса для них. Ждем другие ответы/ошибки.")
			}
		case err, ok := <-errorChan:
			if !ok { // Канал закрыт, и ошибок больше нет
				if lastError != nil {
					return nil, fmt.Errorf("не удалось разрешить домен %s после нескольких попыток: %w", question.Name, lastError)
				}
				return nil, fmt.Errorf("не удалось разрешить домен %s после нескольких попыток (нет ответа)", question.Name)
			}
			lastError = err // Сохраняем последнюю ошибку
		}
	}
}

// resolveNSIP рекурсивно разрешает IP-адрес для NS-имени.
// Добавлены параметры edns0Present и incomingExtra для обработки EDNS(0) опций.
func (r *Resolver) resolveNSIP(ctx context.Context, nsName string, originalID uint16, currentServers []string, edns0Present bool, incomingExtra []dns.RR, depth int) ([]string, error) {
	log.Printf("Debug: resolveNSIP: Разрешаем IP для NS-имени: %s (Глубина: %d)", nsName, depth)

	var ips []string
	questionA := dns.Question{
		Name:   dns.Fqdn(nsName),
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}
	questionAAAA := dns.Question{
		Name:   dns.Fqdn(nsName),
		Qtype:  dns.TypeAAAA,
		Qclass: dns.ClassINET,
	}

	// Попытка разрешить A-запись
	// Передаем edns0Present
	respA, errA := r.recursiveResolve(ctx, questionA, originalID, currentServers, edns0Present, incomingExtra, depth+1)
	if errA == nil && respA != nil {
		for _, rr := range respA.Answer {
			if a, ok := rr.(*dns.A); ok {
				ips = append(ips, a.A.String())
			}
		}
	} else {
		log.Printf("Debug: Не удалось разрешить A-запись для NS %s: %v", nsName, errA)
	}

	// Попытка разрешить AAAA-запись (если A не найдена или в дополнение к A)
	// Передаем edns0Present
	respAAAA, errAAAA := r.recursiveResolve(ctx, questionAAAA, originalID, currentServers, edns0Present, incomingExtra, depth+1)
	if errAAAA == nil && respAAAA != nil {
		for _, rr := range respAAAA.Answer {
			if aaaa, ok := rr.(*dns.AAAA); ok {
				ips = append(ips, aaaa.AAAA.String())
			}
		}
	} else {
		log.Printf("Debug: Не удалось разрешить AAAA-запись для NS %s: %v", nsName, errAAAA)
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("не найдено IP-адресов для NS-имени %s", nsName)
	}

	return ips, nil
}

// resolveCNAMEs обрабатывает CNAME-записи в ответе.
func (r *Resolver) resolveCNAMEs(ctx context.Context, msg *dns.Msg, originalID uint16, depth int) (*dns.Msg, error) {
	// Создаем новый ответ, чтобы добавлять в него записи
	finalMsg := new(dns.Msg)
	finalMsg.SetReply(msg) // Копируем заголовок и вопросы
	finalMsg.RecursionAvailable = true // Устанавливаем флаг RA

	// Добавляем все существующие ответы
	finalMsg.Answer = append(finalMsg.Answer, msg.Answer...)
	finalMsg.Ns = append(finalMsg.Ns, msg.Ns...)
	finalMsg.Extra = append(finalMsg.Extra, msg.Extra...)

	for _, rr := range msg.Answer {
		if cname, ok := rr.(*dns.CNAME); ok {
			if cname.Hdr.Name == msg.Question[0].Name {
				log.Printf("Debug: Найден CNAME для %s: %s. Продолжаем разрешение для нового имени.", cname.Hdr.Name, cname.Target)
				// Создаем новый вопрос для целевого имени CNAME
				newQuestion := dns.Question{
					Name:   cname.Target,
					Qtype:  msg.Question[0].Qtype,
					Qclass: msg.Question[0].Qclass,
				}
				// Рекурсивно разрешаем новое имя
				// Передаем edns0Present и incomingExtra из оригинального запроса
				edns0Present := msg.IsEdns0() != nil // Получаем bool
				var incomingExtraOpt []dns.RR
				for _, rr := range msg.Extra {
					if opt, ok := rr.(*dns.OPT); ok {
						incomingExtraOpt = append(incomingExtraOpt, opt)
						break
					}
				}
				resolvedCnameMsg, err := r.recursiveResolve(ctx, newQuestion, originalID, rootServers, edns0Present, incomingExtraOpt, depth+1)
				if err != nil {
					log.Printf("Error: Не удалось разрешить целевое имя CNAME %s: %v", cname.Target, err)
					return nil, err
				}
				// Добавляем ответы от разрешения CNAME в финальное сообщение
				finalMsg.Answer = append(finalMsg.Answer, resolvedCnameMsg.Answer...)
				finalMsg.Ns = append(finalMsg.Ns, resolvedCnameMsg.Ns...)
				finalMsg.Extra = append(finalMsg.Extra, resolvedCnameMsg.Extra...)
			}
		}
	}
	return finalMsg, nil
}

// prefetchLoop периодически проверяет кеш на предмет записей, которые скоро истекут, и обновляет их.
func (r *Resolver) prefetchLoop(ctx context.Context) {
	ticker := time.NewTicker(prefetchCheckInterval)
	defer ticker.Stop()

	log.Printf("Debug: Prefetching loop started with interval %s and threshold ratio %.2f", prefetchCheckInterval, prefetchThresholdRatio)

	for {
		select {
		case <-ctx.Done():
			log.Printf("Debug: Prefetching loop shutting down.")
			return
		case <-ticker.C:
			log.Printf("Debug: Running prefetch check.")
			soonToExpireEntries := r.cache.GetSoonToExpireEntries(prefetchThresholdRatio)

			if len(soonToExpireEntries) > 0 {
				log.Printf("Debug: Found %d entries for prefetching.", len(soonToExpireEntries))
			}

			for _, entry := range soonToExpireEntries {
				// Запускаем запрос предзагрузки в отдельной горутине, чтобы не блокировать цикл
				go func(e *CacheEntry) {
					// Создаем отдельный контекст для запроса предзагрузки с таймаутом
					prefetchCtx, prefetchCancel := context.WithTimeout(context.Background(), prefetchQueryTimeout)
					defer prefetchCancel()

					log.Printf("Debug: Prefetching query for %s (%s)", e.QueryName, e.QueryType)

					// Создаем вопрос для предзагрузки
					qtypeUint16 := dns.StringToType[e.QueryType]
					if qtypeUint16 == 0 { // Если тип не распознан, по умолчанию A
						qtypeUint16 = dns.TypeA
					}
					prefetchQuestion := dns.Question{
						Name:   dns.Fqdn(e.QueryName),
						Qtype:  qtypeUint16,
						Qclass: dns.ClassINET,
					}

					// Выполняем рекурсивное разрешение.
					// Для предзагрузки мы можем использовать фиктивный ID и EDNS(0) по умолчанию.
					// EDNS(0) опции (ECS) не передаются, так как это не оригинальный клиентский запрос.
					_, err := r.recursiveResolve(prefetchCtx, prefetchQuestion, uint16(rand.Intn(65535)), rootServers, true, nil, 0)
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

// rootServers - список корневых DNS-серверов.
// Это константа, но в более сложной системе могла бы обновляться.
var rootServers = []string{
	"198.41.0.4:53",        // A.ROOT-SERVERS.NET (IPv4)
	"2001:503:ba3e::2:30:53", // A.ROOT-SERVERS.NET (IPv6)
	"170.247.170.2:53",     // B.ROOT-SERVERS.NET (IPv4)
	"2801:1b8:10::b:53",    // B.ROOT-SERVERS.NET (IPv6)
	"192.33.4.12:53",       // C.ROOT-SERVERS.NET (IPv4)
	"2001:500:2::c:53",     // C.ROOT-SERVERS.NET (IPv6)
	"199.7.91.13:53",       // D.ROOT-SERVERS.NET (IPv4)
	"2001:500:2d::d:53",    // D.ROOT-SERVERS.NET (IPv6)
	"192.203.230.10:53",    // E.ROOT-SERVERS.NET (IPv4)
	"2001:500:a8::e:53",    // E.ROOT-SERVERS.NET (IPv6)
	"192.5.5.241:53",       // F.ROOT-SERVERS.NET (IPv4)
	"2001:500:2f::f:53",    // F.ROOT-SERVERS.NET (IPv6)
	"192.112.36.4:53",      // G.ROOT-SERVERS.NET (IPv4)
	"2001:500:12::d0d:53",  // G.ROOT-SERVERS.NET (IPv6)
	"198.97.190.53:53",     // H.ROOT-SERVERS.NET (IPv4)
	"2001:500:1::53",       // H.ROOT-SERVERS.NET (IPv6)
	"192.36.148.17:53",     // I.ROOT-SERVERS.NET (IPv4)
	"2001:7fe::53",         // I.ROOT-SERVERS.NET (IPv6)
	"192.58.128.30:53",     // J.ROOT-SERVERS.NET (IPv4)
	"2001:503:c27::2:30:53", // J.ROOT-SERVERS.NET (IPv6)
	"193.0.14.129:53",      // K.ROOT-SERVERS.NET (IPv4)
	"2001:7fd::1:53",       // K.ROOT-SERVERS.NET (IPv6)
	"199.7.83.42:53",       // L.ROOT-SERVERS.NET (IPv4)
	"2001:500:9f::42:53",   // L.ROOT-SERVERS.NET (IPv6)
	"202.12.27.33:53",      // M.ROOT-SERVERS.NET (IPv4)
	"2001:dc3::35:53",      // M.ROOT-SERVERS.NET (IPv6)
}
