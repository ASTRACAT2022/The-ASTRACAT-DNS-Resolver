package resolver

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"time"

	"github.com/miekg/dns" // Используем miekg/dns
)

// Resolver - основной тип для нашего DNS-резолвера
type Resolver struct {
	cache *Cache
}

// NewResolver создает новый экземпляр Resolver
func NewResolver() *Resolver {
	return &Resolver{
		cache: NewCache(),
	}
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
			// ИСПРАВЛЕНИЕ: Упаковываем ответ recursiveResolve перед возвратом
			respMsg, resolveErr := r.recursiveResolve(ctx, msg.Question[0], msg.Id, rootServers, 0)
			if resolveErr != nil {
				return nil, resolveErr
			}
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
			// ИСПРАВЛЕНИЕ: Упаковываем ответ recursiveResolve перед возвратом
			respMsg, resolveErr := r.recursiveResolve(ctx, msg.Question[0], msg.Id, rootServers, 0)
			if resolveErr != nil {
				return nil, resolveErr
			}
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
	responseMsg, err := r.recursiveResolve(ctx, q, msg.Id, rootServers, 0)
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
		r.cache.Set(cacheKey, packedResponse, minTTL)
		log.Printf("Debug: Ответ для %s (%s) закэширован на %d секунд", queryName, queryType, minTTL)
	}

	return packedResponse, nil
}

// recursiveResolve выполняет рекурсивный запрос к DNS-серверам
func (r *Resolver) recursiveResolve(ctx context.Context, question dns.Question, originalID uint16, currentServers []string, depth int) (*dns.Msg, error) {
	log.Printf("Debug: recursiveResolve: Начинаем рекурсию для %s (Тип: %s, ID: %d, Глубина: %d)", question.Name, dns.Type(question.Qtype).String(), originalID, depth)

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

	for _, serverAddr := range serversToQuery {
		select {
		case <-ctx.Done():
			return nil, ctx.Err() // Контекст отменен или истек таймаут
		default:
			// Продолжаем
		}

		log.Printf("Debug: recursiveResolve: Попытка запроса к %s для %s", serverAddr, question.Name)

		// Создаем DNS-клиент с таймаутом
		client := new(dns.Client)
		client.Net = "udp" // Начинаем с UDP
		// Таймаут для обмена сообщений. Можно сделать его динамическим,
		// но для простоты пока фиксированный.
		client.Timeout = 2 * time.Second

		reqMsg := new(dns.Msg)
		reqMsg.SetQuestion(question.Name, question.Qtype)
		reqMsg.Id = originalID
		reqMsg.RecursionDesired = true // Просим рекурсию, но сами ее выполняем

		// Отправляем запрос
		respMsg, rtt, err := client.ExchangeContext(ctx, reqMsg, serverAddr)
		if err != nil {
			log.Printf("Error: Ошибка обмена DNS с %s: %v (RTT: %s)", serverAddr, err, rtt)
			lastError = err
			continue
		}

		// Проверяем, совпадает ли ID запроса/ответа
		if respMsg.Id != originalID {
			log.Printf("Warning: ID ответа (%d) от %s не совпадает с ID запроса (%d). Пропускаем.", respMsg.Id, serverAddr, originalID)
			continue
		}

		// --- Обработка усеченных ответов (Truncated) ---
		if respMsg.Truncated && client.Net == "udp" {
			log.Printf("Debug: Ответ от %s усечен. Попытка повторной отправки по TCP.", serverAddr)
			client.Net = "tcp"
			respMsg, rtt, err = client.ExchangeContext(ctx, reqMsg, serverAddr)
			if err != nil {
				log.Printf("Error: Ошибка обмена DNS по TCP с %s после усечения: %v (RTT: %s)", serverAddr, err, rtt)
				lastError = err
				continue
			}
			if respMsg.Truncated { // Если и по TCP усечен, это проблема
				log.Printf("Warning: Ответ от %s усечен даже по TCP. Пропускаем.", serverAddr)
				lastError = errors.New("ответ усечен даже по TCP")
				continue
			}
		}

		// --- Проверяем Rcode ---
		if respMsg.Rcode != dns.RcodeSuccess {
			if respMsg.Rcode == dns.RcodeNameError { // NXDOMAIN
				log.Printf("Debug: Получен NXDOMAIN для %s от %s", question.Name, serverAddr)
				return respMsg, errors.New("NXDOMAIN") // Возвращаем ошибку NXDOMAIN
			}
			log.Printf("Warning: Получен Rcode %s для %s от %s. Пропускаем.", dns.RcodeToString[respMsg.Rcode], question.Name, serverAddr)
			lastError = fmt.Errorf("DNS Rcode: %s", dns.RcodeToString[respMsg.Rcode])
			continue
		}

		// --- Проверяем секцию "Answer" ---
		if len(respMsg.Answer) > 0 {
			// Если есть ответы, это окончательный ответ.
			// Нужно обработать CNAME, если он присутствует.
			log.Printf("Debug: Получен окончательный ответ для %s от %s. Обработка CNAME.", question.Name, serverAddr)
			finalResp, err := r.resolveCNAMEs(ctx, respMsg, originalID, depth+1)
			if err != nil {
				return nil, err
			}
			return finalResp, nil
		}

		// --- Если нет ответов, ищем NS-записи в секции "Authority" для продолжения рекурсии ---
		var nextServers []string
		foundReferral := false

		for _, rr := range respMsg.Ns {
			if ns, ok := rr.(*dns.NS); ok {
				nsName := ns.Ns
				log.Printf("Debug: Найден NS-сервер (Authority): %s", nsName)
				foundReferral = true

				// Ищем IP-адрес для этого NS-сервера в секции Additional
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

				// Если IP не найден в Additional (glue record), рекурсивно разрешаем NS-имя
				if !foundIPForNS {
					log.Printf("Debug: IP для NS %s не найден в Additional-секции. Попытка рекурсивного разрешения NS-имени.", nsName)
					nsIPs, err := r.resolveNSIP(ctx, nsName, originalID, rootServers, depth+1) // Начинаем с корня для разрешения NS
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
			// Если нашли делегирование и IP-адреса для новых серверов, продолжаем рекурсию
			log.Printf("Debug: Найдены %d потенциальных новых серверов для %s: %v. Продолжаем рекурсию.", len(nextServers), question.Name, nextServers)
			return r.recursiveResolve(ctx, question, originalID, nextServers, depth+1)
		} else if foundReferral && len(nextServers) == 0 {
			// Нашли NS-записи, но не смогли получить их IP.
			log.Printf("Warning: Найдены NS-записи, но не удалось найти IP-адреса для них. Пробуем следующий сервер в текущем списке.")
		}
	}

	// Если мы прошли по всем текущим серверам и не смогли разрешить домен
	if lastError != nil {
		return nil, fmt.Errorf("не удалось разрешить домен %s после нескольких попыток: %w", question.Name, lastError)
	}
	return nil, fmt.Errorf("не удалось разрешить домен %s после нескольких попыток (нет ответа)", question.Name)
}

// resolveNSIP рекурсивно разрешает IP-адрес для NS-имени.
func (r *Resolver) resolveNSIP(ctx context.Context, nsName string, originalID uint16, currentServers []string, depth int) ([]string, error) {
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
	respA, errA := r.recursiveResolve(ctx, questionA, originalID, currentServers, depth+1)
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
	respAAAA, errAAAA := r.recursiveResolve(ctx, questionAAAA, originalID, currentServers, depth+1)
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
				resolvedCnameMsg, err := r.recursiveResolve(ctx, newQuestion, originalID, rootServers, depth+1)
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
