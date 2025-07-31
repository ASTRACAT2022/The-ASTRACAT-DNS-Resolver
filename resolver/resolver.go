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
	prefetchCheckInterval  = 30 * time.Second
	prefetchThresholdRatio = 0.1
	prefetchQueryTimeout   = 1 * time.Second
)

// Resolver - основной тип для нашего DNS-резолвера
type Resolver struct {
	cache *Cache
}

// NewResolver создает новый экземпляр Resolver и запускает циклы предзагрузки
func NewResolver(ctx context.Context) *Resolver {
	r := &Resolver{
		cache: NewCache(),
	}
	go r.prefetchLoop(ctx)
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
	queryType := dns.Type(q.Qtype).String()
	cacheKey := fmt.Sprintf("%s_%s", queryName, queryType)

	if cachedResponse, found := r.cache.Get(cacheKey); found {
		log.Printf("Debug: Ответ для %s (%s) найден в кэше", queryName, queryType)
		cachedMsg := new(dns.Msg)
		err := cachedMsg.Unpack(cachedResponse)
		if err != nil {
			log.Printf("Error: Ошибка распаковки кэшированного ответа: %v. Попытка рекурсивного разрешения.", err)
			respMsg, resolveErr := r.recursiveResolve(ctx, msg.Question[0], msg.Id, rootServers, 0, false)
			if resolveErr != nil {
				return nil, resolveErr
			}
			respMsg.RecursionAvailable = true
			packedResp, packErr := respMsg.Pack()
			if packErr != nil {
				return nil, fmt.Errorf("ошибка упаковки рекурсивного ответа: %w", packErr)
			}
			return packedResp, nil
		}

		cachedMsg.Id = msg.Id
		cachedMsg.Question = msg.Question
		cachedMsg.RecursionAvailable = true
		cachedMsg.RecursionDesired = true

		finalResponse, err := cachedMsg.Pack()
		if err != nil {
			log.Printf("Error: Ошибка пересборки кэшированного ответа: %v. Попытка рекурсивного разрешения.", err)
			respMsg, resolveErr := r.recursiveResolve(ctx, msg.Question[0], msg.Id, rootServers, 0, false)
			if resolveErr != nil {
				return nil, resolveErr
			}
			respMsg.RecursionAvailable = true
			packedResp, packErr := respMsg.Pack()
			if packErr != nil {
				return nil, fmt.Errorf("ошибка упаковки рекурсивного ответа: %w", packErr)
			}
			return packedResp, nil
		}
		log.Printf("Debug: Возвращаем кэшированный ответ для %s (%s)", queryName, queryType)
		return finalResponse, nil
	}

	log.Printf("Debug: Кэш промахнулся. Начинаем рекурсивное разрешение для %s (%s)", queryName, queryType)
	responseMsg, err := r.recursiveResolve(ctx, q, msg.Id, rootServers, 0, true)
	if err != nil {
		return nil, err
	}

	minTTL := uint32(3600)
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
		return nil, err
	}

	if minTTL > 0 {
		r.cache.Set(cacheKey, packedResponse, minTTL, queryName, queryType)
		log.Printf("Debug: Ответ для %s (%s) закэширован на %d секунд", queryName, queryType, minTTL)
	}

	return packedResponse, nil
}

func (r *Resolver) recursiveResolve(ctx context.Context, question dns.Question, originalID uint16, currentServers []string, depth int, useQnameMinimization bool) (*dns.Msg, error) {
	log.Printf("Debug: recursiveResolve: Начинаем рекурсию для %s (Тип: %s, ID: %d, Глубина: %d, QNAME Minimization: %t)", question.Name, dns.Type(question.Qtype).String(), originalID, depth, useQnameMinimization)

	const maxRecursionDepth = 10
	if depth > maxRecursionDepth {
		log.Printf("Error: Достигнута максимальная глубина рекурсии (%d) для %s", maxRecursionDepth, question.Name)
		return nil, fmt.Errorf("достигнута максимальная глубина рекурсии")
	}

	serversToQuery := make([]string, len(currentServers))
	copy(serversToQuery, currentServers)
	rand.Shuffle(len(serversToQuery), func(i, j int) {
		serversToQuery[i], serversToQuery[j] = serversToQuery[j], serversToQuery[i]
	})

	var lastError error
	parallelCtx, cancelParallel := context.WithCancel(ctx)
	defer cancelParallel()
	var wg sync.WaitGroup
	responseChan := make(chan *dns.Msg, len(serversToQuery))
	errorChan := make(chan error, len(serversToQuery))

	for _, serverAddr := range serversToQuery {
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			select {
			case <-parallelCtx.Done():
				return
			default:
			}

			var queryName string
			if useQnameMinimization {
				labels := dns.SplitDomainName(question.Name)
				if len(labels) > depth+1 {
					queryName = strings.Join(labels[len(labels)-(depth+1):], ".") + "."
					if queryName == "." {
						queryName = "."
					}
				} else {
					queryName = question.Name
				}
			} else {
				queryName = question.Name
			}

			log.Printf("Debug: recursiveResolve: Отправка запроса к %s для %s (оригинальный: %s) в горутине.", addr, queryName, question.Name)
			
			client := new(dns.Client)
			client.Net = "udp"
			client.Timeout = 2 * time.Second

			reqMsg := new(dns.Msg)
			reqMsg.SetQuestion(queryName, question.Qtype)
			reqMsg.Id = originalID
			reqMsg.RecursionDesired = true

			respMsg, rtt, err := client.ExchangeContext(parallelCtx, reqMsg, addr)
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

			if respMsg.Truncated && client.Net == "udp" {
				log.Printf("Debug: Ответ от %s усечен. Попытка повторной отправки по TCP.", addr)
				client.Net = "tcp"
				respMsg, rtt, err = client.ExchangeContext(parallelCtx, reqMsg, addr)
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
				log.Printf("Warning: Получен Rcode %s для %s от %s. Пропускаем.", dns.RcodeToString[respMsg.Rcode], addr, dns.RcodeToString[respMsg.Rcode])
				errorChan <- fmt.Errorf("DNS Rcode: %s", dns.RcodeToString[respMsg.Rcode])
				return
			}

			responseChan <- respMsg
		}(serverAddr)
	}

	go func() {
		wg.Wait()
		close(responseChan)
		close(errorChan)
	}()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case respMsg, ok := <-responseChan:
			if !ok {
				if lastError != nil {
					return nil, fmt.Errorf("не удалось разрешить домен %s после нескольких попыток: %w", question.Name, lastError)
				}
				return nil, fmt.Errorf("не удалось разрешить домен %s после нескольких попыток (нет ответа)", question.Name)
			}

			if len(respMsg.Answer) > 0 {
				log.Printf("Debug: Получен окончательный ответ для %s от одного из серверов. Обработка CNAME.", question.Name)
				cancelParallel()
				finalResp, err := r.resolveCNAMEs(ctx, respMsg, originalID, depth+1)
				if err != nil {
					return nil, err
				}
				finalResp.RecursionAvailable = true
				return finalResp, nil
			}

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
						nsIPs, err := r.resolveNSIP(ctx, nsName, originalID, rootServers, depth+1, useQnameMinimization)
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
				cancelParallel()
				return r.recursiveResolve(ctx, question, originalID, nextServers, depth+1, useQnameMinimization)
			} else if foundReferral && len(nextServers) == 0 {
				log.Printf("Warning: Найдены NS-записи, но не удалось найти IP-адреса для них. Ждем другие ответы/ошибки.")
			}
		case err, ok := <-errorChan:
			if !ok {
				if lastError != nil {
					return nil, fmt.Errorf("не удалось разрешить домен %s после нескольких попыток: %w", question.Name, lastError)
				}
				return nil, fmt.Errorf("не удалось разрешить домен %s после нескольких попыток (нет ответа)", question.Name)
			}
			lastError = err
		}
	}
}

func (r *Resolver) resolveNSIP(ctx context.Context, nsName string, originalID uint16, currentServers []string, depth int, useQnameMinimization bool) ([]string, error) {
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

	respA, errA := r.recursiveResolve(ctx, questionA, originalID, currentServers, depth+1, useQnameMinimization)
	if errA == nil && respA != nil {
		for _, rr := range respA.Answer {
			if a, ok := rr.(*dns.A); ok {
				ips = append(ips, a.A.String())
			}
		}
	} else {
		log.Printf("Debug: Не удалось разрешить A-запись для NS %s: %v", nsName, errA)
	}

	respAAAA, errAAAA := r.recursiveResolve(ctx, questionAAAA, originalID, currentServers, depth+1, useQnameMinimization)
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

func (r *Resolver) resolveCNAMEs(ctx context.Context, msg *dns.Msg, originalID uint16, depth int) (*dns.Msg, error) {
	finalMsg := new(dns.Msg)
	finalMsg.SetReply(msg)
	finalMsg.RecursionAvailable = true

	finalMsg.Answer = append(finalMsg.Answer, msg.Answer...)
	finalMsg.Ns = append(finalMsg.Ns, msg.Ns...)
	finalMsg.Extra = append(finalMsg.Extra, msg.Extra...)

	for _, rr := range msg.Answer {
		if cname, ok := rr.(*dns.CNAME); ok {
			if cname.Hdr.Name == msg.Question[0].Name {
				log.Printf("Debug: Найден CNAME для %s: %s. Продолжаем разрешение для нового имени.", cname.Hdr.Name, cname.Target)
				newQuestion := dns.Question{
					Name:   cname.Target,
					Qtype:  msg.Question[0].Qtype,
					Qclass: msg.Question[0].Qclass,
				}
				resolvedCnameMsg, err := r.recursiveResolve(ctx, newQuestion, originalID, rootServers, depth+1, false)
				if err != nil {
					log.Printf("Error: Не удалось разрешить целевое имя CNAME %s: %v", cname.Target, err)
					return nil, err
				}
				finalMsg.Answer = append(finalMsg.Answer, resolvedCnameMsg.Answer...)
				finalMsg.Ns = append(finalMsg.Ns, resolvedCnameMsg.Ns...)
				finalMsg.Extra = append(finalMsg.Extra, resolvedCnameMsg.Extra...)
			}
		}
	}
	return finalMsg, nil
}

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

					_, err := r.recursiveResolve(prefetchCtx, prefetchQuestion, uint16(rand.Intn(65535)), rootServers, 0, false)
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

var rootServers = []string{
	"198.41.0.4:53",
	"2001:503:ba3e::2:30:53",
	"170.247.170.2:53",
	"2801:1b8:10::b:53",
	"192.33.4.12:53",
	"2001:500:2::c:53",
	"199.7.91.13:53",
	"2001:500:2d::d:53",
	"192.203.230.10:53",
	"2001:500:a8::e:53",
	"192.5.5.241:53",
	"2001:500:2f::f:53",
	"192.112.36.4:53",
	"2001:500:12::d0d:53",
	"198.97.190.53:53",
	"2001:500:1::53",
	"192.36.148.17:53",
	"2001:7fe::53",
	"192.58.128.30:53",
	"2001:503:c27::2:30:53",
	"193.0.14.129:53",
	"2001:7fd::1:53",
	"199.7.83.42:53",
	"2001:500:9f::42:53",
	"202.12.27.33:53",
	"2001:dc3::35:53",
}
