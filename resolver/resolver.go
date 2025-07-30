package resolver

import (
	"fmt"
	"log"
	"net"
	"time"

	"golang.org/x/net/dns/dnsmessage"
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
func (r *Resolver) Resolve(request []byte) ([]byte, error) {
	log.Printf("DEBUG: Resolve: Запрос поступил в функцию Resolve.")

	var msg dnsmessage.Message
	err := msg.Unpack(request) // Используем Unpack для всего сообщения сразу
	if err != nil {
		return nil, fmt.Errorf("ошибка распаковки DNS-запроса: %w", err)
	}

	if len(msg.Questions) == 0 {
		return nil, fmt.Errorf("отсутствуют вопросы в DNS-запросе")
	}

	// Для простоты пока будем обрабатывать только первый вопрос
	q := msg.Questions[0]
	queryName := q.Name.String()
	queryType := q.Type.String()
	cacheKey := fmt.Sprintf("%s_%s", queryName, queryType)

	// 1. Проверяем кэш
	if cachedResponse, found := r.cache.Get(cacheKey); found {
		log.Printf("DEBUG: Ответ для %s (%s) найден в кэше", queryName, queryType)

		// Важно: в кэшированном ответе нужно изменить ID запроса на тот, что пришел от клиента
		// Иначе клиент может отклонить ответ.
		var cachedMsg dnsmessage.Message
		err := cachedMsg.Unpack(cachedResponse)
		if err != nil {
			log.Printf("ERROR: Ошибка распаковки кэшированного ответа: %v", err)
			return r.recursiveResolve(request, q, msg.Header.ID)
		}

		cachedMsg.Header.ID = msg.Header.ID // Устанавливаем ID из оригинального запроса
		cachedMsg.Questions = msg.Questions // Устанавливаем оригинальные вопросы

		finalResponse, err := cachedMsg.Pack()
		if err != nil {
			log.Printf("ERROR: Ошибка пересборки кэшированного ответа: %v", err)
			return r.recursiveResolve(request, q, msg.Header.ID)
		}
		log.Printf("DEBUG: Возвращаем кэшированный ответ для %s (%s)", queryName, queryType)
		return finalResponse, nil
	}

	// 2. Если нет в кэше, начинаем рекурсивное разрешение
	log.Printf("DEBUG: Кэш промахнулся. Начинаем рекурсивное разрешение для %s (%s)", queryName, queryType)
	response, err := r.recursiveResolve(request, q, msg.Header.ID)
	if err != nil {
		return nil, err
	}

	// 3. Парсим ответ, чтобы извлечь TTL и закэшировать
	var responseMsg dnsmessage.Message
	err = responseMsg.Unpack(response)
	if err != nil {
		log.Printf("ERROR: Ошибка распаковки ответа для кэширования: %v", err)
		return response, nil // Возвращаем ответ, даже если не можем закэшировать
	}

	minTTL := uint32(3600) // Дефолтный TTL, если не найдем ничего лучше

	// Ищем минимальный TTL среди ответов
	for _, ans := range responseMsg.Answers {
		if ans.Header.TTL < minTTL {
			minTTL = ans.Header.TTL
		}
	}

	for _, auth := range responseMsg.Authorities {
		if auth.Header.TTL < minTTL {
			minTTL = auth.Header.TTL
		}
	}

	for _, add := range responseMsg.Additionals {
		if add.Header.TTL < minTTL {
			minTTL = add.Header.TTL
		}
	}

	if minTTL > 0 { // Кэшируем только если TTL больше 0
		r.cache.Set(cacheKey, response, minTTL)
		log.Printf("DEBUG: Ответ для %s (%s) закэширован на %d секунд", queryName, queryType, minTTL)
	}

	return response, nil
}

// recursiveResolve выполняет рекурсивный запрос к DNS-серверам
func (r *Resolver) recursiveResolve(originalRequest []byte, question dnsmessage.Question, originalID uint16) ([]byte, error) {
	log.Printf("DEBUG: recursiveResolve: Начинаем рекурсию для %s (ID: %d)", question.Name.String(), originalID)

	// Root-серверы DNS (это список общедоступных корневых серверов)
	rootServers := []string{
		"198.41.0.4:53",  // A.ROOT-SERVERS.NET
		"199.9.14.201:53", // B.ROOT-SERVERS.NET
		"192.33.4.12:53", // C.ROOT-SERVERS.NET
		"199.7.91.13:53", // D.ROOT-SERVERS.NET
		"192.203.230.10:53", // E.ROOT-SERVERS.NET
		"192.5.5.241:53", // F.ROOT-SERVERS.NET
		"192.112.36.4:53", // G.ROOT-SERVERS.NET
		"198.97.190.53:53", // H.ROOT-SERVERS.NET
		"192.36.148.17:53", // I.ROOT-SERVERS.NET
		"192.58.128.30:53", // J.ROOT-SERVERS.NET
		"193.0.14.129:53", // K.ROOT-SERVERS.NET
		"199.7.83.42:53", // L.ROOT-SERVERS.NET
		"202.12.27.33:53", // M.ROOT-SERVERS.NET
	}

	var currentServers []string = rootServers
	var responseBytes []byte

	for attempt := 0; attempt < 5; attempt++ { // Ограничим количество попыток
		nextServers := []string{} // Серверы для следующей итерации

		log.Printf("DEBUG: recursiveResolve: Попытка %d. Текущие серверы для %s: %v", attempt+1, question.Name.String(), currentServers)

		// Перемешиваем список серверов, чтобы распределить нагрузку и избежать застревания на одном неработающем сервере
		// (Простая реализация, для продакшена нужна более надежная)
		// rand.Shuffle(len(currentServers), func(i, j int) {
		// 	currentServers[i], currentServers[j] = currentServers[j], currentServers[i]
		// })

		for _, serverAddr := range currentServers {
			conn, err := net.DialTimeout("udp", serverAddr, 2*time.Second) // Таймаут 2 секунды
			if err != nil {
				log.Printf("ERROR: Не удалось подключиться к %s: %v", serverAddr, err)
				continue
			}
			defer conn.Close() // Закрываем соединение после использования

			log.Printf("DEBUG: recursiveResolve: Попытка запроса к %s для %s", serverAddr, question.Name.String())

			reqMsg := dnsmessage.Message{
				Header: dnsmessage.Header{
					ID: originalID,
					RecursionDesired: true,
				},
				Questions: []dnsmessage.Question{question},
			}
			requestToSend, err := reqMsg.Pack()
			if err != nil {
				log.Printf("ERROR: Ошибка сборки DNS-запроса для %s: %v", question.Name.String(), err)
				continue
			}

			_, err = conn.Write(requestToSend)
			if err != nil {
				log.Printf("ERROR: Ошибка отправки запроса на %s: %v", serverAddr, err)
				continue
			}

			buf := make([]byte, 512)
			conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			n, err := conn.Read(buf)
			if err != nil {
				log.Printf("ERROR: Ошибка чтения ответа от %s: %v", serverAddr, err)
				continue
			}
			responseBytes = buf[:n]

			var msg dnsmessage.Message
			err = msg.Unpack(responseBytes)
			if err != nil {
				log.Printf("ERROR: Ошибка распаковки ответа от %s: %v. Ответ (bytes): %x", serverAddr, err, responseBytes)
				continue
			}

			if msg.Header.RecursionAvailable || (msg.Header.Authoritative && len(msg.Answers) > 0) {
				if msg.Header.ID != originalID {
					log.Printf("WARNING: ID ответа (%d) от %s не совпадает с ID запроса (%d). Пропускаем.", msg.Header.ID, serverAddr, originalID)
					continue
				}
				log.Printf("DEBUG: Получен окончательный ответ для %s от %s", question.Name.String(), serverAddr)
				return responseBytes, nil
			}

			// Если ответ не окончательный, ищем NS-записи в секции "Authority"
			// и соответствующие A/AAAA записи в секции "Additional"
			for _, auth := range msg.Authorities {
				if auth.Header.Type == dnsmessage.TypeNS {
					nsName := auth.Body.(*dnsmessage.NSResource).NS.String()
					log.Printf("DEBUG: Найден NS-сервер: %s", nsName)
					
					foundIPForNS := false // Флаг, чтобы знать, нашли ли мы IP для этого NS
					for _, add := range msg.Additionals {
						if add.Header.Name.String() == nsName {
							if add.Header.Type == dnsmessage.TypeA {
								nextServers = append(nextServers, fmt.Sprintf("%s:%d", net.IP(add.Body.(*dnsmessage.AResource).A[:]).String(), 53))
								foundIPForNS = true
								log.Printf("DEBUG: Найден A-запись для %s: %s", nsName, net.IP(add.Body.(*dnsmessage.AResource).A[:]).String())
							} else if add.Header.Type == dnsmessage.TypeAAAA {
								nextServers = append(nextServers, fmt.Sprintf("%s:%d", net.IP(add.Body.(*dnsmessage.AAAAResource).AAAA[:]).String(), 53))
								foundIPForNS = true
								log.Printf("DEBUG: Найден AAAA-запись для %s: %s", nsName, net.IP(add.Body.(*dnsmessage.AAAAResource).AAAA[:]).String())
							}
						}
					}
					if !foundIPForNS {
						log.Printf("DEBUG: Не удалось найти IP-адрес для NS-сервера %s в Additional-секции. Возможно, потребуется отдельный запрос на его разрешение.", nsName)
						// В более сложной логике, здесь нужно было бы отправить отдельный рекурсивный запрос на разрешение nsName.
						// Сейчас мы просто пропускаем его, если нет glue-записей.
					}
				}
			}

			if len(nextServers) > 0 {
				log.Printf("DEBUG: Найдены %d потенциальных новых серверов для %s: %v. Переходим к следующей попытке.", len(nextServers), question.Name.String(), nextServers)
				currentServers = nextServers
				goto nextAttempt // Переходим к следующей попытке с новыми серверами
			} else {
				log.Printf("DEBUG: Не удалось найти NS-записи или их IP для %s от %s. Пробуем следующий сервер в текущем списке.", question.Name.String(), serverAddr)
			}
		}
		// Если дошли сюда, значит, все серверы в currentServers были испробованы
		// без нахождения новых серверов для продолжения или окончательного ответа.
		if len(nextServers) == 0 {
			log.Printf("DEBUG: Не найдено новых серверов для продолжения рекурсии. Завершаем текущую попытку.")
			break // Выходим из цикла попыток
		}
		currentServers = nextServers // Обновляем currentServers для следующей итерации
	nextAttempt: // Метка для goto
	}

	return nil, fmt.Errorf("не удалось разрешить домен %s после нескольких попыток", question.Name.String())
}
