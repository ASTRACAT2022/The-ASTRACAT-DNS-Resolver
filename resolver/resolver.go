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
	var parser dnsmessage.Parser
	// Вместо Start() теперь можно просто передать байты в ParseHeader()
	// или использовать ParseAll() для полной структуры.
	// Для начала разберем заголовок, чтобы получить ID и флаги.
	header, err := parser.ParseHeader(request)
	if err != nil {
		return nil, fmt.Errorf("ошибка парсинга DNS-заголовка: %w", err)
	}

	// Чтобы получить вопросы, нужно использовать ParseQuestion().
	// Можно также использовать ParseAll() для получения всех разделов сразу,
	// но для детального контроля удобнее по секциям.
	questions := make([]dnsmessage.Question, 0)
	for {
		q, err := parser.ParseQuestion()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("ошибка парсинга DNS-вопроса: %w", err)
		}
		questions = append(questions, q)
	}

	if len(questions) == 0 {
		return nil, fmt.Errorf("отсутствуют вопросы в DNS-запросе")
	}

	// Для простоты пока будем обрабатывать только первый вопрос
	q := questions[0]
	queryName := q.Name.String()
	queryType := q.Type.String()
	cacheKey := fmt.Sprintf("%s_%s", queryName, queryType)

	// 1. Проверяем кэш
	if cachedResponse, found := r.cache.Get(cacheKey); found {
		log.Printf("Ответ для %s (%s) найден в кэше", queryName, queryType)

		// Важно: в кэшированном ответе нужно изменить ID запроса на тот, что пришел от клиента
		// Иначе клиент может отклонить ответ.
		// Используем Message для более удобной работы с готовыми сообщениями
		var msg dnsmessage.Message
		err := msg.Unpack(cachedResponse)
		if err != nil {
			log.Printf("Ошибка распаковки кэшированного ответа: %v", err)
			// Если не можем распарсить кэшированный, то лучше попытаться резолвить заново
			return r.recursiveResolve(request, q, header.ID)
		}

		msg.Header.ID = header.ID // Устанавливаем ID из оригинального запроса
		// Также убедимся, что вопросы соответствуют оригиналу, хотя в простом кэше
		// мы кэшируем только один тип запроса на одно имя.
		msg.Questions = questions 

		finalResponse, err := msg.Pack()
		if err != nil {
			log.Printf("Ошибка пересборки кэшированного ответа: %v", err)
			return r.recursiveResolve(request, q, header.ID) // Снова пытаемся резолвить
		}
		return finalResponse, nil
	}

	// 2. Если нет в кэше, начинаем рекурсивное разрешение
	log.Printf("Начинаем рекурсивное разрешение для %s (%s)", queryName, queryType)
	response, err := r.recursiveResolve(request, q, header.ID)
	if err != nil {
		return nil, err
	}

	// 3. Парсим ответ, чтобы извлечь TTL и закэшировать
	var msg dnsmessage.Message
	err = msg.Unpack(response)
	if err != nil {
		log.Printf("Ошибка распаковки ответа для кэширования: %v", err)
		return response, nil // Возвращаем ответ, даже если не можем закэшировать
	}

	minTTL := uint32(3600) // Дефолтный TTL, если не найдем ничего лучше

	// Ищем минимальный TTL среди ответов
	for _, ans := range msg.Answers {
		if ans.Header.TTL < minTTL {
			minTTL = ans.Header.TTL
		}
	}
	
	for _, auth := range msg.Authorities {
		if auth.Header.TTL < minTTL {
			minTTL = auth.Header.TTL
		}
	}

	for _, add := range msg.Additionals {
		if add.Header.TTL < minTTL {
			minTTL = add.Header.TTL
		}
	}

	if minTTL > 0 { // Кэшируем только если TTL больше 0
		r.cache.Set(cacheKey, response, minTTL)
		log.Printf("Ответ для %s (%s) закэширован на %d секунд", queryName, queryType, minTTL)
	}

	return response, nil
}

// recursiveResolve выполняет рекурсивный запрос к DNS-серверам
func (r *Resolver) recursiveResolve(originalRequest []byte, question dnsmessage.Question, originalID uint16) ([]byte, error) {
	// Root-серверы DNS (это список общедоступных корневых серверов)
	// В реальном проекте этот список должен быть актуальным и возможно обновляемым
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

	// Отправляем запрос
	var currentServers []string = rootServers
	var responseBytes []byte

	for attempt := 0; attempt < 5; attempt++ { // Ограничим количество попыток
		nextServers := []string{} // Серверы для следующей итерации

		for _, serverAddr := range currentServers {
			conn, err := net.DialTimeout("udp", serverAddr, 2*time.Second) // Таймаут 2 секунды
			if err != nil {
				log.Printf("Не удалось подключиться к %s: %v", serverAddr, err)
				continue
			}
			defer conn.Close() // Закрываем соединение после использования

			// Строим новый запрос, чтобы убедиться, что он корректен для рекурсии
			// Флаг Recursion Desired (RD) должен быть установлен
			// ID запроса должен совпадать с оригинальным
			reqMsg := dnsmessage.Message{
				Header: dnsmessage.Header{
					ID:            originalID,
					RecursionDesired: true, // Мы хотим, чтобы вышестоящий сервер делал рекурсию (если может)
				},
				Questions: []dnsmessage.Question{question},
			}
			requestToSend, err := reqMsg.Pack()
			if err != nil {
				log.Printf("Ошибка сборки DNS-запроса для %s: %v", question.Name.String(), err)
				continue
			}


			_, err = conn.Write(requestToSend)
			if err != nil {
				log.Printf("Ошибка отправки запроса на %s: %v", serverAddr, err)
				continue
			}

			// Читаем ответ
			buf := make([]byte, 512)
			conn.SetReadDeadline(time.Now().Add(3 * time.Second)) // Дополнительный таймаут на чтение
			n, err := conn.Read(buf)
			if err != nil {
				log.Printf("Ошибка чтения ответа от %s: %v", serverAddr, err)
				continue
			}
			responseBytes = buf[:n]

			// Парсим ответ с помощью dnsmessage.Message.Unpack
			var msg dnsmessage.Message
			err = msg.Unpack(responseBytes)
			if err != nil {
				log.Printf("Ошибка распаковки ответа от %s: %v", serverAddr, err)
				continue
			}

			// Проверяем, получен ли окончательный ответ (флаг RA - Recursion Available)
			// Или если это авторитетный ответ (AA - Authoritative Answer) и есть ответы
			// Или если это CNAME, и мы можем его обработать
			if msg.Header.RecursionAvailable || (msg.Header.Authoritative && len(msg.Answers) > 0) {
				// Если это финальный ответ, возвращаем его
				if msg.Header.ID != originalID {
					log.Printf("ID ответа (%d) не совпадает с ID запроса (%d) от %s. Пропускаем.", msg.Header.ID, originalID, serverAddr)
					continue
				}
				log.Printf("Получен окончательный ответ для %s от %s", question.Name.String(), serverAddr)
				return responseBytes, nil
			}

			// Если ответ не окончательный, ищем NS-записи в секции "Authority"
			// и соответствующие A/AAAA записи в секции "Additional"
			
			// Собираем NS-записи и их IP-адреса
			for _, auth := range msg.Authorities {
				if auth.Header.Type == dnsmessage.TypeNS {
					nsName := auth.Body.(*dnsmessage.NSResource).NS.String()
					// Ищем IP-адрес для этого NS-сервера в разделе Additional
					for _, add := range msg.Additionals {
						if add.Header.Name.String() == nsName {
							if add.Header.Type == dnsmessage.TypeA {
								nextServers = append(nextServers, fmt.Sprintf("%s:%d", add.Body.(*dnsmessage.AResource).A.String(), 53))
							} else if add.Header.Type == dnsmessage.TypeAAAA {
								nextServers = append(nextServers, fmt.Sprintf("%s:%d", add.Body.(*dnsmessage.AAAAResource).AAAA.String(), 53))
							}
						}
					}
				}
			}

			if len(nextServers) > 0 {
				log.Printf("Найдены %d новых серверов для %s: %v", len(nextServers), question.Name.String(), nextServers)
				currentServers = nextServers // Обновляем список серверов для следующей попытки
				goto nextAttempt // Переходим к следующей попытке с новыми серверами
			} else {
				// Если NS-записи не найдены или нет IP для них, это может быть тупик.
				// Пробуем следующий сервер из текущего списка.
				log.Printf("Не удалось найти NS-записи или их IP для %s от %s. Пробуем следующий сервер в текущем списке.", question.Name.String(), serverAddr)
			}
		}
		// Если дошли сюда, значит, все серверы в currentServers были испробованы
		// без нахождения новых серверов для продолжения или окончательного ответа.
		// Если nextServers пуст, то это тупик.
		if len(nextServers) == 0 {
			break // Выходим из цикла попыток
		}
		currentServers = nextServers // Обновляем currentServers для следующей итерации
		nextAttempt: // Метка для goto
	}

	// Если дошли до сюда, значит, не смогли разрешить
	return nil, fmt.Errorf("не удалось разрешить домен %s после нескольких попыток", question.Name.String())
}
