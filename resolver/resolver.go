package resolver

import (
	"fmt"
	"log"
	"net"
	"time"

	"golang.org/x/net/dns/dnsmessage" // Отличная библиотека для работы с DNS-сообщениями
)

// Resolver - основной тип для нашего DNS-резолвера
type Resolver struct {
	cache *Cache
	// Здесь можно добавить корневые DNS-серверы, если они не будут жестко закодированы
	// rootServers []net.UDPAddr
}

// NewResolver создает новый экземпляр Resolver
func NewResolver() *Resolver {
	return &Resolver{
		cache: NewCache(),
		// rootServers: ...
	}
}

// Resolve обрабатывает DNS-запрос и возвращает ответ
func (r *Resolver) Resolve(request []byte) ([]byte, error) {
	var parser dnsmessage.Parser
	header, err := parser.Start(request)
	if err != nil {
		return nil, fmt.Errorf("ошибка парсинга DNS-заголовка: %w", err)
	}

	questions, err := parser.AllQuestions()
	if err != nil || len(questions) == 0 {
		return nil, fmt.Errorf("ошибка парсинга DNS-вопросов или их отсутствие: %w", err)
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
		var cachedParser dnsmessage.Parser
		cachedHeader, err := cachedParser.Start(cachedResponse)
		if err != nil {
			log.Printf("Ошибка парсинга кэшированного ответа: %v", err)
			// Если не можем распарсить кэшированный, то лучше попытаться резолвить заново
			return r.recursiveResolve(request, q, header.ID)
		}
		cachedHeader.ID = header.ID // Устанавливаем ID из оригинального запроса
		
		// Пересобираем сообщение с новым ID
		builder := dnsmessage.Builder{}
		builder.SetHeader(cachedHeader)
		builder.EnableCompression() // Важно для DNS
		
		// Копируем вопросы, ответы, авторитетные и дополнительные записи
		for _, qst := range questions {
			builder.AddQuestion(qst)
		}

		answers, _ := cachedParser.AllAnswers()
		for _, ans := range answers {
			builder.AddAnswer(ans)
		}
		
		authorities, _ := cachedParser.AllAuthorities()
		for _, auth := range authorities {
			builder.AddAuthority(auth)
		}

		additionals, _ := cachedParser.AllAdditionals()
		for _, add := range additionals {
			builder.AddAdditional(add)
		}

		finalResponse, err := builder.Pack()
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
	var responseParser dnsmessage.Parser
	_, err = responseParser.Start(response)
	if err != nil {
		log.Printf("Ошибка парсинга ответа для кэширования: %v", err)
		return response, nil // Возвращаем ответ, даже если не можем закэшировать
	}

	minTTL := uint32(3600) // Дефолтный TTL, если не найдем ничего лучше

	// Ищем минимальный TTL среди ответов
	answers, _ := responseParser.AllAnswers()
	for _, ans := range answers {
		if ans.Header.TTL < minTTL {
			minTTL = ans.Header.TTL
		}
	}
	
	authorities, _ := responseParser.AllAuthorities()
	for _, auth := range authorities {
		if auth.Header.TTL < minTTL {
			minTTL = auth.Header.TTL
		}
	}

	additionals, _ := responseParser.AllAdditionals()
	for _, add := range additionals {
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
		// ... добавьте больше корневых серверов для надежности
	}

	// Отправляем запрос
	var currentServers []string = rootServers
	var responseBytes []byte

	for attempt := 0; attempt < 5; attempt++ { // Ограничим количество попыток
		for _, serverAddr := range currentServers {
			conn, err := net.DialTimeout("udp", serverAddr, 2*time.Second) // Таймаут 2 секунды
			if err != nil {
				log.Printf("Не удалось подключиться к %s: %v", serverAddr, err)
				continue
			}
			defer conn.Close() // Закрываем соединение после использования

			// Отправляем запрос (не обязательно оригинальный, можно построить новый)
			// Однако для простоты пока будем отправлять тот, что пришел
			// В реальности мы должны отправлять запрос только с флагом RD (Recursion Desired)
			// и без флага RA (Recursion Available), так как мы сами рекурсивные
			_, err = conn.Write(originalRequest)
			if err != nil {
				log.Printf("Ошибка отправки запроса на %s: %v", serverAddr, err)
				continue
			}

			// Читаем ответ
			buf := make([]byte, 512)
			n, err := conn.Read(buf)
			if err != nil {
				log.Printf("Ошибка чтения ответа от %s: %v", serverAddr, err)
				continue
			}
			responseBytes = buf[:n]

			// Парсим ответ
			var parser dnsmessage.Parser
			header, err := parser.Start(responseBytes)
			if err != nil {
				log.Printf("Ошибка парсинга ответа от %s: %v", serverAddr, err)
				continue
			}

			// Проверяем, получен ли окончательный ответ (флаг RA - Recursion Available)
			// Или если это авторитетный ответ (AA - Authoritative Answer) и есть ответы
			if header.RecursionAvailable || (header.Authoritative && len(parser.AllAnswers().CNAMEs)+len(parser.AllAnswers().ARecords)+len(parser.AllAnswers().AAAARecords) > 0) {
				// Если это финальный ответ, возвращаем его
				// Важно: нужно убедиться, что ID ответа совпадает с ID запроса,
				// который мы отправили
				if header.ID != originalID {
					log.Printf("ID ответа (%d) не совпадает с ID запроса (%d) от %s. Пропускаем.", header.ID, originalID, serverAddr)
					continue
				}
				log.Printf("Получен окончательный ответ для %s от %s", question.Name.String(), serverAddr)
				return responseBytes, nil
			}

			// Если ответ не окончательный, ищем NS-записи в секции "Authority"
			authorities, err := parser.AllAuthorities()
			if err != nil {
				log.Printf("Ошибка парсинга Authority-записей от %s: %v", serverAddr, err)
				continue
			}
			
			// Ищем дополнительные A/AAAA записи в секции "Additional"
			additionals, err := parser.AllAdditionals()
			if err != nil {
				log.Printf("Ошибка парсинга Additional-записей от %s: %v", serverAddr, err)
				continue
			}

			nextServers := []string{}
			// Собираем NS-записи
			for _, auth := range authorities.NSs {
				nsName := auth.NS.String()
				// Ищем IP-адрес для этого NS-сервера в разделе Additional
				for _, add := range additionals.ARecords {
					if add.Header.Name.String() == nsName {
						nextServers = append(nextServers, fmt.Sprintf("%s:%d", add.A.String(), 53))
					}
				}
				for _, add := range additionals.AAAARecords {
					if add.Header.Name.String() == nsName {
						nextServers = append(nextServers, fmt.Sprintf("%s:%d", add.AAAA.String(), 53))
					}
				}
			}

			if len(nextServers) > 0 {
				log.Printf("Найдены %d новых серверов для %s: %v", len(nextServers), question.Name.String(), nextServers)
				currentServers = nextServers
				break // Переходим к следующей итерации с новыми серверами
			} else {
				// Если NS-записи не найдены или нет IP для них, это может быть тупик.
				// Пробуем следующий сервер из текущего списка.
				log.Printf("Не удалось найти NS-записи или их IP для %s от %s. Пробуем следующий сервер.", question.Name.String(), serverAddr)
			}
		}
		if len(currentServers) == 0 {
			break // Если не найдено серверов для продолжения, выходим
		}
	}

	// Если дошли до сюда, значит, не смогли разрешить
	return nil, fmt.Errorf("не удалось разрешить домен %s после нескольких попыток", question.Name.String())
}
