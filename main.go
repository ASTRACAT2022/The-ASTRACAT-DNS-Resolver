package main

import (
	"fmt"
	"io" // Добавляем для io.Discard
	"log"
	"net"
	// "runtime/debug" // Удален, так как не используется

	"astracat-dns/resolver"
	"golang.org/x/net/dns/dnsmessage"
)

const (
	port = 5353 // Порт для The ASTRACAT DNS Resolver
)

func main() {
	// *** ВАЖНО: Это должно быть одной из ПЕРВЫХ операций в main. ***
	// Устанавливаем вывод логов в "никуда", чтобы они не отображались.
	log.SetOutput(io.Discard)

	// Эти настройки (флаги и префикс) теперь не будут иметь видимого эффекта,
	// так как вывод логов отключен, но их можно оставить для легкого включения логирования обратно.
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.SetPrefix("[DNS_RESOLVER] ")

	// Инициализируем наш резолвер
	dnsResolver := resolver.NewResolver()

	// Создаем UDP-сервер
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", port))
	if err != nil {
		// log.Fatalf остается, так как это критическая ошибка запуска,
		// которая должна быть видна, даже если остальные логи отключены.
		log.Fatalf("Ошибка разрешения UDP-адреса: %v", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("Ошибка при прослушивании UDP: %v", err)
	}
	defer conn.Close()

	// Это сообщение также не будет выведено, так как логирование отключено.
	// log.Printf("The ASTRACAT DNS Resolver запущен на :%d", port)

	// Основной цикл обработки запросов
	for {
		buf := make([]byte, 512) // Максимальный размер UDP DNS-пакета
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			// log.Printf("ERROR: Ошибка чтения из UDP: %v", err)
			continue
		}

		// Запускаем обработку запроса в горутине, чтобы не блокировать сервер
		go handleDNSRequest(conn, clientAddr, buf[:n], dnsResolver)
	}
}

// handleDNSRequest обрабатывает каждый входящий DNS-запрос
func handleDNSRequest(conn *net.UDPConn, clientAddr *net.UDPAddr, request []byte, r *resolver.Resolver) {
	// Отлов паник, чтобы приложение не падало полностью
	defer func() {
		if r := recover(); r != nil {
			// Если вы хотите видеть паники, даже когда логи отключены,
			// можно использовать fmt.Printf здесь, но это не будет логироваться
			// через стандартный log пакет.
			// fmt.Printf("CRITICAL PANIC in handleDNSRequest for client %s: %v\n", clientAddr.String(), r)
			// debug.PrintStack() // Если хотите стек-трейс, нужно импортировать "runtime/debug" обратно

			// В случае паники отправляем клиенту SERVFAIL
			errorResponse := buildErrorDNSResponse(request, dnsmessage.RCodeServerFailure)
			_, writeErr := conn.WriteToUDP(errorResponse, clientAddr)
			if writeErr != nil {
				// log.Printf("ERROR: Ошибка отправки ошибки клиенту после паники %s: %v", clientAddr.String(), writeErr)
			}
		}
	}()

	// log.Printf("DEBUG: Получен запрос от %s: %d байт. Начинаем обработку.", clientAddr.String(), len(request))

	response, err := r.Resolve(request)
	if err != nil {
		// log.Printf("ERROR: Ошибка резолвинга запроса от %s: %v", clientAddr.String(), err)
		// Отправка DNS-ответа с ошибкой
		errorResponse := buildErrorDNSResponse(request, dnsmessage.RCodeServerFailure)
		_, writeErr := conn.WriteToUDP(errorResponse, clientAddr)
		if writeErr != nil {
			// log.Printf("ERROR: Ошибка отправки ошибки клиенту %s: %v", clientAddr.String(), writeErr)
		}
		return
	}

	// log.Printf("DEBUG: Запрос от %s успешно разрешен. Отправляем ответ.", clientAddr.String())
	_, err = conn.WriteToUDP(response, clientAddr)
	if err != nil {
		// log.Printf("ERROR: Ошибка отправки ответа клиенту %s: %v", clientAddr.String(), err)
	} else {
		// log.Printf("DEBUG: Ответ успешно отправлен клиенту %s", clientAddr.String())
	}
}

// buildErrorDNSResponse создает DNS-ответ с указанным кодом ошибки (RCode).
func buildErrorDNSResponse(originalRequest []byte, rcode dnsmessage.RCode) []byte {
	var originalMsg dnsmessage.Message
	// Попытаемся распаковать оригинальный запрос, чтобы скопировать ID и вопросы.
	// Если не получится, используем дефолтные значения.
	if err := originalMsg.Unpack(originalRequest); err != nil {
		// log.Printf("DEBUG: Не удалось распаковать оригинальный запрос для формирования ошибки: %v", err)
		// Если запрос невалидный, создадим минимальный ответ с ошибкой
		resp := dnsmessage.Message{
			Header: dnsmessage.Header{
				ID:       0, // Или случайный ID, если originalMsg.Header.ID невалиден
				Response: true,
				RCode:    rcode,
			},
		}
		packed, _ := resp.Pack() // Игнорируем ошибку упаковки для простоты
		return packed
	}

	resp := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 originalMsg.Header.ID,
			Response:           true,
			RecursionDesired:   originalMsg.Header.RecursionDesired,
			RecursionAvailable: true, // Мы рекурсивный резолвер
			RCode:              rcode,
		},
		Questions: originalMsg.Questions, // Копируем оригинальные вопросы
	}
	packed, err := resp.Pack()
	if err != nil {
		// log.Printf("ERROR: Ошибка упаковки DNS-ответа с ошибкой: %v", err)
		return []byte{} // Возвращаем пустые байты в случае критической ошибки
	}
	return packed
}
