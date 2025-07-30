package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	// ИСПРАВЛЕННЫЙ ПУТЬ ИМПОРТА
	"github.com/ASTRACAT2022/The-ASTRACAT-DNS-Resolver/resolver" 
	"github.com/miekg/dns" // Используем miekg/dns
)

const (
	port = 5353 // Порт для The ASTRACAT DNS Resolver
)

func main() {
	// --- Настройка логирования ---
	// Для отладки раскомментируйте следующую строку:
	// log.SetOutput(os.Stdout)
	log.SetOutput(io.Discard) // Отключаем логирование по умолчанию для "чистоты"
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.SetPrefix("[ASTRACAT_DNS_RESOLVER] ")

	// Инициализируем наш резолвер
	dnsResolver := resolver.NewResolver()

	// Создаем UDP-сервер
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatalf("Fatal: Ошибка разрешения UDP-адреса: %v", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("Fatal: Ошибка при прослушивании UDP: %v", err)
	}
	defer conn.Close()

	fmt.Printf("The ASTRACAT DNS Resolver запущен на UDP :%d\n", port) // Всегда выводим в консоль

	// Основной цикл обработки запросов
	for {
		buf := make([]byte, 512) // Максимальный размер UDP DNS-пакета
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("Error: Ошибка чтения из UDP: %v", err)
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
		if rec := recover(); rec != nil {
			log.Printf("Critical Panic in handleDNSRequest for client %s: %v", clientAddr.String(), rec)
			// Отправляем SERVFAIL, чтобы клиент знал, что что-то пошло не так
			errorResponse := buildErrorDNSResponse(request, dns.RcodeServerFailure)
			_, writeErr := conn.WriteToUDP(errorResponse, clientAddr)
			if writeErr != nil {
				log.Printf("Error: Ошибка отправки ошибки клиенту после паники %s: %v", clientAddr.String(), writeErr)
			}
		}
	}()

	log.Printf("Debug: Получен запрос от %s: %d байт. Начинаем обработку.", clientAddr.String(), len(request))

	// Создаем контекст для запроса с таймаутом
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second) // Общий таймаут на разрешение
	defer cancel()

	response, err := r.Resolve(ctx, request)
	if err != nil {
		log.Printf("Error: Ошибка резолвинга запроса от %s: %v", clientAddr.String(), err)
		// Отправка DNS-ответа с ошибкой
		rcode := dns.RcodeServerFailure
		if err == context.DeadlineExceeded || err == context.Canceled {
			rcode = dns.RcodeServerFailure // Или dns.RcodeRefused, если хотите
		} else if err.Error() == "NXDOMAIN" { // Пример для NXDOMAIN
			rcode = dns.RcodeNameError
		}
		errorResponse := buildErrorDNSResponse(request, rcode)
		_, writeErr := conn.WriteToUDP(errorResponse, clientAddr)
		if writeErr != nil {
			log.Printf("Error: Ошибка отправки ошибки клиенту %s: %v", clientAddr.String(), writeErr)
		}
		return
	}

	log.Printf("Debug: Запрос от %s успешно разрешен. Отправляем ответ.", clientAddr.String())
	_, err = conn.WriteToUDP(response, clientAddr)
	if err != nil {
		log.Printf("Error: Ошибка отправки ответа клиенту %s: %v", clientAddr.String(), err)
	} else {
		log.Printf("Debug: Ответ успешно отправлен клиенту %s", clientAddr.String())
	}
}

// buildErrorDNSResponse создает DNS-ответ с указанным кодом ошибки (RCode).
func buildErrorDNSResponse(originalRequest []byte, rcode int) []byte {
	msg := new(dns.Msg)
	err := msg.Unpack(originalRequest)
	if err != nil {
		// Если запрос невалидный, создадим минимальный ответ с ошибкой
		resp := new(dns.Msg)
		resp.SetRcode(msg, rcode)
		packed, _ := resp.Pack()
		return packed
	}

	resp := new(dns.Msg)
	resp.SetRcode(msg, rcode)
	resp.RecursionAvailable = true // Мы рекурсивный резолвер
	packed, err := resp.Pack()
	if err != nil {
		log.Printf("Error: Ошибка упаковки DNS-ответа с ошибкой: %v", err)
		return []byte{} // Возвращаем пустые байты в случае критической ошибки
	}
	return packed
}
