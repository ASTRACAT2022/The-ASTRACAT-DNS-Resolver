package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/ASTRACAT2022/The-ASTRACAT-DNS-Resolver/resolver"
	"github.com/miekg/dns"
)

const (
	port = 5353 // Порт для The ASTRACAT DNS Resolver
)

// --- Rate Limiting ---
const (
	// Максимальное количество запросов в секунду для одного IP-адреса
	maxRequestsPerSecond = 10
	// Период окна для ограничения скорости (например, 1 секунда)
	rateLimitWindow = 1 * time.Second
)

// clientRequestCounter хранит количество запросов от каждого IP-адреса
var clientRequestCounter = make(map[string]int)
// clientWindowStart хранит время начала текущего окна для каждого IP-адреса
var clientWindowStart = make(map[string]time.Time)
var mu sync.Mutex // Мьютекс для защиты доступа к картам rate limiter'а

func main() {
	// --- Настройка логирования ---
	log.SetOutput(os.Stdout) // Включаем логирование для отладки
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.SetPrefix("[ASTRACAT_DNS_RESOLVER] ")

	// Создаем контекст для всего приложения, который будет управлять жизненным циклом, включая предзагрузку
	appCtx, appCancel := context.WithCancel(context.Background())
	defer appCancel() // Убедимся, что контекст отменен при выходе из main

	// Инициализируем наш резолвер, передавая контекст
	dnsResolver := resolver.NewResolver(appCtx) // <--- ИЗМЕНЕНО

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

	fmt.Printf("The ASTRACAT DNS Resolver запущен на UDP :%d\n", port)

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
			errorResponse := buildErrorDNSResponse(request, dns.RcodeServerFailure)
			_, writeErr := conn.WriteToUDP(errorResponse, clientAddr)
			if writeErr != nil {
				log.Printf("Error: Ошибка отправки ошибки клиенту после паники %s: %v", clientAddr.String(), writeErr)
			}
		}
	}()

	clientIP := clientAddr.IP.String()

	// --- Rate Limiting Check ---
	if !allowRequest(clientIP) {
		log.Printf("Warning: Запрос от %s отклонен из-за превышения лимита скорости.", clientIP)
		errorResponse := buildErrorDNSResponse(request, dns.RcodeServerFailure) // Или RcodeRefused
		_, writeErr := conn.WriteToUDP(errorResponse, clientAddr)
		if writeErr != nil {
			log.Printf("Error: Ошибка отправки ошибки клиенту (rate limit) %s: %v", clientAddr.String(), writeErr)
		}
		return
	}

	log.Printf("Debug: Получен запрос от %s: %d байт. Начинаем обработку.", clientAddr.String(), len(request))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	response, err := r.Resolve(ctx, request)
	if err != nil {
		log.Printf("Error: Ошибка резолвинга запроса от %s: %v", clientAddr.String(), err)
		rcode := dns.RcodeServerFailure
		if err == context.DeadlineExceeded || err == context.Canceled {
			rcode = dns.RcodeServerFailure
		} else if err.Error() == "NXDOMAIN" {
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

// allowRequest проверяет, разрешен ли запрос от данного IP-адреса согласно лимиту скорости.
func allowRequest(ip string) bool {
	mu.Lock()
	defer mu.Unlock()

	now := time.Now()

	// Если окно для этого IP истекло, сбрасываем счетчик
	if lastWindowStart, ok := clientWindowStart[ip]; !ok || now.Sub(lastWindowStart) >= rateLimitWindow {
		clientRequestCounter[ip] = 0
		clientWindowStart[ip] = now
	}

	// Увеличиваем счетчик запросов
	clientRequestCounter[ip]++

	// Проверяем, не превышен ли лимит
	return clientRequestCounter[ip] <= maxRequestsPerSecond
}

// buildErrorDNSResponse создает DNS-ответ с указанным кодом ошибки (RCode).
func buildErrorDNSResponse(originalRequest []byte, rcode int) []byte {
	msg := new(dns.Msg)
	err := msg.Unpack(originalRequest)
	if err != nil {
		resp := new(dns.Msg)
		resp.SetRcode(msg, rcode)
		packed, _ := resp.Pack()
		return packed
	}

	resp := new(dns.Msg)
	resp.SetRcode(msg, rcode)
	resp.RecursionAvailable = true
	packed, err := resp.Pack()
	if err != nil {
		log.Printf("Error: Ошибка упаковки DNS-ответа с ошибкой: %v", err)
		return []byte{}
	}
	return packed
}
