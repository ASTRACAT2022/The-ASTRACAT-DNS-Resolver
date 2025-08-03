package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"runtime"
	"syscall"
	"time"

	"The-ASTRACAT-DNS-Resolver/resolver"
	"github.com/miekg/dns"
)

const (
	port = 5353
)

func main() {
	// --- Настройка логирования ---
	log.SetOutput(io.Discard)
	// log.SetOutput(os.Stdout) // Раскомментируйте эту строку и добавьте "os" в импорты для отладки
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.SetPrefix("[ASTRACAT_DNS-RESOLVER] ")

	// Создаем контекст для всего приложения
	appCtx, appCancel := context.WithCancel(context.Background())
	defer appCancel()

	// Инициализируем наш резолвер, передавая контекст
	dnsResolver := resolver.NewResolver(appCtx)

	// Создаем UDP-сервер с опцией SO_REUSEPORT
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var err error
			// Эта опция работает только на Linux
			if runtime.GOOS == "linux" {
				c.Control(func(fd uintptr) {
					// Используем числовое значение 15 для SO_REUSEPORT, так как в некоторых средах
					// константа syscall.SO_REUSEPORT может быть не определена.
					const SO_REUSEPORT = 15
					err = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, SO_REUSEPORT, 1)
					if err != nil {
						log.Printf("Warning: Не удалось установить SO_REUSEPORT: %v", err)
					} else {
						log.Println("Debug: Опция SO_REUSEPORT успешно установлена.")
					}
				})
			}
			return err
		},
	}

	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatalf("Fatal: Ошибка разрешения UDP-адреса: %v", err)
	}

	pc, err := lc.ListenPacket(appCtx, "udp", addr.String())
	if err != nil {
		log.Fatalf("Fatal: Ошибка при прослушивании UDP: %v", err)
	}
	defer pc.Close()

	conn := pc.(*net.UDPConn)
	
	fmt.Printf("The ASTRACAT DNS Resolver запущен на UDP :%d\n", port)

	// Основной цикл обработки запросов
	for {
		buf := make([]byte, 512)
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("Error: Ошибка чтения из UDP: %v", err)
			continue
		}

		go handleDNSRequest(conn, clientAddr, buf[:n], dnsResolver)
	}
}

func handleDNSRequest(conn *net.UDPConn, clientAddr *net.UDPAddr, request []byte, r *resolver.Resolver) {
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

	log.Printf("Debug: Получен запрос от %s: %d байт. Начинаем обработку.", clientAddr.String(), len(request))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Изменено: передача clientAddr в функцию Resolve
	response, err := r.Resolve(ctx, request, clientAddr)
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
