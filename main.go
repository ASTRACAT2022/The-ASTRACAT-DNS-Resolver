package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"syscall"
	"time"

	"./resolver"
	"github.com/miekg/dns"
)

const (
	port = 5353
)

func main() {
	// --- Настройка логирования ---
	// В этой версии мы используем os.Stdout для вывода логов,
	// поэтому io больше не требуется.
	log.SetOutput(os.Stdout)
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
					// Включаем SO_REUSEPORT, чтобы несколько процессов могли прослушивать один и тот же порт
					err = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, SO_REUSEPORT, 1)
					if err != nil {
						log.Printf("Error: Не удалось установить SO_REUSEPORT: %v", err)
					}
				})
			}
			return err
		},
	}

	addr := fmt.Sprintf(":%d", port)
	conn, err := lc.ListenPacket(appCtx, "udp", addr)
	if err != nil {
		log.Fatalf("Ошибка при прослушивании UDP на %s: %v", addr, err)
	}
	defer conn.Close()

	log.Printf("ASTRACAT DNS Resolver запущен и слушает на %s", addr)

	// Буфер для чтения входящих запросов
	buffer := make([]byte, 512)

	// Приводим тип conn к *net.UDPConn для вызовов ReadFromUDP и WriteToUDP
	udpConn := conn.(*net.UDPConn)

	for {
		// Устанавливаем дедлайн для чтения, чтобы цикл не зависал
		readErr := udpConn.SetReadDeadline(time.Now().Add(1 * time.Second))
		if readErr != nil {
			continue
		}

		n, clientAddr, err := udpConn.ReadFromUDP(buffer)

		if err != nil {
			// Проверяем, не был ли это таймаут или контекст приложения завершен
			if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
				select {
				case <-appCtx.Done():
					log.Println("Контекст приложения завершен, завершаем работу...")
					return
				default:
					continue // Это был таймаут, продолжаем цикл
				}
			}
			log.Printf("Ошибка чтения из UDP: %v", err)
			continue
		}

		// Обработка запроса в отдельной горутине, чтобы не блокировать цикл
		go handleDNSRequest(appCtx, dnsResolver, udpConn, buffer[:n], clientAddr)
	}
}

// handleDNSRequest обрабатывает один DNS-запрос
func handleDNSRequest(ctx context.Context, r *resolver.Resolver, conn *net.UDPConn, request []byte, clientAddr *net.UDPAddr) {
	// Создаем контекст с таймаутом для каждого запроса
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

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
		if errorResponse != nil {
			_, writeErr := conn.WriteToUDP(errorResponse, clientAddr)
			if writeErr != nil {
				log.Printf("Error: Ошибка отправки ошибки клиенту %s: %v", clientAddr.String(), writeErr)
			}
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

// buildErrorDNSResponse создает DNS-ответ с ошибкой на основе оригинального запроса
func buildErrorDNSResponse(originalRequest []byte, rcode int) []byte {
	msg := new(dns.Msg)
	err := msg.Unpack(originalRequest)
	if err != nil {
		// Если не удалось распаковать, создаем простой ответ с ошибкой
		packedResponse, packErr := (&dns.Msg{
			MsgHdr: dns.MsgHdr{
				Id: 0, Rcode: rcode,
			},
		}).Pack()
		if packErr != nil {
			return nil
		}
		return packedResponse
	}

	response := new(dns.Msg)
	response.SetRcode(msg, rcode)
	response.Authoritative = false
	response.RecursionAvailable = true
	// Возвращаем вопрос из оригинального запроса
	if len(msg.Question) > 0 {
		response.Question = []dns.Question{msg.Question[0]}
	}

	packedResponse, packErr := response.Pack()
	if packErr != nil {
		// Если не удалось упаковать, возвращаем nil
		return nil
	}
	return packedResponse
}
