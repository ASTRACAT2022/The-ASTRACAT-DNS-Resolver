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

	"The-ASTRACAT-DNS-Resolver/resolver"
	"github.com/miekg/dns"
)

const (
	port = 5353
)

// RequestData содержит данные, необходимые для обработки DNS-запроса
type RequestData struct {
	request    []byte
	clientAddr *net.UDPAddr
}

func main() {
	// --- Настройка логирования ---
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
			if runtime.GOOS == "linux" {
				c.Control(func(fd uintptr) {
					const SO_REUSEPORT = 15
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

	// Приводим тип conn к *net.UDPConn для вызовов ReadFromUDP и WriteToUDP
	udpConn := conn.(*net.UDPConn)

	// Создаем канал для передачи запросов рабочим потокам
	requestQueue := make(chan RequestData, 1000)

	// Определяем количество рабочих потоков.
	// Используем количество ядер CPU для оптимальной производительности.
	numWorkers := runtime.NumCPU()
	if numWorkers < 1 {
		numWorkers = 1
	}

	log.Printf("Запускаем пул из %d рабочих потоков для обработки DNS-запросов", numWorkers)
	for i := 0; i < numWorkers; i++ {
		go handleDNSRequest(appCtx, dnsResolver, udpConn, requestQueue)
	}

	// Буфер для чтения входящих запросов
	buffer := make([]byte, 512)

	for {
		readErr := udpConn.SetReadDeadline(time.Now().Add(1 * time.Second))
		if readErr != nil {
			continue
		}

		n, clientAddr, err := udpConn.ReadFromUDP(buffer)

		if err != nil {
			if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
				select {
				case <-appCtx.Done():
					log.Println("Контекст приложения завершен, завершаем работу...")
					return
				default:
					continue
				}
			}
			log.Printf("Ошибка чтения из UDP: %v", err)
			continue
		}

		// Копируем данные из буфера перед отправкой в канал,
		// чтобы избежать состояния гонки.
		requestCopy := make([]byte, n)
		copy(requestCopy, buffer[:n])

		// Отправляем запрос в канал для обработки рабочим потоком.
		// Если канал переполнен, будем ждать.
		select {
		case requestQueue <- RequestData{request: requestCopy, clientAddr: clientAddr}:
		case <-appCtx.Done():
			log.Println("Контекст приложения завершен, завершаем работу...")
			return
		}
	}
}

// handleDNSRequest обрабатывает DNS-запросы, получая их из канала
func handleDNSRequest(ctx context.Context, r *resolver.Resolver, conn *net.UDPConn, requestQueue <-chan RequestData) {
	for {
		select {
		case <-ctx.Done():
			return // Завершаем горутину, если контекст приложения отменен
		case data := <-requestQueue:
			// Создаем контекст с таймаутом для каждого запроса
			reqCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

			response, err := r.Resolve(reqCtx, data.request, data.clientAddr)
			if err != nil {
				log.Printf("Error: Ошибка резолвинга запроса от %s: %v", data.clientAddr.String(), err)
				rcode := dns.RcodeServerFailure
				if err == context.DeadlineExceeded || err == context.Canceled {
					rcode = dns.RcodeServerFailure
				} else if err.Error() == "NXDOMAIN" {
					rcode = dns.RcodeNameError
				}
				errorResponse := buildErrorDNSResponse(data.request, rcode)
				if errorResponse != nil {
					_, writeErr := conn.WriteToUDP(errorResponse, data.clientAddr)
					if writeErr != nil {
						log.Printf("Error: Ошибка отправки ошибки клиенту %s: %v", data.clientAddr.String(), writeErr)
					}
				}
			} else {
				log.Printf("Debug: Запрос от %s успешно разрешен. Отправляем ответ.", data.clientAddr.String())
				_, err = conn.WriteToUDP(response, data.clientAddr)
				if err != nil {
					log.Printf("Error: Ошибка отправки ответа клиенту %s: %v", data.clientAddr.String(), err)
				} else {
					log.Printf("Debug: Ответ успешно отправлен клиенту %s", data.clientAddr.String())
				}
			}
			cancel() // Не забываем отменять контекст
		}
	}
}

// buildErrorDNSResponse создает DNS-ответ с ошибкой на основе оригинального запроса
func buildErrorDNSResponse(originalRequest []byte, rcode int) []byte {
	msg := new(dns.Msg)
	err := msg.Unpack(originalRequest)
	if err != nil {
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
	if len(msg.Question) > 0 {
		response.Question = []dns.Question{msg.Question[0]}
	}

	packedResponse, packErr := response.Pack()
	if packErr != nil {
		return nil
	}
	return packedResponse
}
