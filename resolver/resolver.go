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
	// port - порт, на котором будет работать DNS-сервер.
	port = 5353
	// workers - количество горутин для обработки запросов.
	workers = 4
	// requestQueueapacity - емкость канала для запросов.
	requestQueueCapacity = 100000
	// maxMessageSize - максимальный размер UDP-сообщения.
	maxMessageSize = 512
)

// RequestData содержит данные, необходимые для обработки DNS-запроса.
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
	dnsResolver := resolver.NewResolver(appCtx, resolver.WithCache(1000000), resolver.WithExpiry(), resolver.WithTCPRetry())

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
		log.Fatalf("Fatal: Не удалось запустить сервер: %v", err)
	}
	defer conn.Close()
	
	log.Printf("Info: DNS-сервер запущен на %s с %d воркерами", addr, workers)

	// Канал для передачи запросов от слушателя воркерам.
	requestQueue := make(chan RequestData, requestQueueCapacity)

	// Запуск воркеров
	for i := 0; i < workers; i++ {
		go handleRequests(appCtx, dnsResolver, conn, requestQueue)
	}

	// Основной цикл прослушивания входящих запросов.
	buffer := make([]byte, maxMessageSize)
	for {
		n, clientAddr, readErr := conn.ReadFrom(buffer)
		if readErr != nil {
			select {
			case <-appCtx.Done():
				log.Println("Info: Завершение работы сервера.")
				return
			default:
				log.Printf("Error: Ошибка чтения UDP-пакета: %v", readErr)
			}
			continue
		}

		// Копируем данные, чтобы избежать состояний гонки.
		requestData := make([]byte, n)
		copy(requestData, buffer[:n])

		// Отправляем запрос в канал для обработки воркером.
		requestQueue <- RequestData{
			request:    requestData,
			clientAddr: clientAddr.(*net.UDPAddr),
		}
	}
}

// handleRequests - воркер, который обрабатывает запросы из очереди.
func handleRequests(ctx context.Context, dnsResolver *resolver.Resolver, conn net.PacketConn, requestQueue chan RequestData) {
	for data := range requestQueue {
		requestCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		
		msg := new(dns.Msg)
		err := msg.Unpack(data.request)
		if err != nil {
			log.Printf("Error: Ошибка разбора DNS-пакета от %s: %v", data.clientAddr.String(), err)
			cancel()
			continue
		}
		
		if len(msg.Question) == 0 {
			log.Printf("Warning: Пустой DNS-запрос от %s", data.clientAddr.String())
			cancel()
			continue
		}

		qname := msg.Question[0].Name
		qtype := dns.Type(msg.Question[0].Qtype).String()

		log.Printf("Debug: Запрос от %s: %s %s", data.clientAddr.String(), qname, qtype)
		
		rrs, resolveErr := dnsResolver.ResolveContext(requestCtx, qname, qtype)

		responseMsg := new(dns.Msg)
		responseMsg.SetReply(msg)
		responseMsg.Authoritative = true
		
		if resolveErr != nil {
			responseMsg.Rcode = dns.RcodeServerFailure
			if resolveErr == resolver.NXDOMAIN {
				responseMsg.Rcode = dns.RcodeNameError
			}
		} else {
			responseMsg.Rcode = dns.RcodeSuccess
			for _, rr := range rrs {
				// Конвертируем нашу структуру RR обратно в miekg/dns.RR.
				// NOTE: Эта часть требует более сложной логики для разных типов записей.
				// Простой пример для A-записей.
				dnsRR, err := dns.NewRR(fmt.Sprintf("%s %d IN %s %s", rr.Name, rr.TTL, rr.Type, rr.Value))
				if err == nil {
					responseMsg.Answer = append(responseMsg.Answer, dnsRR)
				} else {
					log.Printf("Error: Failed to create DNS RR: %v", err)
				}
			}
		}
		
		packedResponse, packErr := responseMsg.Pack()
		if packErr != nil {
			log.Printf("Error: Ошибка упаковки DNS-ответа для %s: %v", data.clientAddr.String(), packErr)
		} else {
			_, writeErr := conn.WriteTo(packedResponse, data.clientAddr)
			if writeErr != nil {
				log.Printf("Error: Ошибка отправки ответа клиенту %s: %v", data.clientAddr.String(), writeErr)
			} else {
				log.Printf("Debug: Ответ успешно отправлен клиенту %s", data.clientAddr.String())
			}
		}
		
		cancel()
	}
}
