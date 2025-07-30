package main

import (
	"fmt"
	"log"
	"net"

	"astracat-dns/resolver" // Это будет наш модуль резолвера
)

const (
	port = 53 // Стандартный порт DNS
)

func main() {
	// Инициализируем наш резолвер
	dnsResolver := resolver.NewResolver()

	// Создаем UDP-сервер
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatalf("Ошибка разрешения UDP-адреса: %v", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("Ошибка при прослушивании UDP: %v", err)
	}
	defer conn.Close()

	log.Printf("The ASTRACAT DNS Resolver запущен на :%d", port)

	// Основной цикл обработки запросов
	for {
		buf := make([]byte, 512) // Максимальный размер UDP DNS-пакета
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("Ошибка чтения из UDP: %v", err)
			continue
		}

		// Запускаем обработку запроса в горутине, чтобы не блокировать сервер
		go handleDNSRequest(conn, clientAddr, buf[:n], dnsResolver)
	}
}

func handleDNSRequest(conn *net.UDPConn, clientAddr *net.UDPAddr, request []byte, r *resolver.Resolver) {
	// Здесь будет логика обработки DNS-запроса
	// 1. Распарсить запрос
	// 2. Использовать резолвер для получения ответа
	// 3. Отправить ответ обратно клиенту

	// Пока заглушка: просто печатаем запрос
	log.Printf("Получен запрос от %s: %d байт", clientAddr.String(), len(request))

	// В будущем:
	// response, err := r.Resolve(request)
	// if err != nil {
	//    log.Printf("Ошибка резолвинга запроса от %s: %v", clientAddr.String(), err)
	//    // Отправить клиенту ошибку DNS
	//    return
	// }
	//
	// _, err = conn.WriteToUDP(response, clientAddr)
	// if err != nil {
	//    log.Printf("Ошибка отправки ответа клиенту %s: %v", clientAddr.String(), err)
	// }
}
