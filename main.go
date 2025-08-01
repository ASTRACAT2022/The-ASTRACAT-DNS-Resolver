package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"sync"

	"github.com/miekg/dns"
	"super-tuned-dns-root-data/resolver"
)

const (
	port = 5353
)

// RequestData holds the data needed to process a DNS request.
type RequestData struct {
	request    []byte
	clientAddr *net.UDPAddr
}

func main() {
	// --- Logging setup ---
	log.SetOutput(os.Stdout)
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.SetPrefix("[ASTRACAT_DNS-RESOLVER] ")

	// Create a context for the entire application.
	appCtx, appCancel := context.WithCancel(context.Background())
	defer appCancel()

	// Initialize our resolver, passing the context.
	dnsResolver := resolver.NewResolver(appCtx)
	if dnsResolver == nil {
		log.Fatal("Failed to initialize DNS resolver.")
	}

	// Create a UDP server with SO_REUSEPORT option for performance.
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var err error
			if runtime.GOOS == "linux" {
				c.Control(func(fd uintptr) {
					const SO_REUSEPORT = 15
					err = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, SO_REUSEPORT, 1)
					if err != nil {
						log.Printf("Error: Failed to set SO_REUSEPORT: %v", err)
					}
				})
			}
			return err
		},
	}

	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatalf("Error: Failed to resolve UDP address: %v", err)
	}

	conn, err := lc.ListenPacket(appCtx, "udp", addr.String())
	if err != nil {
		log.Fatalf("Error: Failed to listen on UDP port: %v", err)
	}
	defer conn.Close()

	log.Printf("DNS server started on %s", conn.LocalAddr().String())

	// Use a buffered channel to handle incoming requests from the main loop.
	requestQueue := make(chan RequestData, 1024)

	// A WaitGroup to ensure all goroutines finish on shutdown.
	var wg sync.WaitGroup

	// Start worker goroutines to process requests.
	numWorkers := runtime.NumCPU() * 2 // A good starting point
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go handleRequest(appCtx, &wg, dnsResolver, requestQueue, conn)
	}

	// A goroutine to listen for OS signals for graceful shutdown.
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Main loop to accept new requests.
	go func() {
		for {
			select {
			case <-appCtx.Done():
				return
			default:
				buffer := make([]byte, 512)
				conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				n, clientAddr, err := conn.ReadFromUDP(buffer)
				if err != nil {
					if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
						continue
					}
					log.Printf("Error: ReadFromUDP failed: %v", err)
					continue
				}

				requestData := RequestData{
					request:    buffer[:n],
					clientAddr: clientAddr,
				}
				
				// Push the request to the queue.
				select {
				case requestQueue <- requestData:
				default:
					log.Println("Warning: Request queue is full, dropping request.")
				}
			}
		}
	}()

	// Wait for a signal to shut down.
	<-sigChan
	log.Println("Shutting down gracefully...")

	// Cancel the context and wait for all goroutines to finish.
	appCancel()
	close(requestQueue)
	wg.Wait()

	log.Println("Shutdown complete.")
}

// handleRequest processes requests from the queue in a separate goroutine.
func handleRequest(ctx context.Context, wg *sync.WaitGroup, dnsResolver *resolver.Resolver, requestQueue <-chan RequestData, conn *net.UDPConn) {
	defer wg.Done()
	
	for {
		select {
		case <-ctx.Done():
			return
		case data, ok := <-requestQueue:
			if !ok { // Channel closed
				return
			}
			
			// Unpack the DNS message.
			msg := new(dns.Msg)
			if err := msg.Unpack(data.request); err != nil {
				log.Printf("Error: Failed to unpack DNS request from %s: %v", data.clientAddr.String(), err)
				errorResponse := buildErrorDNSResponse(data.request, dns.RcodeFormatError)
				if errorResponse != nil {
					conn.WriteToUDP(errorResponse, data.clientAddr)
				}
				continue
			}

			if len(msg.Question) == 0 {
				log.Printf("Warning: Empty question section from %s", data.clientAddr.String())
				continue
			}

			// Resolve the query.
			response, err := dnsResolver.Resolve(ctx, msg.Question[0])
			if err != nil {
				log.Printf("Error: Failed to resolve query from %s: %v", data.clientAddr.String(), err)
				rcode := dns.RcodeServerFailure
				if err == resolver.NXDOMAIN {
					rcode = dns.RcodeNameError
				}
				errorResponse := buildErrorDNSResponse(data.request, rcode)
				if errorResponse != nil {
					conn.WriteToUDP(errorResponse, data.clientAddr)
				}
				continue
			}
			
			// Set the response header and send the response.
			response.SetReply(msg)
			response.RecursionAvailable = true
			packedResponse, packErr := response.Pack()
			if packErr != nil {
				log.Printf("Error: Failed to pack response for %s: %v", data.clientAddr.String(), packErr)
				errorResponse := buildErrorDNSResponse(data.request, dns.RcodeServerFailure)
				if errorResponse != nil {
					conn.WriteToUDP(errorResponse, data.clientAddr)
				}
				continue
			}

			_, writeErr := conn.WriteToUDP(packedResponse, data.clientAddr)
			if writeErr != nil {
				log.Printf("Error: Failed to send response to %s: %v", data.clientAddr.String(), writeErr)
			}
		}
	}
}

// buildErrorDNSResponse creates a DNS error response based on the original request.
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
	
	errorMsg := new(dns.Msg)
	errorMsg.SetRcode(msg, rcode)
	packedResponse, packErr := errorMsg.Pack()
	if packErr != nil {
		return nil
	}
	return packedResponse
}
