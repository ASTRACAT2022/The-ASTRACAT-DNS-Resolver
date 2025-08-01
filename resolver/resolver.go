package resolver

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Prefetching constants
const (
	// prefetchCheckInterval determines how often we check the cache for entries to prefetch.
	prefetchCheckInterval = 10 * time.Second
	// prefetchThresholdRatio determines the percentage of the original TTL that must remain to trigger a prefetch.
	prefetchThresholdRatio = 0.2
	// prefetchQueryTimeout - timeout for prefetch queries.
	prefetchQueryTimeout = 500 * time.Millisecond 
	
	// rootHintsUpdateInterval - how often to update root servers (can be increased for stable systems)
	rootHintsUpdateInterval = 24 * time.Hour
	
	// adaptiveTimeoutGracePeriod - period during which a server is not considered slow
	adaptiveTimeoutGracePeriod = 20 * time.Millisecond
	// adaptiveTimeoutFactor - factor by which to increase the timeout for slow servers
	adaptiveTimeoutFactor = 1.5
	
	// L2CacheCleanupInterval - how often to clean up the L2 cache (e.g., once a week)
	L2CacheCleanupInterval = 7 * 24 * time.Hour
)

// Resolver struct holds the state for the DNS resolver.
type Resolver struct {
	cache       *Cache
	rootServers []string
	serverStats *ServerStats
	// prefetchWork is a channel for prefetching tasks.
	prefetchWork chan string
	// prefetchWG is a WaitGroup for prefetch tasks.
	prefetchWG sync.WaitGroup
	ctx        context.Context
}

// NewResolver creates a new instance of Resolver.
func NewResolver(ctx context.Context) *Resolver {
	// Load root servers once at startup.
	rootServers := InitialRootServers
	if len(rootServers) == 0 {
		log.Println("Error: Initial root servers list is empty.")
		return nil
	}

	r := &Resolver{
		cache:       NewCache(L2CacheCleanupInterval),
		rootServers: rootServers,
		serverStats: NewServerStats(),
		prefetchWork: make(chan string, 1000),
		ctx:         ctx,
	}
	
	// Start prefetching and root hint update loops.
	go r.prefetchLoop()
	go r.rootHintsUpdater()

	return r
}

// Resolve handles a DNS query recursively.
func (r *Resolver) Resolve(ctx context.Context, question dns.Question) (*dns.Msg, error) {
	// Use a dedicated context for the resolution process.
	resCtx, resCancel := context.WithTimeout(ctx, 5*time.Second) // A reasonable overall timeout
	defer resCancel()

	msg := new(dns.Msg)
	msg.SetQuestion(question.Name, question.Qtype)
	msg.RecursionDesired = true

	// Check cache first.
	cacheKey := fmt.Sprintf("%s/%d", question.Name, question.Qtype)
	if cachedResp, found := r.cache.Get(cacheKey); found {
		resp := new(dns.Msg)
		if err := resp.Unpack(cachedResp); err == nil {
			return resp, nil
		}
	}
	
	// Start with a list of root servers.
	servers := r.rootServers
	for {
		if resCtx.Err() != nil {
			return nil, resCtx.Err()
		}

		// Create a channel to receive responses from parallel queries.
		responseCh := make(chan *dns.Msg, len(servers))
		var wg sync.WaitGroup
		
		// Query multiple servers in parallel.
		for _, server := range servers {
			wg.Add(1)
			go func(server string) {
				defer wg.Done()
				client := new(dns.Client)
				client.Net = "udp"
				client.Timeout = r.serverStats.GetTimeout(server)
				
				resp, rtt, err := client.ExchangeWithContext(resCtx, msg, server)
				if err == nil {
					responseCh <- resp
					r.serverStats.Update(server, rtt)
				}
			}(server)
		}

		wg.Wait()
		close(responseCh)

		if len(responseCh) == 0 {
			// All queries failed.
			return nil, errors.New("all upstream servers failed to respond")
		}

		// Process the first successful response.
		resp := <-responseCh
		
		if resp.Rcode == dns.RcodeSuccess {
			// Check for CNAME chain and resolve it.
			if len(resp.Answer) > 0 && resp.Answer[0].Header().Rrtype == dns.TypeCNAME {
				targetName := resp.Answer[0].(*dns.CNAME).Target
				// Recursively resolve the CNAME target.
				cnameResp, err := r.Resolve(resCtx, dns.Question{Name: targetName, Qtype: question.Qtype, Class: dns.ClassINET})
				if err == nil {
					// Append the CNAME answer to the final response.
					resp.Answer = append(resp.Answer, cnameResp.Answer...)
				}
			}

			// Cache the final response before returning.
			if len(resp.Answer) > 0 {
				packed, err := resp.Pack()
				if err == nil {
					// Use a reasonable TTL from the response.
					ttl := resp.Answer[0].Header().Ttl
					r.cache.Set(cacheKey, packed, ttl, question.Name, dns.Type(question.Qtype).String())
				}
			}
			return resp, nil
		}

		// Handle referral to new nameservers.
		if len(resp.Ns) > 0 {
			var newServers []string
			for _, ns := range resp.Ns {
				if a, ok := ns.(*dns.A); ok {
					newServers = append(newServers, a.A.String()+":53")
				}
				if aaaa, ok := ns.(*dns.AAAA); ok {
					newServers = append(newServers, aaaa.AAAA.String()+":53")
				}
			}
			if len(newServers) > 0 {
				servers = newServers
				continue
			}
		}

		// If we've exhausted all options, return the response as is.
		return resp, nil
	}
}

// prefetchLoop listens for prefetch tasks and executes them.
func (r *Resolver) prefetchLoop() {
	for {
		select {
		case task := <-r.prefetchWork:
			r.prefetch(task)
		case <-r.ctx.Done():
			return
		}
	}
}

// prefetch performs a DNS query for a nearing-expiration entry.
func (r *Resolver) prefetch(query string) {
	parts := strings.Split(query, "/")
	if len(parts) != 2 {
		log.Printf("Error: Malformed prefetch query: %s", query)
		return
	}
	qname := parts[0]
	qtypeStr := parts[1]
	
	qtype, ok := dns.StringToType[qtypeStr]
	if !ok {
		log.Printf("Error: Unknown query type for prefetch: %s", qtypeStr)
		return
	}

	msg := new(dns.Msg)
	msg.SetQuestion(qname, qtype)
	msg.RecursionDesired = true

	// Use a short, non-blocking timeout for prefetch queries.
	ctx, cancel := context.WithTimeout(context.Background(), prefetchQueryTimeout)
	defer cancel()

	_, err := r.Resolve(ctx, dns.Question{Name: qname, Qtype: qtype, Class: dns.ClassINET})
	if err != nil {
		log.Printf("Warning: Prefetch for %s failed: %v", qname, err)
	} else {
		log.Printf("Debug: Prefetch for %s successful.", qname)
	}
}


// rootHintsUpdater periodically updates the list of root servers.
func (r *Resolver) rootHintsUpdater() {
	ticker := time.NewTicker(rootHintsUpdateInterval)
	defer ticker.Stop()

	for range ticker.C {
		// Logic to update root server hints.
		// For now, we'll just log that it's happening.
		log.Println("Updating root server hints...")
	}
}

// ServerStats - structure for storing server statistics.
type ServerStats struct {
	mu    sync.RWMutex
	data  map[string]time.Duration
	count map[string]int
}

// NewServerStats creates a new structure for server statistics.
func NewServerStats() *ServerStats {
	return &ServerStats{
		data:  make(map[string]time.Duration),
		count: make(map[string]int),
	}
}

// Update updates the statistics for a server.
func (s *ServerStats) Update(server string, rtt time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[server] += rtt
	s.count[server]++
}

// GetTimeout returns the timeout for a server, adapting to its performance.
func (s *ServerStats) GetTimeout(server string) time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.count[server] < 5 {
		return 5 * time.Second
	}

	avgRTT := s.data[server] / time.Duration(s.count[server])

	if avgRTT > adaptiveTimeoutGracePeriod {
		return time.Duration(float64(avgRTT) * adaptiveTimeoutFactor)
	}

	return 5 * time.Second
}
