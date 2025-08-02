// main.rs
// ASTRACAT DNS Resolver - V8
// This version introduces a robust monitoring and recovery mechanism using a CancellationToken
// for graceful task shutdown. This is a more idiomatic and safe approach in Rust/Tokio
// than trying to abort tasks, which can lead to ownership issues.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use std::time::{Duration, Instant};
use std::io;
use std::pin::Pin;
use std::future::Future;

use hickory_proto::op::{Message, ResponseCode, Query};
use hickory_proto::rr::{Record, RecordType, RData};
use hickory_proto::serialize::binary::{BinEncoder, BinDecoder, BinEncodable, BinDecodable};
use anyhow::{Result, Context};
use rand::random;
use dashmap::DashMap;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// The maximum UDP payload size for DNS messages.
const MAX_UDP_PAYLOAD_SIZE: usize = 512;
/// The port for the DNS server to listen on.
const DNS_PORT: u16 = 5353;
/// The timeout for a DNS query to an external server.
const DNS_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
/// The TTL threshold for triggering a prefetch (cache refresh).
/// If a record's remaining TTL drops below this value, a new lookup is initiated.
const PREFETCH_THRESHOLD: Duration = Duration::from_secs(60);
/// The duration after which the server's main loop will restart.
const RESTART_INTERVAL: Duration = Duration::from_secs(600); // 10 minutes
/// The maximum time to wait for a heartbeat from the server's main loop.
/// If this time is exceeded, the server is considered non-responsive.
const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(30); // 30 seconds

/// The list of root DNS servers, including both IPv4 and IPv6 addresses.
const ROOT_SERVERS: &[IpAddr] = &[
    IpAddr::V4(Ipv4Addr::new(198, 41, 0, 4)),       // a.root-servers.net (IPv4)
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x503, 0xba3e, 0, 0, 0, 0, 0x2)), // a.root-servers.net (IPv6)
    IpAddr::V4(Ipv4Addr::new(199, 9, 14, 201)),      // b.root-servers.net (IPv4)
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x500, 0x200, 0, 0, 0, 0, 0xb)), // b.root-servers.net (IPv6)
    IpAddr::V4(Ipv4Addr::new(192, 33, 4, 12)),       // c.root-servers.net (IPv4)
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x500, 0x2e, 0, 0, 0, 0, 0x2)), // c.root-servers.net (IPv6)
    IpAddr::V4(Ipv4Addr::new(199, 7, 91, 13)),       // d.root-servers.net (IPv4)
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x500, 0x2d, 0, 0, 0, 0, 0xd)), // d.root-servers.net (IPv6)
    IpAddr::V4(Ipv4Addr::new(192, 203, 230, 10)),    // e.root-servers.net (IPv4)
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x500, 0xa8, 0, 0, 0, 0, 0x2)), // e.root-servers.net (IPv6)
    IpAddr::V4(Ipv4Addr::new(192, 5, 5, 241)),       // f.root-servers.net (IPv4)
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x500, 0x2f, 0, 0, 0, 0, 0xf)), // f.root-servers.net (IPv6)
    IpAddr::V4(Ipv4Addr::new(192, 112, 36, 4)),      // g.root-servers.net (IPv4)
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x500, 0x12, 0, 0, 0, 0, 0xd0d)), // g.root-servers.net (IPv6)
    IpAddr::V4(Ipv4Addr::new(198, 97, 190, 53)),     // h.root-servers.net (IPv4)
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x500, 0x1, 0, 0, 0, 0, 0x53)), // h.root-servers.net (IPv6)
    IpAddr::V4(Ipv4Addr::new(192, 36, 148, 17)),     // i.root-servers.net (IPv4)
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x7fe, 0, 0, 0, 0, 0, 0x33)), // i.root-servers.net (IPv6)
    IpAddr::V4(Ipv4Addr::new(192, 58, 128, 30)),     // j.root-servers.net (IPv4)
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x503, 0xc27, 0, 0, 0, 0, 0x2)), // j.root-servers.net (IPv6)
    IpAddr::V4(Ipv4Addr::new(193, 0, 14, 129)),      // k.root-servers.net (IPv4)
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x7fd, 0, 0, 0, 0, 0, 0x1)), // k.root-servers.net (IPv6)
    IpAddr::V4(Ipv4Addr::new(199, 7, 83, 42)),       // l.root-servers.net (IPv4)
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x500, 0x9f, 0, 0, 0, 0, 0x42)), // l.root-servers.net (IPv6)
    IpAddr::V4(Ipv4Addr::new(202, 12, 27, 33)),      // m.root-servers.net (IPv4)
    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdc3, 0, 0, 0, 0, 0, 0x35)), // m.root-servers.net (IPv6)
];

/// A cache entry containing the DNS records and their expiration time.
struct CacheEntry {
    records: Vec<Record>,
    expires_at: Instant,
}

/// The main cache, implemented as a thread-safe `DashMap` for concurrent access.
type Cache = Arc<DashMap<(String, RecordType), CacheEntry>>;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    // This loop acts as a supervisor for the server logic.
    loop {
        println!("Starting ASTRACAT DNS resolver on 0.0.0.0:{} (dual-stack)", DNS_PORT);
        
        // CancellationToken for graceful shutdown
        let shutdown_token = CancellationToken::new();
        let shutdown_token_server = shutdown_token.clone();
        let shutdown_token_monitor = shutdown_token.clone();
        let (tx, rx) = mpsc::channel(1); // Channel for heartbeats

        // Start the server's main logic as a separate task
        let server_task = tokio::spawn(run_server(tx, shutdown_token_server));
        
        // Start the heartbeat monitor as a separate task
        let monitor_task = tokio::spawn(heartbeat_monitor(rx, shutdown_token_monitor));

        // Use `tokio::select!` to monitor for a crash or a scheduled restart signal
        let result = tokio::select! {
            server_result = server_task => {
                // The server task exited, signal a shutdown to the monitor
                shutdown_token.cancel();
                server_result.context("Server task panicked")?
            },
            monitor_result = monitor_task => {
                // The monitor task exited, signal a shutdown to the server
                shutdown_token.cancel();
                monitor_result.context("Monitor task panicked")?
            },
            _ = tokio::time::sleep(RESTART_INTERVAL) => {
                // Scheduled restart timer expired, signal a shutdown to all
                shutdown_token.cancel();
                println!("Scheduled restart initiated. Shutting down and restarting the server...");
                Ok(())
            }
        };

        if let Err(e) = result {
            eprintln!("ASTRACAT DNS resolver encountered a fatal error: {}. Restarting...", e);
        }
        
        println!("Restarting server in 1 second...");
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// The main server logic, now extracted into its own function.
/// It takes a Sender to send heartbeats and a CancellationToken for graceful shutdown.
async fn run_server(heartbeat_tx: mpsc::Sender<()>, shutdown_token: CancellationToken) -> Result<()> {
    let bind_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), DNS_PORT);
    let sock = Arc::new(UdpSocket::bind(bind_addr).await.context("Failed to bind UDP socket")?);
    let cache: Cache = Arc::new(DashMap::new());

    println!("Listening on {}", bind_addr);

    let cache_clone_prefetch = Arc::clone(&cache);
    let shutdown_token_prefetch = shutdown_token.clone(); // Clone the token for the prefetch task

    tokio::spawn(async move {
        loop {
            // Check for shutdown signal
            if shutdown_token_prefetch.is_cancelled() {
                println!("Prefetch task received shutdown signal. Exiting gracefully.");
                return;
            }

            let now = Instant::now();
            cache_clone_prefetch.retain(|_, v| v.expires_at > now);

            for entry in cache_clone_prefetch.iter() {
                if let Some(time_left) = entry.expires_at.checked_duration_since(now) {
                    if time_left < PREFETCH_THRESHOLD {
                        let key = entry.key().clone();
                        let name_str = key.0.clone();
                        let record_type = key.1;
                        let name_owned = name_str.parse().unwrap_or_else(|_| {
                            hickory_proto::rr::Name::from_ascii(".").unwrap()
                        });
                        
                        let cache_clone_inner = Arc::clone(&cache_clone_prefetch);
                        tokio::spawn(async move {
                            if let Ok((answers, _)) = recursive_lookup_with_cache(name_owned, record_type, cache_clone_inner.clone(), 0).await {
                                if let Some(min_ttl) = answers.iter().map(|r| r.ttl()).min() {
                                    let expires_at = Instant::now() + Duration::from_secs(min_ttl.into());
                                    cache_clone_inner.insert((name_str.clone(), record_type), CacheEntry { records: answers.clone(), expires_at });
                                }
                            }
                        });
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    });

    let mut buf = vec![0; MAX_UDP_PAYLOAD_SIZE];
    loop {
        tokio::select! {
            _ = shutdown_token.cancelled() => {
                println!("Server task received shutdown signal. Exiting gracefully.");
                return Ok(());
            },
            recv_result = sock.recv_from(&mut buf) => {
                let (len, addr) = match recv_result {
                    Ok(result) => result,
                    Err(e) => {
                        eprintln!("Error receiving from socket: {}. Continuing...", e);
                        continue;
                    }
                };

                let _ = heartbeat_tx.try_send(());

                let sock_clone = Arc::clone(&sock);
                let cache_clone = Arc::clone(&cache);
                let request_bytes_owned = buf[..len].to_vec();
        
                tokio::spawn(async move {
                    match handle_query(&request_bytes_owned, &cache_clone).await {
                        Ok(response_message) => {
                            let mut response_bytes = Vec::new();
                            let mut encoder = BinEncoder::new(&mut response_bytes);
                            if response_message.emit(&mut encoder).is_ok() {
                                if let Err(e) = sock_clone.send_to(&response_bytes, addr).await {
                                    eprintln!("Failed to send response to {}: {}", addr, e);
                                }
                            }
                        },
                        Err(e) => {
                            eprintln!("Error handling query from {}: {}", addr, e);
                            if let Ok(request_message) = Message::from_vec(&request_bytes_owned) {
                                let failure_message = Message::error_msg(
                                    request_message.header().id(),
                                    request_message.op_code(),
                                    ResponseCode::ServFail,
                                );
        
                                let mut response_bytes = Vec::new();
                                let mut encoder = BinEncoder::new(&mut response_bytes);
                                if failure_message.emit(&mut encoder).is_ok() {
                                    if let Err(e) = sock_clone.send_to(&response_bytes, addr).await {
                                        eprintln!("Failed to send error response to {}: {}", addr, e);
                                    }
                                }
                            }
                        }
                    }
                });
            }
        }
    }
}

/// A separate task that monitors for heartbeats from the server.
/// If no heartbeat is received within the timeout, it returns an error.
async fn heartbeat_monitor(mut rx: mpsc::Receiver<()>, shutdown_token: CancellationToken) -> Result<()> {
    loop {
        tokio::select! {
            _ = shutdown_token.cancelled() => {
                println!("Heartbeat monitor received shutdown signal. Exiting gracefully.");
                return Ok(());
            },
            _ = rx.recv() => {
                // Heartbeat received, continue the loop and reset the timer
            },
            _ = tokio::time::sleep(HEARTBEAT_TIMEOUT) => {
                // Timeout without a heartbeat, return an error
                return Err(anyhow::anyhow!("Heartbeat timeout: The server is non-responsive."));
            }
        }
    }
}

/// Handles a single incoming DNS query.
async fn handle_query(request_bytes: &[u8], cache: &Cache) -> Result<Message> {
    let mut decoder = BinDecoder::new(request_bytes);
    let request_message = Message::read(&mut decoder).context("Failed to decode DNS request message")?;

    let questions = request_message.queries();
    if questions.is_empty() {
        let mut response_message = Message::response(request_message.header().id(), request_message.op_code());
        response_message.set_recursion_available(true);
        return Ok(response_message);
    }

    let query = questions[0].clone();

    let cache_key = (query.name().to_string(), query.query_type());
    if let Some(entry) = cache.get(&cache_key) {
        if entry.expires_at > Instant::now() {
            let mut response_message = Message::response(request_message.header().id(), request_message.op_code());
            response_message.set_recursion_available(true);
            response_message.add_query(query);
            for record in entry.records.iter() {
                response_message.add_answer(record.clone());
            }
            return Ok(response_message);
        } else {
            cache.remove(&cache_key);
        }
    }

    let (answers, authorities) = recursive_lookup_with_cache(query.name().clone(), query.query_type(), Arc::clone(&cache), 0)
        .await.context("Recursive lookup failed")?;

    let mut response_message = Message::response(request_message.header().id(), request_message.op_code());
    response_message.set_recursion_available(true);
    for q in request_message.queries() {
        response_message.add_query(q.clone());
    }
    for record in answers {
        response_message.add_answer(record);
    }
    for record in authorities {
        response_message.add_name_server(record);
    }

    Ok(response_message)
}

/// Recursively performs a DNS lookup, starting from the root servers.
fn recursive_lookup_with_cache(
    name: hickory_proto::rr::Name,
    record_type: RecordType,
    cache: Cache,
    depth: u8,
) -> Pin<Box<dyn Future<Output = Result<(Vec<Record>, Vec<Record>)>> + Send + 'static>> {
    Box::pin(async move {
        if depth > 10 {
            return Ok((vec![], vec![]));
        }

        let mut current_servers: Vec<IpAddr> = ROOT_SERVERS.to_vec();

        loop {
            let mut request = Message::query();
            let mut header = request.header().clone();
            header.set_id(random());
            header.set_recursion_desired(false);
            request.set_header(header);

            let query = Query::query(name.clone(), record_type);
            request.add_query(query);

            let mut request_bytes = Vec::new();
            let mut encoder = BinEncoder::new(&mut request_bytes);
            request.emit(&mut encoder)?;

            let mut futures = Vec::new();
            for server_ip in &current_servers {
                let server_addr = SocketAddr::new(*server_ip, 53);
                futures.push(send_udp_query(&request_bytes, server_addr));
            }

            let mut successful_response = None;
            for fut in futures {
                if let Ok(bytes) = fut.await {
                    let mut decoder = BinDecoder::new(&bytes);
                    if let Ok(message) = Message::read(&mut decoder) {
                        successful_response = Some(message);
                        break;
                    }
                }
            }

            let response = match successful_response {
                Some(res) => res,
                None => return Err(io::Error::new(io::ErrorKind::TimedOut, "Failed to get a response from any nameserver").into()),
            };

            if !response.answers().is_empty() {
                let answers = response.answers().to_vec();
                if let Some(min_ttl) = answers.iter().map(|r| r.ttl()).min() {
                    let expires_at = Instant::now() + Duration::from_secs(min_ttl.into());
                    cache.insert((name.to_string(), record_type), CacheEntry { records: answers.clone(), expires_at });
                }
                return Ok((answers, response.name_servers().to_vec()));
            }

            if let Some(rec) = response.answers().iter().find(|rec| rec.record_type() == RecordType::CNAME) {
                if let RData::CNAME(cname_name_record) = rec.data() {
                    return recursive_lookup_with_cache(cname_name_record.0.clone(), record_type, cache.clone(), depth + 1).await;
                }
            }

            if !response.name_servers().is_empty() {
                let mut new_servers = Vec::new();
                let mut ns_names = Vec::new();

                for record in response.name_servers() {
                    if let RData::NS(ns_name_record) = record.data() {
                        ns_names.push(ns_name_record.0.clone());
                        for additional_record in response.additionals() {
                            if additional_record.name() == &ns_name_record.0 {
                                if let Some(ip) = extract_ip_from_rdata(additional_record.data()) {
                                    new_servers.push(ip);
                                }
                            }
                        }
                    }
                }

                if new_servers.is_empty() {
                    for ns_name in &ns_names {
                        if let Ok((answers, _)) = recursive_lookup_with_cache(ns_name.clone(), RecordType::A, cache.clone(), depth + 1).await {
                            for answer in answers {
                                if let Some(ip) = extract_ip_from_rdata(answer.data()) {
                                    new_servers.push(ip);
                                }
                            }
                        }
                        if let Ok((answers, _)) = recursive_lookup_with_cache(ns_name.clone(), RecordType::AAAA, cache.clone(), depth + 1).await {
                            for answer in answers {
                                if let Some(ip) = extract_ip_from_rdata(answer.data()) {
                                    new_servers.push(ip);
                                }
                            }
                        }
                    }
                }

                if new_servers.is_empty() {
                    return Ok((vec![], response.name_servers().to_vec()));
                }

                current_servers = new_servers;
            } else {
                return Ok((vec![], response.name_servers().to_vec()));
            }
        }
    })
}

/// Sends a UDP DNS query and waits for a response with a timeout.
async fn send_udp_query(request_bytes: &[u8], server_addr: SocketAddr) -> Result<Vec<u8>, anyhow::Error> {
    let bind_addr = match server_addr.ip() {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    
    let socket = UdpSocket::bind(bind_addr).await?;
    tokio::time::timeout(DNS_REQUEST_TIMEOUT, socket.send_to(request_bytes, &server_addr)).await??;

    let mut buf = vec![0; MAX_UDP_PAYLOAD_SIZE];
    let (len, _) = tokio::time::timeout(DNS_REQUEST_TIMEOUT, socket.recv_from(&mut buf)).await??;

    Ok(buf[..len].to_vec())
}

/// Helper function to extract an IP address from an `RData` enum.
fn extract_ip_from_rdata(rdata: &RData) -> Option<IpAddr> {
    match rdata {
        RData::A(ipv4_rdata) => Some(IpAddr::V4(ipv4_rdata.0)),
        RData::AAAA(ipv6_rdata) => Some(IpAddr::V6(ipv6_rdata.0)),
        _ => None,
    }
}
