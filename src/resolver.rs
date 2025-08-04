// Run the server with: RUST_LOG=info cargo run
// Ensure your Cargo.toml file is updated with the dependencies from the previous step.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use std::time::{Duration, Instant};
use std::io;
use std::future::Future;
use std::pin::Pin;
use std::collections::HashSet; // Для обнаружения циклов

use log::{info, error, trace, warn};
use hickory_proto::op::{Message, ResponseCode, Query};
use hickory_proto::rr::{Record, RecordType, RData, Name};
use hickory_proto::serialize::binary::{BinEncoder, BinDecoder, BinEncodable, BinDecodable};
use anyhow::{Result, Context};
use rand::random;
use dashmap::DashMap;

/// Maximum UDP payload size for DNS
const MAX_UDP_PAYLOAD_SIZE: usize = 512;
/// The DNS port to listen on
const DNS_PORT: u16 = 5353;
/// Timeout for each DNS request
const DNS_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
/// Minimum remaining TTL to trigger prefetching
const PREFETCH_THRESHOLD: Duration = Duration::from_secs(60);
/// Max recursion depth to prevent infinite loops
const MAX_RECURSION_DEPTH: u8 = 10;

// Root DNS servers
const ROOT_SERVERS: &[Ipv4Addr] = &[
    Ipv4Addr::new(198, 41, 0, 4), // a.root-servers.net
    Ipv4Addr::new(199, 9, 14, 201), // b.root-servers.net
    Ipv4Addr::new(192, 33, 4, 12), // c.root-servers.net
    Ipv4Addr::new(199, 7, 91, 13), // d.root-servers.net
    Ipv4Addr::new(192, 203, 230, 10), // e.root-servers.net
    Ipv4Addr::new(192, 5, 5, 241), // f.root-servers.net
    Ipv4Addr::new(192, 112, 36, 4), // g.root-servers.net
    Ipv4Addr::new(198, 97, 190, 53), // h.root-servers.net
    Ipv4Addr::new(192, 36, 148, 17), // i.root-servers.net
    Ipv4Addr::new(192, 58, 128, 30), // j.root-servers.net
    Ipv4Addr::new(193, 0, 14, 129), // k.root-servers.net
    Ipv4Addr::new(199, 7, 83, 42), // l.root-servers.net
    Ipv4Addr::new(202, 12, 27, 33), // m.root-servers.net
];

// Cache entry with records and an expiration time
struct CacheEntry {
    records: Vec<Record>,
    expires_at: Instant,
}

// Cache for DNS responses using a thread-safe DashMap
type Cache = Arc<DashMap<(String, RecordType), CacheEntry>>;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    
    info!("Starting DNS resolver on 0.0.0.0:{}", DNS_PORT);

    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), DNS_PORT);
    let sock = Arc::new(UdpSocket::bind(bind_addr).await
        .with_context(|| format!("Failed to bind to {}", bind_addr))?);
    let cache: Cache = Arc::new(DashMap::new());

    info!("Listening on {}", bind_addr);

    let cache_clone_prefetch = Arc::clone(&cache);
    tokio::spawn(async move {
        loop {
            let now = Instant::now();
            cache_clone_prefetch.retain(|_, v| v.expires_at > now);

            for entry in cache_clone_prefetch.iter() {
                if let Some(time_left) = entry.expires_at.checked_duration_since(now) {
                    if time_left < PREFETCH_THRESHOLD {
                        let key = entry.key().clone();
                        let name_str = key.0;
                        let record_type = key.1;

                        let name_owned = name_str.parse().unwrap_or_else(|_| {
                            error!("Failed to parse name from cache for prefetch: {}", name_str);
                            return hickory_proto::rr::Name::from_ascii(".").unwrap();
                        });
                        
                        let name_for_log = name_str.clone();
                        info!("Prefetching expiring record for '{}' (type {})", name_for_log, record_type);
                        
                        let cache_clone_inner = Arc::clone(&cache_clone_prefetch);
                        tokio::spawn(async move {
                            if let Ok((answers, _)) = iterative_lookup_with_cache(name_owned, record_type, cache_clone_inner.clone()).await {
                                if !answers.is_empty() {
                                    let min_ttl = answers.iter().map(|r| r.ttl()).min().unwrap_or(0);
                                    let expires_at = Instant::now() + Duration::from_secs(min_ttl.into());
                                    cache_clone_inner.insert((name_str.clone(), record_type), CacheEntry { records: answers, expires_at });
                                    info!("Successfully prefetched and updated cache for '{}'", name_str);
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
        let (len, addr) = tokio::select! {
            result = sock.recv_from(&mut buf) => result.context("Failed to receive from socket"),
            _ = tokio::time::sleep(Duration::from_secs(60)) => {
                trace!("No activity, sleeping...");
                continue;
            }
        }?;
        
        let sock_clone = Arc::clone(&sock);
        let cache_clone = Arc::clone(&cache);
        let request_bytes_owned = buf[..len].to_vec();
        
        tokio::spawn(async move {
            match handle_query(&request_bytes_owned, &cache_clone).await {
                Ok(response_message) => {
                    let mut response_bytes = Vec::new();
                    let mut encoder = BinEncoder::new(&mut response_bytes);
                    
                    if let Ok(_) = response_message.emit(&mut encoder) {
                        if let Err(e) = sock_clone.send_to(&response_bytes, addr).await {
                            error!("Failed to send response to {}: {}", addr, e);
                        }
                    }
                },
                Err(e) => {
                    error!("Error handling query from {}: {}", addr, e);
                    if let Ok(request_message) = Message::from_vec(&request_bytes_owned) {
                        let failure_message = Message::error_msg(
                            request_message.header().id(),
                            request_message.op_code(),
                            ResponseCode::ServFail,
                        );
                        
                        let mut response_bytes = Vec::new();
                        let mut encoder = BinEncoder::new(&mut response_bytes);
                        
                        if let Ok(_) = failure_message.emit(&mut encoder) {
                            if let Err(e) = sock_clone.send_to(&response_bytes, addr).await {
                                error!("Failed to send error response to {}: {}", addr, e);
                            }
                        }
                    } else {
                        error!("Failed to parse original request for error response: {}", e);
                    }
                }
            }
        });
    }
}

/// Asynchronously handles a single DNS query.
async fn handle_query(request_bytes: &[u8], cache: &Cache) -> Result<Message> {
    let mut decoder = BinDecoder::new(request_bytes);
    let request_message = Message::read(&mut decoder)
        .context("Failed to decode DNS request message")?;

    let questions = request_message.queries();
    if questions.is_empty() {
        warn!("Received a DNS request with no questions.");
        let mut response_message = Message::response(request_message.header().id(), request_message.op_code());
        response_message.set_recursion_available(true);
        return Ok(response_message);
    }
    
    let query = questions[0].clone();
    
    info!("Received a query for '{}' (type {})", query.name(), query.query_type());

    let cache_key = (query.name().to_string(), query.query_type());
    if let Some(entry) = cache.get(&cache_key) {
        if entry.expires_at > Instant::now() {
            info!("Cache hit for '{}'", query.name());
            let mut response_message = Message::response(request_message.header().id(), request_message.op_code());
            response_message.set_recursion_available(true);
            response_message.add_query(query);
            for record in entry.records.iter() {
                response_message.add_answer(record.clone());
            }
            return Ok(response_message);
        } else {
            cache.remove(&cache_key);
            info!("Cache entry for '{}' expired", query.name());
        }
    }
    
    let (answers, authorities) = iterative_lookup_with_cache(query.name().clone(), query.query_type(), Arc::clone(&cache)).await
        .context("Iterative lookup failed")?;

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
    
    info!("Successfully resolved '{}' with {} answers", query.name(), response_message.answers().len());
    
    Ok(response_message)
}

/// Performs a manual iterative DNS lookup starting from root servers.
fn iterative_lookup_with_cache(
    name: Name,
    record_type: RecordType,
    cache: Cache,
) -> Pin<Box<dyn Future<Output = Result<(Vec<Record>, Vec<Record>)>> + Send + 'static>> {
    Box::pin(async move {
        let mut current_servers: Vec<IpAddr> = ROOT_SERVERS.iter().map(|&ip| IpAddr::V4(ip)).collect();
        let mut lookup_name = name.clone();
        let mut visited_servers = HashSet::new();
        let mut depth = 0;

        loop {
            if depth > MAX_RECURSION_DEPTH {
                error!("Max recursion depth reached for '{}'", lookup_name);
                return Err(io::Error::new(io::ErrorKind::Other, "Max recursion depth reached").into());
            }

            // Добавляем текущие серверы в набор посещенных, чтобы избежать циклов
            for server in &current_servers {
                if !visited_servers.insert(*server) {
                    error!("Detected DNS server loop for '{}'", lookup_name);
                    return Err(io::Error::new(io::ErrorKind::Other, "Detected DNS server loop").into());
                }
            }

            let mut request = Message::query();
            let mut header = request.header().clone();
            header.set_id(random());
            header.set_recursion_desired(false);
            request.set_header(header);
            
            let query = Query::query(lookup_name.clone(), record_type);
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
            while !futures.is_empty() {
                let response_result = tokio::select! {
                    res = futures.remove(0) => res,
                    _ = tokio::time::sleep(DNS_REQUEST_TIMEOUT) => {
                        warn!("Timeout waiting for response.");
                        continue;
                    },
                };
                
                if let Ok(bytes) = response_result {
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
                let authorities = response.name_servers().to_vec();
                if let Some(min_ttl) = answers.iter().map(|r| r.ttl()).min() {
                    let expires_at = Instant::now() + Duration::from_secs(min_ttl.into());
                    cache.insert((lookup_name.to_string(), record_type), CacheEntry { records: answers.clone(), expires_at });
                }
                
                return Ok((answers, authorities));
            }

            if let Some(rec) = response.answers().iter().find(|rec| rec.record_type() == RecordType::CNAME) {
                if let Some(RData::CNAME(cname_name_record)) = rec.data() {
                    info!("Received CNAME for '{}', continuing with '{}'", lookup_name, cname_name_record.0);
                    lookup_name = cname_name_record.0.clone();
                    depth += 1;
                    continue;
                }
            }
    
            if !response.name_servers().is_empty() {
                let mut new_servers = Vec::new();
                let mut ns_names = Vec::new();
                
                for record in response.name_servers() {
                    if let Some(RData::NS(ns_name_record)) = record.data() {
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
                    info!("Glue records not found, performing new lookups for NS servers.");
                    for ns_name in &ns_names {
                        match iterative_lookup_with_cache(ns_name.clone(), RecordType::A, Arc::clone(&cache)).await {
                            Ok((answers, _)) => {
                                for answer in answers {
                                    if let Some(ip) = extract_ip_from_rdata(answer.data()) {
                                        new_servers.push(ip);
                                    }
                                }
                            },
                            Err(e) => error!("Failed to resolve NS server {}: {}", ns_name, e),
                        }
                    }
                }
                
                if new_servers.is_empty() {
                    warn!("Could not find IP addresses for new nameservers, stopping recursion.");
                    return Ok((vec![], response.name_servers().to_vec()));
                }
    
                current_servers = new_servers;
                info!("Following referral to new servers: {:?}", current_servers);
                depth += 1;
            } else {
                warn!("No answers or referrals for '{}'", lookup_name);
                return Ok((vec![], response.name_servers().to_vec()));
            }
        }
    })
}

/// Sends a UDP DNS query and waits for a response with a timeout.
async fn send_udp_query(request_bytes: &[u8], server_addr: SocketAddr) -> Result<Vec<u8>, anyhow::Error> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    tokio::time::timeout(DNS_REQUEST_TIMEOUT, socket.send_to(request_bytes, server_addr)).await??;

    let mut buf = vec![0; MAX_UDP_PAYLOAD_SIZE];
    let (len, _) = tokio::time::timeout(DNS_REQUEST_TIMEOUT, socket.recv_from(&mut buf)).await??;
    
    Ok(buf[..len].to_vec())
}

/// Helper function to extract an IpAddr from RData
fn extract_ip_from_rdata(rdata: &RData) -> Option<IpAddr> {
    match rdata {
        RData::A(ipv4_rdata) => Some(IpAddr::V4(ipv4_rdata.0)),
        RData::AAAA(ipv6_rdata) => Some(IpAddr::V6(ipv6_rdata.0)),
        _ => None,
    }
}
