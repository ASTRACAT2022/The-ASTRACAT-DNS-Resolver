// Run the server with: RUST_LOG=info cargo run
// Ensure your Cargo.toml file includes required dependencies.
// The necessary dependencies are:
// [dependencies]
// log = "0.4"
// env_logger = "0.10"
// tokio = { version = "1", features = ["full"] }
// hickory-proto = "0.23"
// anyhow = "1.0"
// rand = "0.8"
// dashmap = "5"

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use std::time::{Duration, Instant};
use std::io;
use std::pin::Pin;
use std::future::Future;

use log::{info, error, trace, warn};
use hickory_proto::op::{Message, ResponseCode, Query};
use hickory_proto::rr::{Record, RecordType, RData};
use hickory_proto::serialize::binary::{BinEncoder, BinDecoder, BinEncodable, BinDecodable};
use anyhow::{Result, Context};
use rand::random;
use dashmap::DashMap;

/// The maximum UDP payload size for DNS messages.
const MAX_UDP_PAYLOAD_SIZE: usize = 512;
/// The port for the DNS server to listen on.
const DNS_PORT: u16 = 5353;
/// The timeout for a DNS query to an external server.
const DNS_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
/// The TTL threshold for triggering a prefetch (cache refresh).
/// If a record's remaining TTL drops below this value, a new lookup is initiated.
const PREFETCH_THRESHOLD: Duration = Duration::from_secs(60);

/// The list of IPv4 root DNS servers. These are the starting point for all
/// recursive lookups.
const ROOT_SERVERS: &[Ipv4Addr] = &[
    Ipv4Addr::new(198, 41, 0, 4),    // a.root-servers.net
    Ipv4Addr::new(199, 9, 14, 201),  // b.root-servers.net
    Ipv4Addr::new(192, 33, 4, 12),   // c.root-servers.net
    Ipv4Addr::new(199, 7, 91, 13),   // d.root-servers.net
    Ipv4Addr::new(192, 203, 230, 10), // e.root-servers.net
    Ipv4Addr::new(192, 5, 5, 241),   // f.root-servers.net
    Ipv4Addr::new(192, 112, 36, 4),  // g.root-servers.net
    Ipv4Addr::new(198, 97, 190, 53),  // h.root-servers.net
    Ipv4Addr::new(192, 36, 148, 17),  // i.root-servers.net
    Ipv4Addr::new(192, 58, 128, 30),  // j.root-servers.net
    Ipv4Addr::new(193, 0, 14, 129),  // k.root-servers.net
    Ipv4Addr::new(199, 7, 83, 42),   // l.root-servers.net
    Ipv4Addr::new(202, 12, 27, 33),  // m.root-servers.net
];

/// A cache entry containing the DNS records and their expiration time.
struct CacheEntry {
    records: Vec<Record>,
    expires_at: Instant,
}

/// The main cache, implemented as a thread-safe `DashMap` for concurrent access.
/// The key is a tuple of the domain name and record type.
type Cache = Arc<DashMap<(String, RecordType), CacheEntry>>;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize the logger for console output.
    env_logger::init();

    info!("Starting DNS resolver on 0.0.0.0:{}", DNS_PORT);

    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), DNS_PORT);
    // Bind the UDP socket and wrap it in an Arc for shared ownership.
    let sock = Arc::new(UdpSocket::bind(bind_addr).await.context("Failed to bind UDP socket")?);
    // Initialize the concurrent cache.
    let cache: Cache = Arc::new(DashMap::new());

    info!("Listening on {}", bind_addr);

    // Spawn a background task for cache cleanup and prefetching.
    let cache_clone_prefetch = Arc::clone(&cache);
    tokio::spawn(async move {
        loop {
            let now = Instant::now();
            // Retain only entries that have not yet expired.
            cache_clone_prefetch.retain(|_, v| v.expires_at > now);

            // Iterate over all cache entries to check for prefetching opportunities.
            for entry in cache_clone_prefetch.iter() {
                // If the remaining TTL is less than the prefetch threshold...
                if let Some(time_left) = entry.expires_at.checked_duration_since(now) {
                    if time_left < PREFETCH_THRESHOLD {
                        let key = entry.key().clone();
                        let name_str = key.0.clone();
                        let record_type = key.1;
                        let name_owned = name_str.parse().unwrap_or_else(|_| {
                            error!("Failed to parse name from cache for prefetch: {}", name_str);
                            hickory_proto::rr::Name::from_ascii(".").unwrap()
                        });
                        info!("Prefetching expiring record for '{}' (type {})", name_str, record_type);

                        // Spawn a new task to perform the prefetch lookup.
                        let cache_clone_inner = Arc::clone(&cache_clone_prefetch);
                        tokio::spawn(async move {
                            if let Ok((answers, _)) = recursive_lookup_with_cache(name_owned, record_type, cache_clone_inner.clone(), 0).await {
                                if !answers.is_empty() {
                                    // Get the minimum TTL from the new answers.
                                    let min_ttl = answers.iter().map(|r| r.ttl()).min().unwrap_or(0);
                                    // Calculate the new expiration time.
                                    let expires_at = Instant::now() + Duration::from_secs(min_ttl.into());
                                    // Update the cache with the new, fresh records.
                                    cache_clone_inner.insert((name_str.clone(), record_type), CacheEntry { records: answers, expires_at });
                                    info!("Successfully prefetched and updated cache for '{}'", name_str);
                                }
                            }
                        });
                    }
                }
            }
            // Sleep for a minute before the next cleanup/prefetch check.
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    });

    let mut buf = vec![0; MAX_UDP_PAYLOAD_SIZE];
    loop {
        // Use `tokio::select!` to listen for incoming packets or a timeout.
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

        // Spawn a new task for each incoming DNS query. This allows the server
        // to handle multiple requests concurrently without blocking.
        tokio::spawn(async move {
            match handle_query(&request_bytes_owned, &cache_clone).await {
                Ok(response_message) => {
                    let mut response_bytes = Vec::new();
                    let mut encoder = BinEncoder::new(&mut response_bytes);
                    if response_message.emit(&mut encoder).is_ok() {
                        if let Err(e) = sock_clone.send_to(&response_bytes, addr).await {
                            error!("Failed to send response to {}: {}", addr, e);
                        }
                    }
                },
                Err(e) => {
                    error!("Error handling query from {}: {}", addr, e);
                    // If an error occurs, send a `ServFail` response.
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
                                error!("Failed to send error response to {}: {}", addr, e);
                            }
                        }
                    }
                }
            }
        });
    }
}

/// Handles a single incoming DNS query.
async fn handle_query(request_bytes: &[u8], cache: &Cache) -> Result<Message> {
    let mut decoder = BinDecoder::new(request_bytes);
    let request_message = Message::read(&mut decoder).context("Failed to decode DNS request message")?;

    let questions = request_message.queries();
    if questions.is_empty() {
        warn!("Received DNS request with no questions.");
        let mut response_message = Message::response(request_message.header().id(), request_message.op_code());
        response_message.set_recursion_available(true);
        return Ok(response_message);
    }

    let query = questions[0].clone();
    info!("Received query for '{}' (type {})", query.name(), query.query_type());

    let cache_key = (query.name().to_string(), query.query_type());
    // Check if the query is in the cache and is still valid.
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
            // Remove expired entry from the cache.
            cache.remove(&cache_key);
            info!("Cache entry for '{}' expired", query.name());
        }
    }

    // If no cache hit, perform a recursive lookup.
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

    info!("Successfully resolved '{}' with {} answers", query.name(), response_message.answers().len());

    Ok(response_message)
}

/// Recursively performs a DNS lookup, starting from the root servers.
/// This function returns a `Pin<Box<dyn Future>>` to handle recursion.
fn recursive_lookup_with_cache(
    name: hickory_proto::rr::Name,
    record_type: RecordType,
    cache: Cache,
    depth: u8,
) -> Pin<Box<dyn Future<Output = Result<(Vec<Record>, Vec<Record>)>> + Send + 'static>> {
    Box::pin(async move {
        // Prevent infinite recursion.
        if depth > 10 {
            error!("Max recursion depth reached for '{}'", name);
            return Ok((vec![], vec![]));
        }

        let mut current_servers: Vec<IpAddr> = ROOT_SERVERS.iter().map(|&ip| IpAddr::V4(ip)).collect();

        loop {
            let mut request = Message::query();
            let mut header = request.header().clone();
            // Use a random ID for the request.
            header.set_id(random());
            // Set recursion desired to false, as we are doing the recursion ourselves.
            header.set_recursion_desired(false);
            request.set_header(header);

            let query = Query::query(name.clone(), record_type);
            request.add_query(query);

            let mut request_bytes = Vec::new();
            let mut encoder = BinEncoder::new(&mut request_bytes);
            request.emit(&mut encoder)?;

            // Send queries to all current servers in parallel.
            let mut futures = Vec::new();
            for server_ip in &current_servers {
                let server_addr = SocketAddr::new(*server_ip, 53);
                futures.push(send_udp_query(&request_bytes, server_addr));
            }

            let mut successful_response = None;
            // Await the first successful response.
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

            // If we have answers, we've found our result. Cache and return.
            if !response.answers().is_empty() {
                let answers = response.answers().to_vec();
                if let Some(min_ttl) = answers.iter().map(|r| r.ttl()).min() {
                    let expires_at = Instant::now() + Duration::from_secs(min_ttl.into());
                    cache.insert((name.to_string(), record_type), CacheEntry { records: answers.clone(), expires_at });
                }
                return Ok((answers, response.name_servers().to_vec()));
            }

            // Handle CNAME redirects.
            if let Some(rec) = response.answers().iter().find(|rec| rec.record_type() == RecordType::CNAME) {
                if let RData::CNAME(cname_name_record) = rec.data() {
                    info!("Received CNAME for '{}', recursing with '{}'", name, cname_name_record.0);
                    return recursive_lookup_with_cache(cname_name_record.0.clone(), record_type, cache.clone(), depth + 1).await;
                }
            }

            // Handle delegation (referral) to other nameservers.
            if !response.name_servers().is_empty() {
                let mut new_servers = Vec::new();
                let mut ns_names = Vec::new();

                for record in response.name_servers() {
                    if let RData::NS(ns_name_record) = record.data() {
                        ns_names.push(ns_name_record.0.clone());
                        // Check for "glue records" in the additional section.
                        for additional_record in response.additionals() {
                            if additional_record.name() == &ns_name_record.0 {
                                if let Some(ip) = extract_ip_from_rdata(additional_record.data()) {
                                    new_servers.push(ip);
                                }
                            }
                        }
                    }
                }

                // If no glue records were found, we need to perform a new lookup
                // for the NS server's IP address.
                if new_servers.is_empty() {
                    info!("Glue records not found, performing new lookups for NS servers.");
                    for ns_name in &ns_names {
                        match recursive_lookup_with_cache(ns_name.clone(), RecordType::A, cache.clone(), depth + 1).await {
                            Ok((answers, _)) => {
                                for answer in answers {
                                    if let Some(ip) = extract_ip_from_rdata(answer.data()) {
                                        new_servers.push(ip);
                                    }
                                }
                            }
                            Err(e) => error!("Failed to resolve NS server {}: {}", ns_name, e),
                        }
                    }
                }

                // If we still don't have new servers, we can't continue.
                if new_servers.is_empty() {
                    warn!("Could not find IP addresses for new nameservers, stopping recursion.");
                    return Ok((vec![], response.name_servers().to_vec()));
                }

                // Update the list of servers and continue the loop.
                current_servers = new_servers;
                info!("Following referral to new servers: {:?}", current_servers);
            } else {
                // No answers and no referrals, the lookup has failed.
                return Ok((vec![], response.name_servers().to_vec()));
            }
        }
    })
}

/// Sends a UDP DNS query and waits for a response with a timeout.
async fn send_udp_query(request_bytes: &[u8], server_addr: SocketAddr) -> Result<Vec<u8>, anyhow::Error> {
    // Bind to a random ephemeral port.
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    // Send the request, with a timeout.
    tokio::time::timeout(DNS_REQUEST_TIMEOUT, socket.send_to(request_bytes, &server_addr)).await??;

    let mut buf = vec![0; MAX_UDP_PAYLOAD_SIZE];
    // Await the response, with a timeout.
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
