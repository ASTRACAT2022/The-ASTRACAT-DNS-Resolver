// Запустите сервер командой: RUST_LOG=info cargo run
// ПЕРЕД СБОРКОЙ ДОБАВЬТЕ ЭТУ СТРОКУ В ФАЙЛ Cargo.toml: dashmap = "5.5"

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use std::time::{Duration, Instant};
use std::io;
use std::future::Future;
use std::pin::Pin;

use hickory_proto::op::{Message, MessageType, ResponseCode, Header, Query};
use hickory_proto::rr::{Record, RecordType, RData};
use hickory_proto::serialize::binary::{BinEncoder, BinDecoder, BinDecodable, BinEncodable};
use anyhow::{Result, Context};
use rand::random;
use dashmap::DashMap;

/// Максимальный размер UDP-пакета для DNS
const MAX_UDP_PAYLOAD_SIZE: usize = 512;
/// Стандартный порт для DNS-сервера
const DNS_PORT: u16 = 5353;
/// Таймаут для каждого запроса к DNS-серверу
const DNS_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
/// Минимальный оставшийся TTL для запуска предзагрузки
const PREFETCH_THRESHOLD: Duration = Duration::from_secs(60);

// Список корневых DNS-серверов. Используется для начала рекурсии.
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

// Структура для хранения записей в кеше с временем жизни (TTL)
struct CacheEntry {
    records: Vec<Record>,
    expires_at: Instant,
}

// Кеш для хранения DNS-ответов
type Cache = Arc<DashMap<(String, RecordType), CacheEntry>>;

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Инициализируем систему логирования
    env_logger::init();
    
    log::info!("Starting DNS resolver on 0.0.0.0:{}", DNS_PORT);

    // 2. Создаем UDP-сокет для прослушивания порта и кеш
    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), DNS_PORT);
    let sock = Arc::new(UdpSocket::bind(bind_addr).await
        .with_context(|| format!("Failed to bind to {}", bind_addr))?);
    let cache: Cache = Arc::new(DashMap::new());

    log::info!("Listening on {}", bind_addr);

    // Запускаем фоновую задачу для очистки кеша и предзагрузки
    let cache_clone_prefetch = Arc::clone(&cache);
    tokio::spawn(async move {
        loop {
            // Итерация по кешу для очистки устаревших записей
            let now = Instant::now();
            cache_clone_prefetch.retain(|_, v| v.expires_at > now);

            // Итерация по кешу для предзагрузки
            for entry in cache_clone_prefetch.iter() {
                if let Some(time_left) = entry.expires_at.checked_duration_since(now) {
                    if time_left < PREFETCH_THRESHOLD {
                        let (name_str, record_type) = entry.key();
                        let name_owned = name_str.parse().unwrap_or_else(|_| {
                            log::error!("Failed to parse name from cache for prefetch: {}", name_str);
                            return hickory_proto::rr::Name::from_ascii(".").unwrap();
                        });
                        log::info!("Prefetching expiring record for '{}' (type {})", name_owned, record_type);
                        
                        // Запускаем фоновый рекурсивный поиск для обновления
                        let cache_clone_inner = Arc::clone(&cache_clone_prefetch);
                        tokio::spawn(async move {
                            if let Ok((answers, authorities)) = recursive_lookup_with_cache(name_owned, *record_type, &cache_clone_inner, 0).await {
                                // Обновляем кеш, если есть ответы
                                if !answers.is_empty() {
                                    let min_ttl = answers.iter().map(|r| r.ttl()).min().unwrap_or(0);
                                    let expires_at = Instant::now() + Duration::from_secs(min_ttl.into());
                                    cache_clone_inner.insert((name_str.to_string(), *record_type), CacheEntry { records: answers, expires_at });
                                    log::info!("Successfully prefetched and updated cache for '{}'", name_str);
                                }
                                if !authorities.is_empty() {
                                    // Обработка авторитетных записей для предзагрузки
                                }
                            }
                        });
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    });

    // 4. Основной цикл сервера для обработки запросов
    let mut buf = vec![0; MAX_UDP_PAYLOAD_SIZE];
    loop {
        let (len, addr) = tokio::select! {
            result = sock.recv_from(&mut buf) => result.context("Failed to receive from socket"),
            _ = tokio::time::sleep(Duration::from_secs(60)) => {
                log::trace!("No activity, sleeping...");
                continue;
            }
        }?;
        
        let sock_clone = Arc::clone(&sock);
        let cache_clone = Arc::clone(&cache);
        let request_bytes_owned = buf[..len].to_vec();
        
        // 5. Запускаем обработку запроса в фоновом режиме
        tokio::spawn(async move {
            match handle_query(&request_bytes_owned, &cache_clone).await {
                Ok(response_message) => {
                    let mut response_bytes = Vec::new();
                    let mut encoder = BinEncoder::new(&mut response_bytes);
                    
                    if let Ok(_) = response_message.emit(&mut encoder) {
                        if let Err(e) = sock_clone.send_to(&response_bytes, addr).await {
                            log::error!("Failed to send response to {}: {}", addr, e);
                        }
                    }
                },
                Err(e) => {
                    log::error!("Error handling query from {}: {}", addr, e);
                    let mut failure_message = Message::new();
                    failure_message.set_response_code(ResponseCode::ServFail);
                    failure_message.set_message_type(MessageType::Response);
                    
                    let mut response_bytes = Vec::new();
                    let mut encoder = BinEncoder::new(&mut response_bytes);
                    
                    if let Ok(_) = failure_message.emit(&mut encoder) {
                        if let Err(e) = sock_clone.send_to(&response_bytes, addr).await {
                            log::error!("Failed to send error response to {}: {}", addr, e);
                        }
                    }
                }
            }
        });
    }
}

/// Асинхронно обрабатывает один DNS-запрос.
async fn handle_query(request_bytes: &[u8], cache: &Cache) -> Result<Message> {
    let mut decoder = BinDecoder::new(request_bytes);
    let request_message = Message::read(&mut decoder)
        .context("Failed to decode DNS request message")?;

    let questions = request_message.queries();
    if questions.is_empty() {
        log::warn!("Received a DNS request with no questions.");
        return Ok(request_message);
    }
    
    let query = questions[0].clone();
    
    log::info!("Received a query for '{}' (type {})", query.name(), query.query_type());

    // 1. Проверяем кеш перед рекурсивным поиском
    let cache_key = (query.name().to_string(), query.query_type());
    if let Some(entry) = cache.get(&cache_key) {
        if entry.expires_at > Instant::now() {
            log::info!("Cache hit for '{}'", query.name());
            let mut response_message = Message::new();
            response_message.set_id(request_message.header().id());
            response_message.set_message_type(MessageType::Response);
            response_message.set_recursion_available(true);
            response_message.add_query(query);
            for record in entry.records.iter() {
                response_message.add_answer(record.clone());
            }
            return Ok(response_message);
        } else {
            // Удаляем устаревшую запись из кеша
            cache.remove(&cache_key);
            log::info!("Cache entry for '{}' expired", query.name());
        }
    }
    
    // ИСПОЛЬЗУЕМ РУЧНУЮ РЕКУРСИЮ!
    let (answers, authorities) = recursive_lookup_with_cache(query.name().clone(), query.query_type(), cache, 0).await
        .context("Recursive lookup failed")?;

    let mut response_message = Message::new();
    response_message.set_id(request_message.header().id());
    response_message.set_message_type(MessageType::Response);
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
    
    log::info!("Successfully resolved '{}' with {} answers", query.name(), response_message.answers().len());
    
    Ok(response_message)
}

/// Выполняет ручную рекурсию, начиная с корневых серверов.
fn recursive_lookup_with_cache(
    name: hickory_proto::rr::Name,
    record_type: RecordType,
    cache: &Cache,
    depth: u8,
) -> Pin<Box<dyn Future<Output = Result<(Vec<Record>, Vec<Record>)>> + Send + 'static>> {
    Box::pin(async move {
        if depth > 10 {
            log::error!("Max recursion depth reached for '{}'", name);
            return Ok((vec![], vec![]));
        }

        let mut current_servers: Vec<IpAddr> = ROOT_SERVERS.iter().map(|&ip| IpAddr::V4(ip)).collect();
        
        loop {
            // Создаем DNS-сообщение для запроса
            let mut request = Message::new();
            let mut header = Header::new();
            header.set_id(random());
            header.set_recursion_desired(false);
            request.set_header(header);
            let query = Query::query(name.clone(), record_type);
            request.add_query(query);
            
            let mut request_bytes = Vec::new();
            let mut encoder = BinEncoder::new(&mut request_bytes);
            request.emit(&mut encoder)?;
    
            // Параллельно отправляем запросы всем серверам
            let mut futures = Vec::new();
            for server_ip in &current_servers {
                let server_addr = SocketAddr::new(*server_ip, 53);
                futures.push(send_udp_query(&request_bytes, &server_addr));
            }

            let mut successful_response = None;
            while !futures.is_empty() {
                // Ждем первый успешный ответ
                let response_result = tokio::select! {
                    res = futures.remove(0) => res,
                    _ = tokio::time::sleep(DNS_REQUEST_TIMEOUT) => {
                        log::warn!("Timeout waiting for response.");
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
                // Найден финальный ответ
                let answers = response.answers().to_vec();
                if let Some(min_ttl) = answers.iter().map(|r| r.ttl()).min() {
                    let expires_at = Instant::now() + Duration::from_secs(min_ttl.into());
                    cache.insert((name.to_string(), record_type), CacheEntry { records: answers.clone(), expires_at });
                }
                
                return Ok((answers, response.name_servers().to_vec()));
            }

            // Обработка CNAME-записей
            if let Some(cname) = response.answers().iter().find_map(|rec| {
                if let Some(RData::CNAME(cname)) = rec.data() {
                    Some(cname.clone())
                } else {
                    None
                }
            }) {
                log::info!("Received CNAME for '{}', recursing with '{}'", name, cname);
                return recursive_lookup_with_cache(cname.0, record_type, cache, depth + 1).await;
            }
    
            // Если есть NS-записи, но нет ответов, то это реферал
            if !response.name_servers().is_empty() {
                let mut new_servers = Vec::new();
                let mut ns_names = Vec::new();
                
                for record in response.name_servers() {
                    if let Some(RData::NS(ns_name)) = record.data() {
                        ns_names.push(ns_name.clone());
                        for additional_record in response.additionals() {
                            if additional_record.name() == &ns_name.0 {
                                if let Some(ip) = extract_ip_from_rdata(additional_record.data()) {
                                    new_servers.push(ip);
                                }
                            }
                        }
                    }
                }
                
                if new_servers.is_empty() {
                    log::info!("Glue records not found, performing new lookups for NS servers.");
                    for ns_name in &ns_names {
                        match recursive_lookup_with_cache(ns_name.0.clone(), RecordType::A, cache, depth + 1).await {
                            Ok((answers, _)) => {
                                for answer in answers {
                                    if let Some(ip) = extract_ip_from_rdata(answer.data()) {
                                        new_servers.push(ip);
                                    }
                                }
                            },
                            Err(e) => log::error!("Failed to resolve NS server {}: {}", ns_name.0, e),
                        }
                    }
                }
                
                if new_servers.is_empty() {
                    log::warn!("Could not find IP addresses for new nameservers, stopping recursion.");
                    return Ok((vec![], response.name_servers().to_vec()));
                }
    
                current_servers = new_servers;
                log::info!("Following referral to new servers: {:?}", current_servers);
            } else {
                return Ok((vec![], response.name_servers().to_vec()));
            }
        }
    })
}

/// Отправляет DNS-запрос по UDP и ждет ответа с таймаутом.
async fn send_udp_query(request_bytes: &[u8], server_addr: &SocketAddr) -> Result<Vec<u8>, anyhow::Error> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    tokio::time::timeout(DNS_REQUEST_TIMEOUT, socket.send_to(request_bytes, server_addr)).await??;

    let mut buf = vec![0; MAX_UDP_PAYLOAD_SIZE];
    let (len, _) = tokio::time::timeout(DNS_REQUEST_TIMEOUT, socket.recv_from(&mut buf)).await??;
    
    Ok(buf[..len].to_vec())
}

/// Вспомогательная функция для извлечения IpAddr из RData
fn extract_ip_from_rdata(rdata: Option<&RData>) -> Option<IpAddr> {
    match rdata {
        Some(RData::A(ipv4)) => Some(IpAddr::V4(ipv4.0)),
        Some(RData::AAAA(ipv6)) => Some(IpAddr::V6(ipv6.0)),
        _ => None,
    }
}
