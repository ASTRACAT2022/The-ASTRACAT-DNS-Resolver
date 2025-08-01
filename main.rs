// main.rs - ASTRACAT DNS Resolver, высокопроизводительная и оптимизированная версия

use std::net::{SocketAddr, IpAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::fs::File;
use std::io::{BufReader, BufRead};

use tokio::net::{UdpSocket, TcpListener};
use tokio::spawn;
use tokio::time::timeout;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// --- ИСПРАВЛЕННЫЕ ИМПОРТЫ ---
use trust_dns_proto::op::{Message, Query, ResponseCode};
use trust_dns_proto::rr::{Record, RecordType};
use trust_dns_proto::serialize::binary::{BinEncodable};

use dashmap::DashMap;
use once_cell::sync::Lazy;

use prometheus::{Encoder, IntCounter, TextEncoder};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server};

// --- Секция: Метрики Prometheus ---
// Инициализация глобальных счетчиков и метрик
static QPS_COUNTER: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::new("astracat_qps_total", "Total DNS queries received").unwrap()
});
static CACHE_HITS_COUNTER: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::new("astracat_cache_hits_total", "Total DNS queries served from cache").unwrap()
});
static RECURSIVE_QUERIES_COUNTER: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::new("astracat_recursive_queries_total", "Total recursive DNS queries performed").unwrap()
});

/// Обработчик HTTP-запроса для метрик Prometheus
async fn serve_metrics(_req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = vec![];
    encoder.encode(&metric_families, &mut buffer).unwrap();
    
    let response = Response::builder()
        .header(hyper::header::CONTENT_TYPE, encoder.format_type())
        .body(Body::from(buffer))
        .unwrap();
    Ok(response)
}

// --- Секция: Структуры данных и кэширование ---

/// Структура для записи в кэше DNS
#[derive(Debug, Clone)]
struct CacheEntry {
    records: Vec<Record>,
    expiry_time: Instant,
}

/// Потокобезопасный DNS-кеш, используем `Query` в качестве ключа
type DnsCache = DashMap<Query, CacheEntry>;

// --- Секция: Подсказки для серверов ---

/// Структура, хранящая адреса корневых серверов для быстрого старта.
struct ServerHints {
    root_servers: Vec<SocketAddr>,
}

impl ServerHints {
    /// Загружает адреса корневых серверов из файла.
    fn load_from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut root_servers = Vec::new();
        for line in reader.lines() {
            let line = line?;
            if let Ok(addr) = line.parse::<SocketAddr>() {
                root_servers.push(addr);
            }
        }
        println!("Loaded {} root server hints from {}", root_servers.len(), path);
        Ok(Self { root_servers })
    }
}

// --- Секция: Итеративный рекурсивный резолвер ---

/// Структура, выполняющая итеративный резолвинг DNS-запроса
struct RecursiveResolver {
    // Shared UDP socket for sending recursive queries
    udp_sock: Arc<UdpSocket>,
    root_servers: Vec<SocketAddr>,
}

impl RecursiveResolver {
    fn new(sock: Arc<UdpSocket>, hints: ServerHints) -> Self {
        Self { udp_sock: sock, root_servers: hints.root_servers }
    }

    /// Рекурсивный резолвинг запроса с параллельными запросами к нескольким NS
    async fn resolve_iterative(&self, query: &Query) -> Result<Message, Box<dyn std::error::Error>> {
        RECURSIVE_QUERIES_COUNTER.inc();
        
        let mut name_to_resolve = query.name().clone();
        let mut current_servers = self.root_servers.clone();

        let mut query_message = Message::new();
        query_message.add_query(query.clone());
        query_message.set_recursion_desired(false);

        loop {
            if current_servers.is_empty() {
                return Err("No more servers to query".into());
            }

            // Создаем задачи для параллельного запроса к серверам
            let mut tasks = Vec::new();
            for server_addr in current_servers.iter() {
                let sock_clone = Arc::clone(&self.udp_sock);
                
                let buf = query_message.to_bytes()?;
                let server_addr_clone = *server_addr;

                tasks.push(tokio::spawn(async move {
                    if let Err(_) = sock_clone.send_to(&buf, server_addr_clone).await {
                        return None;
                    }
                    let mut response_buf = [0; 512];
                    match timeout(Duration::from_secs(5), sock_clone.recv_from(&mut response_buf)).await {
                        Ok(Ok((len, _))) => Some(Message::from_vec(&response_buf[..len]).ok()),
                        _ => None,
                    }
                }));
            }

            // Ждем первый успешный ответ
            let mut response_message = None;
            for task in tasks {
                if let Ok(Some(Some(packet))) = task.await {
                    response_message = Some(packet);
                    break;
                }
            }

            let response_message = match response_message {
                Some(msg) => msg,
                None => return Err("All server queries failed or timed out".into()),
            };

            // Проверяем, является ли ответ авторитетным
            if response_message.header().authoritative() {
                // Если ответ содержит CNAME, нужно его обработать
                if let Some(cname_record) = response_message.answers().iter().find(|r| r.record_type() == RecordType::CNAME) {
                    if let Some(data) = cname_record.data() {
                        if let Some(cname) = data.as_cname() {
                            name_to_resolve = cname.clone();
                        }
                    }
                    query_message = Message::new();
                    query_message.add_query(Query::query(name_to_resolve.clone(), query.query_type()));
                    current_servers = self.root_servers.clone();
                    continue;
                }
                
                // Упрощенная валидация DNSSEC (проверка флага AD)
                if response_message.header().authentic_data() {
                    println!("DNSSEC validation successful (AD flag is set) for: {:?}", query.name());
                } else {
                    println!("DNSSEC validation failed or not supported for: {:?}", query.name());
                }

                // Возвращаем финальный ответ
                return Ok(response_message);
            }
            
            // Если ответ неавторитетный, ищем новые NS-серверы
            let mut next_servers = Vec::new();
            for record in response_message.name_servers() {
                if let Some(rdata) = record.data() {
                    if let Some(ns_name) = rdata.as_ns() {
                        if let Some(glue_record) = response_message.additionals().iter()
                            .find(|r| r.name() == ns_name && (r.record_type() == RecordType::A || r.record_type() == RecordType::AAAA))
                        {
                            // --- ИСПРАВЛЕНО: .as_a() возвращает &Ipv4Addr, мы просто его клонируем
                            if let Some(ip) = glue_record.data().and_then(|data| data.as_a()) {
                                next_servers.push(SocketAddr::new(IpAddr::V4(ip.clone()), 53));
                            }
                        }
                    }
                }
            }
            
            if next_servers.is_empty() {
                return Err("Failed to find next nameservers".into());
            }

            current_servers = next_servers;
        }
    }
}

// --- Секция: Обработка DNS-запроса (основной обработчик) ---

/// Структура для отслеживания rate-limiting
struct RateLimitEntry {
    requests: u32,
    last_reset: Instant,
}

// Потокобезопасная карта для rate-limiting
type RateLimitMap = DashMap<IpAddr, RateLimitEntry>;

/// Главная функция, обрабатывающая DNS-запрос.
async fn process_dns_query(
    buf: &[u8],
    source_addr: std::net::SocketAddr,
    cache: Arc<DnsCache>,
    resolver: Arc<RecursiveResolver>,
    rate_limit_map: Arc<RateLimitMap>,
) -> Option<Message> {
    
    // Проверка rate-limiting
    let ip = source_addr.ip();
    let mut entry = rate_limit_map.entry(ip).or_insert_with(|| RateLimitEntry {
        requests: 0,
        last_reset: Instant::now(),
    });

    let now = Instant::now();
    let max_requests_per_sec = 100;
    
    if now.duration_since(entry.last_reset) > Duration::from_secs(1) {
        entry.requests = 1;
        entry.last_reset = now;
    } else {
        entry.requests += 1;
        if entry.requests > max_requests_per_sec {
            eprintln!("Rate-limit exceeded for IP: {}", ip);
            return None;
        }
    }
    drop(entry);

    QPS_COUNTER.inc();
    
    let message = match Message::from_vec(buf) {
        Ok(p) => p,
        Err(_) => return None,
    };

    let query = match message.queries().get(0) {
        Some(q) => q.clone(),
        None => return None,
    };

    // Проверяем кэш
    if let Some(entry) = cache.get(&query) {
        if Instant::now() < entry.expiry_time {
            CACHE_HITS_COUNTER.inc();
            println!("Cache hit for: {:?}", query.name());
            let mut response = Message::new();
            response.set_header(message.header().clone());
            response.add_query(query.clone());
            response.add_answers(entry.records.clone());
            response.set_response_code(ResponseCode::NoError);
            return Some(response);
        }
    }
    
    println!("Cache miss for: {:?}", query.name());
    
    let response = resolver.resolve_iterative(&query).await.unwrap_or_else(|_| {
        let mut error_msg = Message::new();
        error_msg.set_response_code(ResponseCode::ServFail);
        error_msg
    });

    // После успешного резолвинга, сохраняем ответ в кэш
    if response.answers().is_empty() {
        let entry = CacheEntry {
            records: vec![],
            expiry_time: Instant::now() + Duration::from_secs(300), // Negative caching TTL
        };
        cache.insert(query, entry);
    } else {
        let min_ttl = response.answers().iter().map(|r| r.ttl()).min().unwrap_or(60);
        let entry = CacheEntry {
            records: response.answers().to_vec(),
            expiry_time: Instant::now() + Duration::from_secs(min_ttl.into()),
        };
        cache.insert(query, entry);
    }

    Some(response)
}

// --- Секция: Сетевые слушатели (UDP/TCP) ---

async fn handle_udp_requests(
    sock: Arc<UdpSocket>, // Используем Arc для общего сокета
    cache: Arc<DnsCache>,
    resolver: Arc<RecursiveResolver>,
    rate_limit_map: Arc<RateLimitMap>,
) {
    let mut buf = [0; 512]; // Буфер переиспользуется
    loop {
        match sock.recv_from(&mut buf).await {
            Ok((len, src)) => {
                let cache_clone = Arc::clone(&cache);
                let resolver_clone = Arc::clone(&resolver);
                let udp_sock_clone = Arc::clone(&sock);
                let rate_limit_map_clone = Arc::clone(&rate_limit_map);
                
                tokio::spawn(async move {
                    if let Some(response_msg) = process_dns_query(
                        &buf[..len],
                        src,
                        cache_clone,
                        resolver_clone,
                        rate_limit_map_clone,
                    ).await {
                        if let Ok(response_buf) = response_msg.to_bytes() {
                            if let Err(e) = udp_sock_clone.send_to(&response_buf, src).await {
                                eprintln!("Failed to send UDP response: {:?}", e);
                            }
                        }
                    }
                });
            }
            Err(e) => eprintln!("UDP recv_from error: {:?}", e),
        }
    }
}

async fn handle_tcp_requests(
    listener: TcpListener,
    cache: Arc<DnsCache>,
    resolver: Arc<RecursiveResolver>,
    rate_limit_map: Arc<RateLimitMap>,
) {
    loop {
        let (mut stream, addr) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Failed to accept TCP connection: {}", e);
                continue;
            }
        };
        let cache_clone = Arc::clone(&cache);
        let resolver_clone = Arc::clone(&resolver);
        let rate_limit_map_clone = Arc::clone(&rate_limit_map);

        tokio::spawn(async move {
            let mut len_buf = [0; 2];
            if let Err(e) = stream.read_exact(&mut len_buf).await {
                eprintln!("Failed to read TCP length prefix: {:?}", e);
                return;
            }
            let packet_len = u16::from_be_bytes(len_buf);
            let mut packet_buf = vec![0; packet_len as usize];

            if let Ok(_) = stream.read_exact(&mut packet_buf).await {
                if let Some(response_msg) = process_dns_query(
                    &packet_buf,
                    addr,
                    cache_clone,
                    resolver_clone,
                    rate_limit_map_clone,
                ).await {
                    if let Ok(response_buf) = response_msg.to_bytes() {
                        let len_prefix = (response_buf.len() as u16).to_be_bytes();
                        if let Err(e) = stream.write_all(&len_prefix).await {
                            eprintln!("Failed to send TCP length prefix: {:?}", e);
                        }
                        if let Err(e) = stream.write_all(&response_buf).await {
                            eprintln!("Failed to send TCP response: {:?}", e);
                        }
                    }
                }
            }
        });
    }
}

// --- Секция: Точка входа в программу ---

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("ASTRACAT DNS Resolver starting...");

    let cache = Arc::new(DnsCache::new());
    let rate_limit_map = Arc::new(RateLimitMap::new());
    
    // Создаем общий UDP-сокет с SO_REUSEPORT
    let udp_bind_addr = "0.0.0.0:5353";
    let udp_sock_raw = UdpSocket::bind(udp_bind_addr).await.expect("Failed to bind UDP socket");
    
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let fd = udp_sock_raw.as_raw_fd();
        let reuseport = 1;
        let res = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_REUSEPORT,
                &reuseport as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if res != 0 {
            eprintln!("Failed to set SO_REUSEPORT: {}", std::io::Error::last_os_error());
        }
    }
    
    let udp_sock = Arc::new(udp_sock_raw);

    // Загружаем подсказки для корневых серверов
    let hints = ServerHints::load_from_file("root_servers.txt")
        .unwrap_or_else(|_| {
            eprintln!("Failed to load root_servers.txt, using hardcoded defaults.");
            ServerHints {
                root_servers: vec![
                    "198.41.0.4:53".parse::<SocketAddr>().unwrap(),
                    "199.9.14.201:53".parse::<SocketAddr>().unwrap(),
                    "192.33.4.12:53".parse::<SocketAddr>().unwrap(),
                ]
            }
        });

    // Инициализируем резолвер, передавая общий сокет и подсказки
    let resolver = Arc::new(RecursiveResolver::new(Arc::clone(&udp_sock), hints));

    // Запускаем HTTP-сервер для метрик Prometheus
    let metrics_addr = SocketAddr::from(([0, 0, 0, 0], 9090));
    let service = make_service_fn(|_| async {
        Ok::<_, hyper::Error>(service_fn(serve_metrics))
    });
    let metrics_server = Server::bind(&metrics_addr).serve(service);
    println!("Prometheus metrics server running on http://{}", metrics_addr);
    spawn(metrics_server);

    // Запускаем воркеры для обработки UDP-запросов, каждый использует общий сокет
    let num_workers = 4;
    for _ in 0..num_workers {
        let cache_clone = Arc::clone(&cache);
        let resolver_clone = Arc::clone(&resolver);
        let udp_sock_clone = Arc::clone(&udp_sock);
        let rate_limit_map_clone = Arc::clone(&rate_limit_map);
        
        spawn(handle_udp_requests(udp_sock_clone, cache_clone, resolver_clone, rate_limit_map_clone));
    }
    
    // Запускаем TCP-слушатель
    let tcp_listener = TcpListener::bind("0.0.0.0:5353").await?;
    println!("TCP listener on port 5353");
    
    let cache_clone = Arc::clone(&cache);
    let resolver_clone = Arc::clone(&resolver);
    let rate_limit_map_clone = Arc::clone(&rate_limit_map);
    spawn(handle_tcp_requests(tcp_listener, cache_clone, resolver_clone, rate_limit_map_clone));

    println!("ASTRACAT DNS Resolver is ready to serve requests.");

    tokio::signal::ctrl_c().await?;
    println!("Shutting down ASTRACAT DNS Resolver");

    Ok(())
}
