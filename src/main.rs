use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, Ipv6Addr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use log::{error, info, warn};
use simplelog::{ColorChoice, Config, LevelFilter, TermLogger, TerminalMode};
use tokio::net::UdpSocket;
use tokio::time::{timeout, interval};

// Используем Arc<Mutex<_>> для безопасного доступа к кэшу в нескольких потоках
type Cache = Arc<Mutex<HashMap<String, (IpAddr, Instant)>>>;

const CACHE_LIFETIME_SECONDS: u64 = 3600;
const MAX_RECURSION_DEPTH: u32 = 10;
const ROOT_SERVER: &str = "198.41.0.4";
const UDP_TIMEOUT_MS: u64 = 2000;
const SERVER_PORT: u16 = 5353;

/// Тип для рекурсивного асинхронного поиска.
type RecursiveLookupFuture = Pin<Box<dyn std::future::Future<Output = Result<IpAddr, Box<dyn std::error::Error>>> + Send>>;

/// Создает DNS-сообщение для запроса.
fn create_query_message(
    name: &Name,
    record_type: RecordType,
    id: u16,
) -> Result<Message, Box<dyn std::error::Error>> {
    let mut message = Message::new(id, MessageType::Query, OpCode::Query);
    let mut query = hickory_proto::op::Query::new();
    query.set_name(name.clone());
    query.set_query_type(record_type);
    message.add_query(query);
    Ok(message)
}

/// Отправляет и получает UDP-пакеты асинхронно с таймаутом.
async fn send_and_receive_udp(
    server_addr: &IpAddr,
    query_message: &Message,
) -> Result<Message, Box<dyn std::error::Error>> {
    // Биндимся на [::]:0 для поддержки как IPv4, так и IPv6
    let socket = UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0)).await?;
    let buffer = query_message.to_vec()?;
    let server_socket_addr = SocketAddr::new(*server_addr, 53);
    socket.send_to(&buffer, server_socket_addr).await?;

    let mut response_buffer = [0u8; 512];
    let timeout_duration = Duration::from_millis(UDP_TIMEOUT_MS);
    let recv_result = timeout(timeout_duration, socket.recv_from(&mut response_buffer)).await;

    match recv_result {
        Ok(Ok((bytes_read, _))) => {
            let response_message = Message::from_vec(&response_buffer[..bytes_read])?;
            Ok(response_message)
        }
        Ok(Err(e)) => Err(format!("Socket error: {}", e).into()),
        Err(_) => Err("Timed out waiting for response".into()),
    }
}

/// Рекурсивный поиск DNS с кэшированием.
fn recursive_lookup_with_cache(
    name: Name,
    record_type: RecordType,
    cache: Cache,
    depth: u32,
) -> RecursiveLookupFuture {
    Box::pin(async move {
        if depth > MAX_RECURSION_DEPTH {
            return Err("Maximum recursion depth exceeded".into());
        }

        let cache_key = name.to_string();
        if let Some((addr, timestamp)) = cache.lock().unwrap().get(&cache_key) {
            if timestamp.elapsed().as_secs() < CACHE_LIFETIME_SECONDS {
                info!("Cache hit for '{}'", cache_key);
                return Ok(*addr);
            } else {
                info!("Cache expired for '{}'", cache_key);
            }
        }

        info!("Attempting to resolve '{}' (depth: {})", name, depth);

        let mut current_server = IpAddr::V4(ROOT_SERVER.parse()?);
        let mut resolved_address: Option<IpAddr> = None;

        loop {
            let query_message = create_query_message(&name, record_type, 1)?;
            let response_message = match send_and_receive_udp(&current_server, &query_message).await {
                Ok(msg) => msg,
                Err(e) => {
                    error!(
                        "Error sending query for '{}' to {}: {}",
                        name, current_server, e
                    );
                    return Err(e);
                }
            };

            match response_message.response_code() {
                ResponseCode::NoError => {}
                ResponseCode::NXDomain => return Err(format!("NXDOMAIN: Domain '{}' does not exist", name).into()),
                _ => return Err(format!("DNS error for '{}': {:?}", name, response_message.response_code()).into()),
            }

            if let Some(ip) = process_answers(&response_message, &name, record_type) {
                resolved_address = Some(ip);
                cache
                    .lock()
                    .unwrap()
                    .insert(cache_key.clone(), (ip, Instant::now()));
                break;
            }

            if let Some(cname_record) = response_message
                .answers()
                .iter()
                .find(|r| r.name() == &name && r.record_type() == RecordType::CNAME)
                .and_then(|r| r.data().as_cname())
            {
                let cname_name = cname_record.0.clone();
                info!(
                    "Received CNAME for '{}', recursing with '{}'",
                    name, cname_name
                );
                return Box::pin(recursive_lookup_with_cache(
                    cname_name,
                    record_type,
                    Arc::clone(&cache),
                    depth + 1,
                ))
                .await;
            }

            if let Some(ns_record) = response_message
                .name_servers()
                .iter()
                .find(|r| r.record_type() == RecordType::NS)
                .and_then(|r| r.data().as_ns())
            {
                let ns_name = ns_record.0.clone();
                info!("Received NS record: {}", ns_name);

                if let Some(additional_record) = response_message.additionals().iter().find(|r| {
                    *r.name() == ns_name
                        && (r.record_type() == RecordType::A || r.record_type() == RecordType::AAAA)
                }) {
                    if let Some(ns_ip) = get_ip_from_rdata(additional_record.data()) {
                        current_server = ns_ip;
                        info!("Found additional record IP for NS: {}", current_server);
                        continue;
                    }
                }

                info!("No additional record for NS server, doing recursive lookup for IP");
                match Box::pin(recursive_lookup_with_cache(
                    ns_name.clone(),
                    RecordType::A,
                    Arc::clone(&cache),
                    depth + 1,
                ))
                .await
                {
                    Ok(ip) => {
                        current_server = ip;
                        info!("Resolved NS server IP: {}", current_server);
                        continue;
                    }
                    Err(e) => {
                        error!("Failed to resolve NS server {}: {}", ns_name, e);
                        return Err(e);
                    }
                }
            }

            warn!("No answers or referrals received. Giving up on '{}'", name);
            break;
        }

        resolved_address.ok_or_else(|| "Failed to find a valid IP address".into())
    })
}

/// Извлекает IP-адрес из ответа.
fn process_answers(
    response_message: &Message,
    name: &Name,
    record_type: RecordType,
) -> Option<IpAddr> {
    response_message
        .answers()
        .iter()
        .find(|r| r.name() == name && r.record_type() == record_type)
        .and_then(|r| get_ip_from_rdata(r.data()))
}

/// Извлекает IP-адрес из RData.
fn get_ip_from_rdata(rdata: &RData) -> Option<IpAddr> {
    match rdata {
        RData::A(a) => Some(IpAddr::V4(a.0)),
        RData::AAAA(aaaa) => Some(IpAddr::V6(aaaa.0)),
        _ => None,
    }
}

/// Главная асинхронная функция сервера.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    TermLogger::init(
        LevelFilter::Info,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )?;

    let cache = Arc::new(Mutex::new(HashMap::new()));
    // Биндимся на [::]:5353 для поддержки как IPv4, так и IPv6
    let socket = UdpSocket::bind((Ipv6Addr::UNSPECIFIED, SERVER_PORT)).await?;

    info!("DNS-сервер запущен на 127.0.0.1:{}", SERVER_PORT);

    let mut buf = [0; 512];
    
    // Создаем селектор для ожидания либо UDP-пакета, либо сигнала завершения
    let mut shutdown_signal = Box::pin(tokio::signal::ctrl_c());
    // Создаем интервал для периодической проверки работоспособности
    let mut health_check_interval = interval(Duration::from_secs(30));

    loop {
        tokio::select! {
            // Ожидаем входящий UDP-пакет
            Ok((len, src)) = socket.recv_from(&mut buf) => {
                let cache_clone = Arc::clone(&cache);
                let request_bytes = buf[..len].to_vec();
        
                let (response_message, dest_addr) = tokio::spawn(async move {
                    info!("Received query from {}", src);
                    let mut response_message;
                    let response_code;
        
                    match Message::from_vec(&request_bytes) {
                        Ok(request_message) => {
                            // Создаем ответное сообщение с правильными ID и OpCode сразу
                            response_message = Message::new(
                                request_message.id(),
                                MessageType::Response,
                                request_message.op_code(),
                            );
                            
                            if let Some(query) = request_message.queries().get(0) {
                                info!("Starting recursive lookup for '{}' of type '{}'", query.name(), query.query_type());
                                response_message.add_query(query.clone());
        
                                match Box::pin(recursive_lookup_with_cache(
                                    query.name().clone(),
                                    query.query_type(),
                                    cache_clone,
                                    0,
                                ))
                                .await
                                {
                                    Ok(resolved_ip) => {
                                        let rdata = match resolved_ip {
                                            IpAddr::V4(ipv4) => RData::A(ipv4.into()),
                                            IpAddr::V6(ipv6) => RData::AAAA(ipv6.into()),
                                        };
                                        let record = Record::from_rdata(query.name().clone(), 3600, rdata);
                                        response_message.add_answer(record);
                                        response_code = ResponseCode::NoError;
                                        info!("Successfully resolved '{}' to {}", query.name(), resolved_ip);
                                    }
                                    Err(e) => {
                                        error!("Failed to resolve '{}'. Reason: {}", query.name(), e);
                                        if e.to_string().contains("NXDOMAIN") {
                                            response_code = ResponseCode::NXDomain;
                                        } else {
                                            response_code = ResponseCode::ServFail;
                                        }
                                    }
                                }
                            } else {
                                error!("Received query with no questions.");
                                response_code = ResponseCode::FormErr;
                            }
                        }
                        Err(e) => {
                            error!("Failed to parse DNS query from '{}'. Reason: {}", src, e);
                            response_code = ResponseCode::FormErr;
                            // Создаем сообщение по умолчанию для некорректного пакета
                            response_message = Message::new(0, MessageType::Response, OpCode::Query);
                        }
                    }
                    
                    response_message.set_response_code(response_code);
                    (response_message, src)
                })
                .await?;
        
                let response_buffer = response_message.to_vec()?;
                socket.send_to(&response_buffer, dest_addr).await?;
            }
            // Ожидаем срабатывание интервала проверки здоровья
            _ = health_check_interval.tick() => {
                let health_check_domain = Name::from_ascii("health-check.google.com").unwrap();
                let cache_clone = Arc::clone(&cache);
                info!("Running periodic health check...");

                tokio::spawn(async move {
                    match Box::pin(recursive_lookup_with_cache(
                        health_check_domain.clone(),
                        RecordType::A,
                        cache_clone,
                        0,
                    )).await {
                        Ok(ip) => info!("Health check passed. Resolved '{}' to {}", health_check_domain, ip),
                        Err(e) => error!("Health check FAILED for '{}'. Reason: {}", health_check_domain, e),
                    }
                });
            }
            // Ожидаем сигнал Ctrl+C
            _ = &mut shutdown_signal => {
                info!("Получен сигнал Ctrl+C. Завершение работы...");
                break;
            }
        }
    }

    Ok(())
}
