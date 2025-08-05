use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::collections::HashMap;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use rand::seq::SliceRandom;
use async_recursion::async_recursion;
use lazy_static::lazy_static;
use prometheus_exporter::{
    self,
    prometheus::{
        register_counter_vec, register_histogram_vec, CounterVec, HistogramVec,
    },
};

mod dns;

use crate::dns::{
    byte_packet_buffer::BytePacketBuffer, dns_packet::DnsPacket, dns_question::DnsQuestion,
    dns_record::DnsRecord, query_type::QueryType, result_code::ResultCode, Result,
};

// Определяем метрики
lazy_static! {
    static ref DNS_QUERIES_TOTAL: CounterVec = register_counter_vec!(
        "dns_queries_total",
        "Total number of DNS queries received.",
        &["result"]
    )
    .unwrap();
    static ref DNS_QUERY_DURATION_SECONDS: HistogramVec = register_histogram_vec!(
        "dns_query_duration_seconds",
        "Duration of DNS queries in seconds.",
        &["result"]
    )
    .unwrap();
    static ref DNS_CACHE_HITS_TOTAL: CounterVec =
        register_counter_vec!("dns_cache_hits_total", "Total number of DNS cache hits.", &["type"])
            .unwrap();
    static ref DNS_CACHE_MISSES_TOTAL: CounterVec = register_counter_vec!(
        "dns_cache_misses_total",
        "Total number of DNS cache misses.",
        &["type"]
    )
    .unwrap();
}

// Корневые DNS-серверы
const ROOT_SERVERS: &[Ipv4Addr] = &[
    Ipv4Addr::new(198, 41, 0, 4),    // A
    Ipv4Addr::new(199, 9, 14, 201),  // B
    Ipv4Addr::new(192, 33, 4, 12),   // C
    Ipv4Addr::new(199, 7, 91, 13),   // D
    Ipv4Addr::new(192, 203, 230, 10), // E
    Ipv4Addr::new(192, 5, 5, 241),   // F
    Ipv4Addr::new(192, 112, 36, 4),  // G
    Ipv4Addr::new(198, 97, 190, 53), // H
    Ipv4Addr::new(192, 36, 148, 17), // I
    Ipv4Addr::new(192, 58, 128, 30), // J
    Ipv4Addr::new(193, 0, 14, 129),  // K
    Ipv4Addr::new(199, 7, 83, 42),   // L
    Ipv4Addr::new(202, 12, 27, 33),  // M
];

// Базовый кеш
lazy_static! {
    static ref DNS_CACHE: Arc<parking_lot::RwLock<HashMap<(String, QueryType), (DnsPacket, Instant, u32)>>> =
        Arc::new(parking_lot::RwLock::new(HashMap::new()));
}

// Проверка валидности домена
fn is_valid_domain(qname: &str) -> bool {
    if qname.is_empty() || qname.len() > 255 {
        return false;
    }
    let labels = qname.split('.').collect::<Vec<&str>>();
    if labels.is_empty() || labels.iter().any(|label| label.is_empty() || label.len() > 63) {
        return false;
    }
    qname.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '-' || c == '_')
}

#[async_recursion]
async fn lookup(mut qname: String, qtype: QueryType, nameserver: Ipv4Addr, depth: u8) -> Result<DnsPacket> {
    const MAX_DEPTH: u8 = 20;
    if depth >= MAX_DEPTH {
        return Err("Превышена максимальная глубина поиска.".into());
    }

    if !is_valid_domain(&qname) {
        eprintln!("Невалидное доменное имя: {}", qname);
        return Err("Невалидное доменное имя.".into());
    }

    let mut auth_servers: Vec<Ipv4Addr> = ROOT_SERVERS.to_vec();
    auth_servers.shuffle(&mut rand::thread_rng());
    let mut current_nameserver = nameserver;
    let mut tried_servers = vec![];

    loop {
        if tried_servers.contains(&current_nameserver) {
            if let Some(next_server) = auth_servers.pop() {
                current_nameserver = next_server;
                continue;
            } else {
                return Err(format!("Все доступные серверы для {} были опрошены.", qname).into());
            }
        }
        tried_servers.push(current_nameserver);

        println!("Попытка запроса к {} для {} (тип: {:?}, глубина: {})", current_nameserver, qname, qtype, depth);

        let mut packet = DnsPacket::new();
        packet.header.id = 6666;
        packet.header.recursion_desired = false;
        packet.header.questions = 1;
        packet.questions.push(DnsQuestion::new(qname.clone(), qtype));

        let mut req_buffer = BytePacketBuffer::new();
        packet.write(&mut req_buffer)?;
        let req_bytes = req_buffer.get_range(0, req_buffer.pos())?;

        let socket = UdpSocket::bind(("0.0.0.0", 0)).await?;
        socket.send_to(req_bytes, (current_nameserver, 53)).await?;

        let mut res_buffer = BytePacketBuffer::new();
        let res = timeout(Duration::from_secs(5), socket.recv_from(&mut res_buffer.buf)).await;

        let (_len, _src) = match res {
            Ok(Ok(val)) => val,
            Ok(Err(e)) => {
                eprintln!("Ошибка сокета для {}: {}", current_nameserver, e);
                if let Some(next_server) = auth_servers.pop() {
                    current_nameserver = next_server;
                    continue;
                } else {
                    return Err(format!("Все серверы недоступны: {}", e).into());
                }
            }
            Err(_) => {
                eprintln!("Тайм-аут для сервера {}", current_nameserver);
                if let Some(next_server) = auth_servers.pop() {
                    current_nameserver = next_server;
                    continue;
                } else {
                    return Err("Все серверы недоступны (тайм-аут).".into());
                }
            }
        };

        let res_packet = DnsPacket::from_buffer(&mut res_buffer)?;
        println!("Получен ответ от {}: {:?}", current_nameserver, res_packet);

        if !res_packet.answers.is_empty() {
            return Ok(res_packet);
        }

        if res_packet.header.rescode == ResultCode::NXDOMAIN {
            // Собираем все NS-записи из секции AUTHORITY
            let ns_records: Vec<String> = res_packet.authorities.iter().filter_map(|rec| {
                if let DnsRecord::NS { domain, host, .. } = rec {
                    if qname.ends_with(domain) {
                        return Some(host.clone());
                    }
                }
                None
            }).collect();

            // Проверяем дополнительные A-записи для NS
            let mut ns_ips: Vec<Ipv4Addr> = res_packet.resources.iter().filter_map(|rec| {
                if let DnsRecord::A { domain, addr, .. } = rec {
                    if ns_records.contains(domain) {
                        return Some(*addr);
                    }
                }
                None
            }).collect();

            if !ns_ips.is_empty() {
                // Используем новые NS-серверы
                auth_servers = ns_ips;
                auth_servers.shuffle(&mut rand::thread_rng());
                tried_servers.clear();
                current_nameserver = auth_servers.pop().unwrap_or(current_nameserver);
                continue;
            } else if !ns_records.is_empty() {
                // Запрашиваем IP для NS-записей
                for ns in ns_records {
                    let ns_ip_packet = lookup(ns.clone(), QueryType::A, current_nameserver, depth + 1).await;
                    if let Ok(ns_ip_packet) = ns_ip_packet {
                        if let Some(ns_ip) = ns_ip_packet.get_random_a() {
                            auth_servers.push(ns_ip);
                        }
                    }
                }
                if !auth_servers.is_empty() {
                    auth_servers.shuffle(&mut rand::thread_rng());
                    tried_servers.clear();
                    current_nameserver = auth_servers.pop().unwrap_or(current_nameserver);
                    continue;
                }
            }
            return Err(format!("Домен не существует (NXDOMAIN) для всех серверов зоны: {}", qname).into());
        }

        if let Some(cname_record) = res_packet.answers.iter().find_map(|rec| {
            if let DnsRecord::CNAME { domain, host, .. } = rec {
                if qname.ends_with(domain) {
                    return Some(host.clone());
                }
            }
            None
        }) {
            qname = cname_record;
            tried_servers.clear();
            continue;
        }

        if let Some(ns_record) = res_packet.authorities.iter().find_map(|rec| {
            if let DnsRecord::NS { domain, host, .. } = rec {
                if qname.ends_with(domain) {
                    return Some(host.clone());
                }
            }
            None
        }) {
            if let Some(a_record) = res_packet.resources.iter().find_map(|rec| {
                if let DnsRecord::A { domain, addr, .. } = rec {
                    if domain == &ns_record {
                        return Some(*addr);
                    }
                }
                None
            }) {
                current_nameserver = a_record;
            } else {
                let ns_ip_packet = lookup(ns_record.clone(), QueryType::A, current_nameserver, depth + 1).await?;
                if let Some(ns_ip) = ns_ip_packet.get_random_a() {
                    current_nameserver = ns_ip;
                } else {
                    return Err(format!("Не удалось разрешить NS-запись для {}", ns_record).into());
                }
            }
            tried_servers.clear();
            continue;
        }

        return Err(format!("Не найдено ответов, CNAME или NS-записей для {}.", qname).into());
    }
}

async fn handle_query(socket: Arc<UdpSocket>, src: SocketAddr, req_buffer: BytePacketBuffer) -> Result<()> {
    let start_time = Instant::now();
    let req_packet = DnsPacket::from_buffer(&mut req_buffer.clone())?;
    
    let mut res_packet = DnsPacket::new();
    res_packet.header.id = req_packet.header.id;
    res_packet.header.recursion_desired = true;
    res_packet.header.recursion_available = true;
    res_packet.header.response = true;

    if let Some(question) = req_packet.questions.get(0) {
        if !is_valid_domain(&question.name) {
            eprintln!("Невалидное доменное имя в запросе: {}", question.name);
            res_packet.header.rescode = ResultCode::FORMERR;
        } else {
            res_packet.questions.push(question.clone());

            // Проверяем кеш
            {
                let cache = DNS_CACHE.read();
                if let Some((cached_packet, _, ttl)) = cache.get(&(question.name.clone(), question.qtype)) {
                    if start_time.elapsed().as_secs() < *ttl as u64 {
                        res_packet.answers = cached_packet.answers.clone();
                        res_packet.header.rescode = ResultCode::NOERROR;
                        DNS_CACHE_HITS_TOTAL.with_label_values(&[&question.qtype.to_string()]).inc();
                    }
                }
            }

            if res_packet.answers.is_empty() {
                DNS_CACHE_MISSES_TOTAL.with_label_values(&[&question.qtype.to_string()]).inc();
                
                let root_server = *ROOT_SERVERS.choose(&mut rand::thread_rng()).unwrap();

                match lookup(question.name.clone(), question.qtype, root_server, 0).await {
                    Ok(answers) => {
                        res_packet.header.rescode = ResultCode::NOERROR;
                        res_packet.answers = answers.answers.clone();
                        res_packet.header.answers = res_packet.answers.len() as u16;
                        
                        let ttl = answers
                            .answers
                            .iter()
                            .filter_map(|record| match record {
                                DnsRecord::A { ttl, .. } => Some(*ttl),
                                DnsRecord::CNAME { ttl, .. } => Some(*ttl),
                                DnsRecord::AAAA { ttl, .. } => Some(*ttl),
                                _ => None,
                            })
                            .min()
                            .unwrap_or(600);

                        let mut cache = DNS_CACHE.write();
                        cache.insert((question.name.clone(), question.qtype), (answers, Instant::now(), ttl));
                    }
                    Err(e) => {
                        eprintln!("Ошибка при разрешении домена '{}': {}", question.name, e);
                        res_packet.header.rescode = ResultCode::SERVFAIL;
                    }
                }
            }
        }
    } else {
        res_packet.header.rescode = ResultCode::FORMERR;
    }

    let mut res_buffer = BytePacketBuffer::new();
    res_packet.write(&mut res_buffer)?;

    let res_bytes = res_buffer.get_range(0, res_buffer.pos())?;
    
    socket.send_to(res_bytes, src).await?;

    let duration = start_time.elapsed();
    let result_label = if res_packet.header.rescode == ResultCode::NOERROR {
        "success"
    } else {
        "error"
    };

    DNS_QUERIES_TOTAL.with_label_values(&[result_label]).inc();
    DNS_QUERY_DURATION_SECONDS
        .with_label_values(&[result_label])
        .observe(duration.as_secs_f64());

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let exporter_addr = "0.0.0.0:9090".parse().unwrap();
    println!("Экспортер Prometheus запущен на {}", exporter_addr);
    tokio::spawn(async move {
        prometheus_exporter::start(exporter_addr).unwrap();
    });

    let socket = UdpSocket::bind(("0.0.0.0", 5300)).await?;
    let shared_socket = Arc::new(socket);
    println!("DNS-сервер запущен на порту 5300");

    let mut buffer = BytePacketBuffer::new();
    loop {
        let (len, src) = shared_socket.recv_from(&mut buffer.buf).await?;
        
        let req_buffer = buffer.clone();
        let socket_clone = Arc::clone(&shared_socket);
        tokio::spawn(async move {
            if let Err(e) = handle_query(socket_clone, src, req_buffer).await {
                eprintln!("Ошибка при обработке запроса: {}", e);
            }
        });
        
        buffer = BytePacketBuffer::new();
    }
}
