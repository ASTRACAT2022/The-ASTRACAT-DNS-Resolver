use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::collections::HashMap;
use tokio::net::UdpSocket;
use tokio::time::sleep;
use rand::seq::SliceRandom;
use async_recursion::async_recursion;
use lazy_static::lazy_static;
use prometheus_exporter::{
    self,
    prometheus::{
        register_counter_vec, register_histogram_vec, register_gauge, CounterVec, HistogramVec,
        Gauge,
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

// Константы
const ROOT_TIMEOUT_SECS: u64 = 2; // Уменьшенный таймаут для запросов к корневым серверам

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
    static ref DNS_CACHE: Arc<parking_lot::RwLock<HashMap<(String, QueryType), (DnsPacket, Instant)>>> =
        Arc::new(parking_lot::RwLock::new(HashMap::new()));
}

#[async_recursion]
async fn lookup(mut qname: String, qtype: QueryType, nameserver: Ipv4Addr) -> Result<DnsPacket> {
    const MAX_DEPTH: u8 = 10;
    let mut depth = 0;
    let mut current_nameserver = nameserver;

    loop {
        if depth >= MAX_DEPTH {
            eprintln!("[lookup] Превышена максимальная глубина поиска для {}", qname);
            return Err("Превышена максимальная глубина поиска.".into());
        }
        depth += 1;

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

        // Таймаут через select!
        let mut res_buffer = BytePacketBuffer::new();
        let mut buf = res_buffer.buf;
        tokio::select! {
            recv = socket.recv_from(&mut buf) => {
                let (len, _src) = recv.map_err(|e| {
                    eprintln!("[lookup] Ошибка recv_from: {}", e);
                    e
                })?;
                res_buffer.buf[..len].copy_from_slice(&buf[..len]);
            }
            _ = sleep(Duration::from_secs(ROOT_TIMEOUT_SECS)) => {
                eprintln!("[lookup] Таймаут {}с при запросе к {}", ROOT_TIMEOUT_SECS, current_nameserver);
                current_nameserver = *ROOT_SERVERS.choose(&mut rand::thread_rng()).unwrap();
                continue;
            }
        }

        let res_packet = DnsPacket::from_buffer(&mut res_buffer)?;

        if !res_packet.answers.is_empty() {
            return Ok(res_packet);
        }

        if res_packet.header.rescode == ResultCode::NXDOMAIN {
            eprintln!("[lookup] NXDOMAIN для {}", qname);
            return Err("Домен не существует.".into());
        }

        if let Some(cname_record) = res_packet.answers.iter().find_map(|rec| {
            if let DnsRecord::CNAME { domain, host, .. } = rec {
                if qname.ends_with(domain) {
                    return Some(host.clone());
                }
            }
            None
        }) {
            eprintln!("[lookup] CNAME: {} -> {}", qname, cname_record);
            qname = cname_record.clone();
            // Попытаться найти A-запись для CNAME в ответах и additional (цепочка CNAME)
            if let Some(a_addr) = res_packet.answers.iter().chain(res_packet.additional.iter()).find_map(|rec| {
                if let DnsRecord::A { domain, addr, .. } = rec {
                    if domain == &cname_record {
                        return Some(*addr);
                    }
                }
                None
            }) {
                eprintln!("[lookup] Найдена A-запись для CNAME {} -> {}", cname_record, a_addr);
                // Возвращаем пакет с цепочкой CNAME и A
                let mut final_pkt = DnsPacket::new();
                final_pkt.header = res_packet.header.clone();
                final_pkt.answers.push(DnsRecord::CNAME { domain: qname.clone(), host: cname_record.clone(), ttl: 0 });
                final_pkt.answers.push(DnsRecord::A { domain: cname_record.clone(), addr: a_addr, ttl: 0 });
                return Ok(final_pkt);
            }
            continue;
        }
        }

        if let Some(ns_record) = res_packet.authorities.iter().find_map(|rec| {
            if let DnsRecord::NS { domain, host, .. } = rec {
                if qname.ends_with(domain) {
                    return Some(host.clone());
                }
            }
            None
        }) {
            eprintln!("[lookup] NS найден: {} для {}", ns_record, qname);
            if let Some(a_record) = res_packet.resources.iter().chain(res_packet.additional.iter()).find_map(|rec| {
                if let DnsRecord::A { domain, addr, .. } = rec {
                    if domain == &ns_record {
                        return Some(*addr);
                    }
                }
                None
            }) {
                current_nameserver = a_record;
            } else {
                let ns_ip_packet = lookup(ns_record.clone(), QueryType::A, current_nameserver).await?;
                if let Some(ns_ip) = ns_ip_packet.get_random_a() {
                    current_nameserver = ns_ip;
                } else {
                    eprintln!("[lookup] Не удалось разрешить NS-запись для {}", ns_record);
                    return Err(format!("Не удалось разрешить NS-запись для {}", ns_record).into());
                }
            }
            continue;
        }

        eprintln!("[lookup] Не найдено ответов, CNAME или NS-записей для {}", qname);
        return Err("Не найдено ответов, CNAME или NS-записей.".into());
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
        res_packet.questions.push(question.clone());

        // Проверяем кеш
        {
            let cache = DNS_CACHE.read();
            if let Some((cached_packet, expiry)) = cache.get(&(question.name.clone(), question.qtype)) {
                if expiry.elapsed() < Duration::from_secs(600) {
                    eprintln!("[cache] HIT для {}", question.name);
                    res_packet.answers = cached_packet.answers.clone();
                    res_packet.header.rescode = ResultCode::NOERROR;
                    DNS_CACHE_HITS_TOTAL.with_label_values(&["A"]).inc();
                }
            }
        }

        if res_packet.answers.is_empty() {
            eprintln!("[cache] MISS для {}", question.name);
            DNS_CACHE_MISSES_TOTAL.with_label_values(&["A"]).inc();
            
            let root_server = *ROOT_SERVERS.choose(&mut rand::thread_rng()).unwrap();

            match lookup(question.name.clone(), question.qtype, root_server).await {
                Ok(answers) => {
                    res_packet.header.rescode = ResultCode::NOERROR;
                    res_packet.answers = answers.answers.clone();
                    res_packet.header.answers = res_packet.answers.len() as u16;
                    
                    let mut cache = DNS_CACHE.write();
                    cache.insert((question.name.clone(), question.qtype), (answers, Instant::now()));
                }
                Err(e) => {
                    eprintln!("[handle_query] Ошибка при разрешении '{}': {}", question.name, e);
                    res_packet.header.rescode = ResultCode::SERVFAIL;
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
                eprintln!("[main] Ошибка при обработке запроса: {}", e);
            }
        });
        
        buffer = BytePacketBuffer::new();
    }
}
