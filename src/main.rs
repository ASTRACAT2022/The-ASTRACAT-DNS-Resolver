use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::collections::HashMap;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use rand::seq::SliceRandom;
use async_recursion::async_recursion;

// Используем ваши модули из папки 'dns'
mod dns;

use dns::{
    byte_packet_buffer::BytePacketBuffer, dns_packet::DnsPacket, dns_question::DnsQuestion,
    dns_record::DnsRecord, query_type::QueryType, result_code::ResultCode, Result,
};

// Корневые DNS-серверы
const ROOT_SERVERS: &[Ipv4Addr] = &[
    Ipv4Addr::new(198, 41, 0, 4),   // A
    Ipv4Addr::new(199, 9, 14, 201), // B
    Ipv4Addr::new(192, 33, 4, 12),  // C
    Ipv4Addr::new(199, 7, 91, 13),  // D
    Ipv4Addr::new(192, 203, 230, 10),// E
    Ipv4Addr::new(192, 5, 5, 241),  // F
    Ipv4Addr::new(192, 112, 36, 4), // G
    Ipv4Addr::new(198, 97, 190, 53),// H
    Ipv4Addr::new(192, 36, 148, 17),// I
    Ipv4Addr::new(192, 58, 128, 30),// J
    Ipv4Addr::new(193, 0, 14, 129), // K
    Ipv4Addr::new(199, 7, 83, 42),  // L
    Ipv4Addr::new(202, 12, 27, 33), // M
];

// Кэш для ускорения
lazy_static::lazy_static! {
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
            return Err("Превышена максимальная глубина поиска.".into());
        }
        depth += 1;

        println!("(Глубина {}) Запрос {} {:?} на {}", depth, qname, qtype, current_nameserver);

        let mut packet = DnsPacket::new();
        packet.header.id = rand::random();
        packet.header.recursion_desired = false;
        packet.questions.push(DnsQuestion::new(qname.clone(), qtype));

        let mut req_buffer = BytePacketBuffer::new();
        packet.write(&mut req_buffer)?;
        let req_bytes = req_buffer.get_range(0, req_buffer.pos())?;

        let socket = UdpSocket::bind(("0.0.0.0", 0)).await?;
        socket.send_to(req_bytes, (current_nameserver, 53)).await?;

        let mut res_buffer = BytePacketBuffer::new();
        let res = timeout(Duration::from_secs(3), socket.recv_from(&mut res_buffer.buf)).await;

        let (_len, _src) = match res {
            Ok(Ok(val)) => {
                res_buffer.pos = val.0;
                val
            },
            Ok(Err(e)) => return Err(format!("Ошибка сокета: {}", e).into()),
            Err(_) => {
                println!("Тайм-аут при запросе к {}", current_nameserver);
                return Err(format!("Тайм-аут при запросе к {}", current_nameserver).into());
            }
        };
        
        let res_packet = DnsPacket::from_buffer(&mut res_buffer)?;
        
        if !res_packet.answers.is_empty() {
            return Ok(res_packet);
        }

        if res_packet.header.rescode == ResultCode::NXDOMAIN {
            return Err("Домен не существует (NXDOMAIN).".into());
        }

        // Если в ответе есть запись CNAME, повторяем поиск для нового имени
        if let Some(cname_record) = res_packet.answers.iter().find_map(|rec| {
            if let DnsRecord::CNAME { domain, host, .. } = rec {
                if qname.eq_ignore_ascii_case(domain) {
                    return Some(host.clone());
                }
            }
            None
        }) {
            qname = cname_record;
            let root_server = *ROOT_SERVERS.choose(&mut rand::thread_rng()).unwrap();
            current_nameserver = root_server;
            continue;
        }

        // Ищем IP-адрес для NS-сервера в дополнительной секции
        if let Some(ns_ip) = res_packet.get_ns_ip_from_additional(&qname) {
            current_nameserver = ns_ip;
            continue;
        }
        
        // Ищем имя авторитативного сервера и выполняем новый поиск для его IP
        if let Some(ns_host) = res_packet.get_authoritative_ns(&qname) {
            let root_server = *ROOT_SERVERS.choose(&mut rand::thread_rng()).unwrap();
            let ns_ip_packet = lookup(ns_host.clone(), QueryType::A, root_server).await?;
            
            if let Some(ns_ip) = ns_ip_packet.get_random_a() {
                current_nameserver = ns_ip;
                continue;
            } else {
                return Err(format!("Не удалось разрешить IP для NS-сервера {}", ns_host).into());
            }
        }

        return Err("Не найдено ответов или авторитативных серверов для продолжения.".into());
    }
}


async fn handle_query(socket: Arc<UdpSocket>, src: SocketAddr, mut req_buffer: BytePacketBuffer) -> Result<()> {
    let req_packet = DnsPacket::from_buffer(&mut req_buffer)?;
    
    let mut res_packet = DnsPacket::new();
    res_packet.header.id = req_packet.header.id;
    res_packet.header.recursion_desired = true;
    res_packet.header.recursion_available = true;
    res_packet.header.response = true;

    if let Some(question) = req_packet.questions.get(0).cloned() {
        res_packet.questions.push(question.clone());

        let mut served_from_cache = false;
        {
            let cache = DNS_CACHE.read();
            if let Some((cached_packet, expiry_time)) = cache.get(&(question.name.clone(), question.qtype)) {
                if Instant::now() < *expiry_time {
                    println!("Ответ для {} из кеша", question.name);
                    res_packet.answers = cached_packet.answers.clone();
                    res_packet.header.rescode = cached_packet.header.rescode;
                    served_from_cache = true;
                }
            }
        }
        
        if !served_from_cache {
            let root_server = *ROOT_SERVERS.choose(&mut rand::thread_rng()).unwrap();
            match lookup(question.name.clone(), question.qtype, root_server).await {
                Ok(lookup_result) => {
                    res_packet.header.rescode = lookup_result.header.rescode;
                    res_packet.answers = lookup_result.answers.clone();
                    res_packet.header.answers = res_packet.answers.len() as u16;
                    
                    // Исправлено: Используем сопоставление с образцом для получения TTL
                    let min_ttl = lookup_result
                        .answers
                        .iter()
                        .filter_map(|rec| match rec {
                            DnsRecord::A { ttl, .. } => Some(*ttl),
                            DnsRecord::AAAA { ttl, .. } => Some(*ttl),
                            DnsRecord::CNAME { ttl, .. } => Some(*ttl),
                            DnsRecord::MX { ttl, .. } => Some(*ttl),
                            DnsRecord::NS { ttl, .. } => Some(*ttl),
                            DnsRecord::UNKNOWN { ttl, .. } => Some(*ttl),
                        })
                        .min()
                        .unwrap_or(0);

                    if min_ttl > 0 {
                        let expiry_time = Instant::now() + Duration::from_secs(min_ttl as u64);
                        let mut cache = DNS_CACHE.write();
                        println!("Кешируем {} на {} секунд", question.name, min_ttl);
                        cache.insert(
                            (question.name.clone(), question.qtype),
                            (lookup_result, expiry_time)
                        );
                    }
                }
                Err(e) => {
                    eprintln!("Ошибка при разрешении домена '{}': {}", question.name, e);
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

    Ok(())
}


#[tokio::main]
async fn main() -> Result<()> {
    let socket = UdpSocket::bind(("0.0.0.0", 5300)).await?;
    let shared_socket = Arc::new(socket);
    println!("DNS-сервер запущен на порту 5300");

    loop {
        let mut buffer = [0u8; 512];
        let (_len, src) = shared_socket.recv_from(&mut buffer).await?;
        
        let mut req_buffer = BytePacketBuffer::new();
        req_buffer.buf[.._len].copy_from_slice(&buffer[.._len]);
        req_buffer.pos = _len;

        let socket_clone = Arc::clone(&shared_socket);
        tokio::spawn(async move {
            if let Err(e) = handle_query(socket_clone, src, req_buffer).await {
                eprintln!("Ошибка при обработке запроса: {}", e);
            }
        });
    }
}
