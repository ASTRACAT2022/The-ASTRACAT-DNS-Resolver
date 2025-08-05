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
        register_counter_vec, register_histogram_vec, register_gauge, CounterVec, HistogramVec,
        Gauge,
    },
};

// --- Предполагаем, что у модуля dns есть эти компоненты ---
// Я добавил поле `ttl` в DnsRecord для корректного кеширования.
mod dns {
    use std::net::Ipv4Addr;
    pub use self::byte_packet_buffer::BytePacketBuffer;
    pub use self::dns_packet::DnsPacket;
    pub use self::dns_question::DnsQuestion;
    pub use self::dns_record::DnsRecord;
    pub use self::query_type::QueryType;
    pub use self::result_code::ResultCode;
    pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
    
    // Подключаем остальные модули (заглушки для компиляции)
    pub mod byte_packet_buffer {
        use super::*;
        #[derive(Clone)]
        pub struct BytePacketBuffer { pub buf: [u8; 512], pub pos: usize }
        impl BytePacketBuffer {
            pub fn new() -> Self { BytePacketBuffer { buf: [0; 512], pos: 0 } }
            pub fn pos(&self) -> usize { self.pos }
            pub fn get_range(&self, start: usize, len: usize) -> Result<&[u8]> { Ok(&self.buf[start..start+len]) }
        }
    }
    pub mod dns_packet {
        use super::*;
        #[derive(Clone, Debug)]
        pub struct DnsHeader { pub id: u16, pub recursion_desired: bool, pub recursion_available: bool, pub response: bool, pub questions: u16, pub answers: u16, pub rescode: ResultCode }
        impl DnsHeader { pub fn new() -> Self { DnsHeader { id: 0, recursion_desired: false, recursion_available: false, response: false, questions: 0, answers: 0, rescode: ResultCode::NOERROR } } }
        #[derive(Clone, Debug)]
        pub struct DnsPacket { pub header: DnsHeader, pub questions: Vec<DnsQuestion>, pub answers: Vec<DnsRecord>, pub authorities: Vec<DnsRecord>, pub resources: Vec<DnsRecord> }
        impl DnsPacket {
            pub fn new() -> Self { DnsPacket { header: DnsHeader::new(), questions: Vec::new(), answers: Vec::new(), authorities: Vec::new(), resources: Vec::new() } }
            pub fn from_buffer(_buffer: &mut BytePacketBuffer) -> Result<Self> { /* ... */ Ok(DnsPacket::new()) }
            pub fn write(&self, _buffer: &mut BytePacketBuffer) -> Result<()> { /* ... */ Ok(()) }
            pub fn get_random_a(&self) -> Option<Ipv4Addr> {
                 self.answers.iter().find_map(|record| match record {
                    DnsRecord::A { addr, .. } => Some(*addr),
                    _ => None
                })
            }
        }
    }
    pub mod dns_question {
        use super::*;
        #[derive(Clone, Debug, PartialEq, Eq, Hash)]
        pub struct DnsQuestion { pub name: String, pub qtype: QueryType }
        impl DnsQuestion { pub fn new(name: String, qtype: QueryType) -> Self { DnsQuestion { name, qtype } } }
    }
    #[allow(dead_code)]
    pub mod dns_record {
        use super::*;
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub enum DnsRecord {
            A { domain: String, addr: Ipv4Addr, ttl: u32 },
            NS { domain: String, host: String, ttl: u32 },
            CNAME { domain: String, host: String, ttl: u32 },
            UNKNOWN,
        }
        impl DnsRecord {
            pub fn ttl(&self) -> u32 {
                match self {
                    DnsRecord::A { ttl, .. } | DnsRecord::NS { ttl, .. } | DnsRecord::CNAME { ttl, .. } => *ttl,
                    DnsRecord::UNKNOWN => 0,
                }
            }
        }
    }
    pub mod query_type {
        #[derive(PartialEq, Eq, Debug, Clone, Copy, Hash)]
        pub enum QueryType { A = 1, NS = 2, CNAME = 5 }
        impl From<QueryType> for u16 { fn from(val: QueryType) -> Self { val as u16 } }
    }
    pub mod result_code {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum ResultCode { NOERROR = 0, FORMERR = 1, SERVFAIL = 2, NXDOMAIN = 3 }
        impl From<ResultCode> for u16 { fn from(val: ResultCode) -> u16 { val as u16 } }
    }
}
// --- Конец заглушек ---


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

// ДОБАВЛЕНО: Тип значения в кеше теперь включает время истечения срока действия, а не время вставки.
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
            return Err("Превышена максимальная глубина поиска.".into());
        }
        depth += 1;

        println!("(Глубина {}) Запрос {} {:?} на {}", depth, qname, qtype, current_nameserver);

        let mut packet = DnsPacket::new();
        packet.header.id = rand::random(); // Используем случайный ID
        packet.header.recursion_desired = false;
        packet.header.questions = 1;
        packet.questions.push(DnsQuestion::new(qname.clone(), qtype));

        let mut req_buffer = BytePacketBuffer::new();
        packet.write(&mut req_buffer)?;
        let req_bytes = req_buffer.get_range(0, req_buffer.pos())?;

        let socket = UdpSocket::bind(("0.0.0.0", 0)).await?;
        socket.send_to(req_bytes, (current_nameserver, 53)).await?;

        let mut res_buffer = BytePacketBuffer::new();
        let res = timeout(Duration::from_secs(3), socket.recv_from(&mut res_buffer.buf)).await;

        let (_len, _src) = match res {
            Ok(Ok(val)) => val,
            Ok(Err(e)) => return Err(format!("Ошибка сокета: {}", e).into()),
            Err(_) => {
                // ИЗМЕНЕНО: Обработка таймаута теперь более явная.
                // В реальном мире здесь нужно было бы пробовать другой NS-сервер из списка,
                // а не сразу откатываться к корневому. Но для простоты пока оставим так.
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

        if let Some(cname_record) = res_packet.answers.iter().find_map(|rec| {
            if let DnsRecord::CNAME { domain, host, .. } = rec {
                if qname.eq_ignore_ascii_case(domain) {
                    return Some(host.clone());
                }
            }
            None
        }) {
            qname = cname_record;
            // Начинаем разрешение CNAME с начала (с корневых серверов)
            let root_server = *ROOT_SERVERS.choose(&mut rand::thread_rng()).unwrap();
            current_nameserver = root_server;
            continue;
        }

        if let Some(ns_ip) = res_packet.get_ns_ip_from_additional(&qname) {
            current_nameserver = ns_ip;
            continue;
        }
        
        if let Some(ns_host) = res_packet.get_authoritative_ns(&qname) {
            // ИЗМЕНЕНО: Ключевое исправление!
            // Если мы получили имя NS-сервера (например, ns1.google.com), но не его IP,
            // мы должны разрешить это имя, НАЧАВ С КОРНЕВОГО СЕРВЕРА.
            let root_server = *ROOT_SERVERS.choose(&mut rand::thread_rng()).unwrap();
            let ns_ip_packet = lookup(ns_host.clone(), QueryType::A, root_server).await?;
            
            if let Some(ns_ip) = ns_ip_packet.get_random_a() {
                current_nameserver = ns_ip;
                // Продолжаем цикл с новым сервером имен для ИСХОДНОГО домена
                continue;
            } else {
                return Err(format!("Не удалось разрешить IP для NS-сервера {}", ns_host).into());
            }
        }


        // Если мы здесь, значит, мы не получили ни ответа, ни следующего шага.
        return Err("Не найдено ответов или авторитативных серверов для продолжения.".into());
    }
}


// ДОБАВЛЕНО: Вспомогательные функции для DnsPacket, чтобы сделать код чище
// Помести их в реализацию `impl DnsPacket` в твоем модуле `dns_packet`
impl DnsPacket {
    /// Ищет IP-адрес для NS-сервера в дополнительной секции (glue record)
    fn get_ns_ip_from_additional(&self, qname: &str) -> Option<Ipv4Addr> {
        self.authorities
            .iter()
            .filter_map(|rec| match rec {
                DnsRecord::NS { domain, host, .. } if qname.ends_with(domain) => Some(host),
                _ => None,
            })
            .flat_map(|ns_host| {
                self.resources.iter().filter_map(move |rec| match rec {
                    DnsRecord::A { domain, addr, .. } if domain == ns_host => Some(*addr),
                    _ => None,
                })
            })
            .next()
    }
    
    /// Ищет имя авторитативного сервера в секции authorities
    fn get_authoritative_ns(&self, qname: &str) -> Option<String> {
        self.authorities
            .iter()
            .find_map(|rec| match rec {
                 DnsRecord::NS { domain, host, .. } if qname.ends_with(domain) => Some(host.clone()),
                _ => None,
            })
    }
}


async fn handle_query(socket: Arc<UdpSocket>, src: SocketAddr, mut req_buffer: BytePacketBuffer) -> Result<()> {
    let start_time = Instant::now();
    let req_packet = DnsPacket::from_buffer(&mut req_buffer)?;

    let mut res_packet = DnsPacket::new();
    res_packet.header.id = req_packet.header.id;
    res_packet.header.recursion_desired = true;
    res_packet.header.recursion_available = true;
    res_packet.header.response = true;

    if let Some(question) = req_packet.questions.get(0).cloned() {
        res_packet.questions.push(question.clone());

        // ИЗМЕНЕНО: Логика кеширования теперь использует TTL
        let mut served_from_cache = false;
        {
            let cache = DNS_CACHE.read();
            if let Some((cached_packet, expiry_time)) = cache.get(&(question.name.clone(), question.qtype)) {
                // Проверяем, не истекло ли время жизни кеша
                if Instant::now() < *expiry_time {
                    println!("Ответ для {} из кеша", question.name);
                    res_packet.answers = cached_packet.answers.clone();
                    res_packet.header.rescode = cached_packet.header.rescode;
                    DNS_CACHE_HITS_TOTAL.with_label_values(&["A"]).inc();
                    served_from_cache = true;
                }
            }
        }
        
        if !served_from_cache {
            DNS_CACHE_MISSES_TOTAL.with_label_values(&["A"]).inc();
            
            let root_server = *ROOT_SERVERS.choose(&mut rand::thread_rng()).unwrap();
            match lookup(question.name.clone(), question.qtype, root_server).await {
                Ok(lookup_result) => {
                    res_packet.header.rescode = lookup_result.header.rescode;
                    res_packet.answers = lookup_result.answers.clone();
                    res_packet.header.answers = res_packet.answers.len() as u16;
                    
                    // ИЗМЕНЕНО: Добавляем в кеш с правильным TTL
                    // Находим минимальный TTL среди всех записей в ответе
                    let min_ttl = lookup_result.answers
                        .iter()
                        .map(|rec| rec.ttl())
                        .min()
                        .unwrap_or(0); // Если ответов нет (например, NXDOMAIN), кешируем на 0 секунд

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
    // Запускаем экспортер Prometheus
    let exporter_addr = "0.0.0.0:9090".parse().unwrap();
    println!("Экспортер Prometheus запущен на {}", exporter_addr);
    tokio::spawn(async move {
        prometheus_exporter::start(exporter_addr).unwrap();
    });

    let socket = UdpSocket::bind(("0.0.0.0", 5300)).await?;
    let shared_socket = Arc::new(socket);
    println!("DNS-сервер запущен на порту 5300");

    loop {
        // ИЗМЕНЕНО: создаем новый буфер для каждого запроса, чтобы избежать гонки данных
        let mut buffer = [0u8; 512];
        let (_len, src) = shared_socket.recv_from(&mut buffer).await?;
        
        let mut req_buffer = BytePacketBuffer::new();
        req_buffer.buf[.._len].copy_from_slice(&buffer[.._len]);

        let socket_clone = Arc::clone(&shared_socket);
        tokio::spawn(async move {
            if let Err(e) = handle_query(socket_clone, src, req_buffer).await {
                eprintln!("Ошибка при обработке запроса: {}", e);
            }
        });
    }
}
