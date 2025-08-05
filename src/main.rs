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

// Константы
const ROOT_TIMEOUT_SECS: u64 = 2;

// Корневые DNS-серверы
const ROOT_SERVERS: &[Ipv4Addr] = &[
    Ipv4Addr::new(198, 41, 0, 4), // A
    Ipv4Addr::new(199, 9, 14, 201), // B
    Ipv4Addr::new(192, 33, 4, 12), // C
    Ipv4Addr::new(199, 7, 91, 13), // D
    Ipv4Addr::new(192, 203, 230, 10), // E
    Ipv4Addr::new(192, 5, 5, 241), // F
    Ipv4Addr::new(192, 112, 36, 4), // G
    Ipv4Addr::new(198, 97, 190, 53), // H
    Ipv4Addr::new(192, 36, 148, 17), // I
    Ipv4Addr::new(192, 58, 128, 30), // J
    Ipv4Addr::new(193, 0, 14, 129), // K
    Ipv4Addr::new(199, 7, 83, 42), // L
    Ipv4Addr::new(202, 12, 27, 33), // M
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
            eprintln!("[lookup] Max depth reached for {}", qname);
            return Err("Max lookup depth exceeded".into());
        }
        depth += 1;

        let mut packet = DnsPacket::new();
        packet.header.id = 6666;
        packet.header.recursion_desired = false;
        packet.header.questions = 1;
        packet.questions.push(DnsQuestion::new(qname.clone(), qtype));

        let mut req_buf = BytePacketBuffer::new();
        packet.write(&mut req_buf)?;
        let req_bytes = req_buf.get_range(0, req_buf.pos())?;

        let socket = UdpSocket::bind(("0.0.0.0", 0)).await?;
        socket.send_to(req_bytes, (current_nameserver, 53)).await?;

        let mut res_buf = BytePacketBuffer::new();
        let mut tmp = res_buf.buf;
        tokio::select! {
            res = socket.recv_from(&mut tmp) => {
                let (len, _) = res.map_err(|e| { eprintln!("[lookup] recv_from error: {}", e); e })?;
                res_buf.buf[..len].copy_from_slice(&tmp[..len]);
            }
            _ = sleep(Duration::from_secs(ROOT_TIMEOUT_SECS)) => {
                eprintln!("[lookup] timeout {}s on {}", ROOT_TIMEOUT_SECS, current_nameserver);
                current_nameserver = *ROOT_SERVERS.choose(&mut rand::thread_rng()).unwrap();
                continue;
            }
        }

        let res_packet = DnsPacket::from_buffer(&mut res_buf)?;
        if !res_packet.answers.is_empty() {
            return Ok(res_packet);
        }
        if res_packet.header.rescode == ResultCode::NXDOMAIN {
            eprintln!("[lookup] NXDOMAIN for {}", qname);
            return Err("Domain does not exist".into());
        }

        if let Some(cname) = res_packet.answers.iter().find_map(|rec| {
            if let DnsRecord::CNAME { domain, host, .. } = rec {
                if qname.ends_with(domain) { return Some(host.clone()); }
            }
            None
        }) {
            eprintln!("[lookup] CNAME {} -> {}", qname, cname);
            // if A available in answers or resources
            if let Some(ip) = res_packet.answers.iter().chain(res_packet.resources.iter()).find_map(|rec| {
                if let DnsRecord::A { domain, addr, .. } = rec {
                    if domain == &cname { return Some(addr); }
                }
                None
            }) {
                eprintln!("[lookup] A for CNAME {} -> {}", cname, ip);
                let mut pkt = DnsPacket::new();
                pkt.header = res_packet.header.clone();
                pkt.answers.push(DnsRecord::CNAME { domain: qname.clone(), host: cname.clone(), ttl: 0 });
                pkt.answers.push(DnsRecord::A { domain: cname.clone(), addr: *ip, ttl: 0 });
                return Ok(pkt);
            }
            qname = cname;
            continue;
        }

        if let Some(ns) = res_packet.authorities.iter().find_map(|rec| {
            if let DnsRecord::NS { domain, host, .. } = rec {
                if qname.ends_with(domain) { return Some(host.clone()); }
            }
            None
        }) {
            eprintln!("[lookup] NS {} for {}", ns, qname);
            if let Some(ip) = res_packet.resources.iter().find_map(|rec| {
                if let DnsRecord::A { domain, addr, .. } = rec {
                    if domain == &ns { return Some(addr); }
                }
                None
            }) {
                current_nameserver = *ip;
            } else {
                current_nameserver = ip;
            } else {
                let ns_pkt = lookup(ns.clone(), QueryType::A, current_nameserver).await?;
                if let Some(ip) = ns_pkt.get_random_a() { current_nameserver = ip; }
                else { eprintln!("[lookup] no A for NS {}", ns); return Err("Failed NS lookup".into()); }
            }
            continue;
        }

        eprintln!("[lookup] no answers/CNAME/NS for {}", qname);
        return Err("No usable records".into());
    }
}

async fn handle_query(socket: Arc<UdpSocket>, src: SocketAddr, buf: BytePacketBuffer) -> Result<()> {
    let start = Instant::now();
    let req = DnsPacket::from_buffer(&mut buf.clone())?;
    let mut resp = DnsPacket::new();
    resp.header.id = req.header.id;
    resp.header.response = true;
    resp.header.recursion_desired = true;
    resp.header.recursion_available = true;

    if let Some(q) = req.questions.get(0) {
        resp.questions.push(q.clone());
        let key = (q.name.clone(), q.qtype);
        if let Some((cached, t)) = DNS_CACHE.read().get(&key) {
            if t.elapsed() < Duration::from_secs(600) {
                eprintln!("[cache] HIT {}", q.name);
                resp.answers = cached.answers.clone();
                resp.header.rescode = ResultCode::NOERROR;
                DNS_CACHE_HITS_TOTAL.with_label_values(&["A"]).inc();
            }
        }
        if resp.answers.is_empty() {
            eprintln!("[cache] MISS {}", q.name);
            DNS_CACHE_MISSES_TOTAL.with_label_values(&["A"]).inc();
            let root = *ROOT_SERVERS.choose(&mut rand::thread_rng()).unwrap();
            match lookup(q.name.clone(), q.qtype, root).await {
                Ok(pkt) => {
                    resp.header.rescode = ResultCode::NOERROR;
                    resp.answers = pkt.answers.clone();
                    resp.header.answers = resp.answers.len() as u16;
                    DNS_CACHE.write().insert(key, (pkt, Instant::now()));
                }
                Err(e) => {
                    eprintln!("[handle] error {}: {}", q.name, e);
                    resp.header.rescode = ResultCode::SERVFAIL;
                }
            }
        }
    } else { resp.header.rescode = ResultCode::FORMERR; }

    let mut out = BytePacketBuffer::new();
    resp.write(&mut out)?;
    let data = out.get_range(0, out.pos())?;
    socket.send_to(data, src).await?;

    let dur = start.elapsed().as_secs_f64();
    let label = if resp.header.rescode == ResultCode::NOERROR { "success" } else { "error" };
    DNS_QUERIES_TOTAL.with_label_values(&[label]).inc();
    DNS_QUERY_DURATION_SECONDS.with_label_values(&[label]).observe(dur);
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let addr = "0.0.0.0:9090".parse().unwrap();
    println!("Prometheus on {}", addr);
    tokio::spawn(async move { prometheus_exporter::start(addr).unwrap(); });
    let sock = UdpSocket::bind(("0.0.0.0", 5300)).await?;
    let shared = Arc::new(sock);
    println!("DNS server on 5300");
    let mut buf = BytePacketBuffer::new();
    loop {
        let (len, src) = shared.recv_from(&mut buf.buf).await?;
        let clone_buf = buf.clone();
        let s = Arc::clone(&shared);
        tokio::spawn(async move { if let Err(e) = handle_query(s, src, clone_buf).await { eprintln!("[main] {}", e); } });
        buf = BytePacketBuffer::new();
    }
}
