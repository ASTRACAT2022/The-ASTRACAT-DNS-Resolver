use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use crate::dns::{
    byte_packet_buffer::BytePacketBuffer,
    dns_packet::DnsPacket,
    dns_question::DnsQuestion,
    dns_record::DnsRecord,
    query_type::QueryType,
    result_code::ResultCode,
    Result,
};
use tokio::net::UdpSocket;
use tokio::time::timeout;
use async_recursion::async_recursion;

mod dns;

const ROOT_SERVER: Ipv4Addr = Ipv4Addr::new(198, 41, 0, 4);

#[async_recursion]
async fn lookup(mut qname: String, qtype: QueryType) -> Result<DnsPacket> {
    let mut nameserver = ROOT_SERVER;
    const MAX_DEPTH: u8 = 10;
    let mut depth = 0;

    loop {
        if depth >= MAX_DEPTH {
            return Err("Превышена максимальная глубина поиска.".into());
        }
        depth += 1;

        // println!("Выполняем поиск '{}' на сервере {}", qname, nameserver);

        let mut packet = DnsPacket::new();
        packet.header.id = 6666;
        packet.header.recursion_desired = false;
        packet.header.questions = 1;
        packet
            .questions
            .push(DnsQuestion::new(qname.clone(), qtype));

        let mut req_buffer = BytePacketBuffer::new();
        packet.write(&mut req_buffer)?;
        let req_bytes = req_buffer.get_range(0, req_buffer.pos())?;

        let socket = UdpSocket::bind(("0.0.0.0", 0)).await?;
        socket.send_to(req_bytes, (nameserver, 53)).await?;

        let mut res_buffer = BytePacketBuffer::new();
        let res = timeout(Duration::from_secs(3), socket.recv_from(&mut res_buffer.buf)).await;

        let (_len, _src) = match res {
            Ok(Ok(val)) => val,
            Ok(Err(e)) => return Err(format!("Ошибка сокета: {}", e).into()),
            Err(_) => {
                // println!("Тайм-аут, повторяем...");
                continue;
            }
        };

        let res_packet = DnsPacket::from_buffer(&mut res_buffer)?;

        if !res_packet.answers.is_empty() {
            // println!("Найден ответ!");
            return Ok(res_packet);
        }

        if res_packet.header.rescode == ResultCode::NXDOMAIN {
            return Err("Домен не существует.".into());
        }

        // Итеративная обработка CNAME
        if let Some(cname_record) = res_packet.answers.iter().find_map(|rec| {
            if let DnsRecord::CNAME { domain, host, .. } = rec {
                if qname.ends_with(domain) {
                    return Some(host.clone());
                }
            }
            None
        }) {
            // println!("Получен CNAME, обновляем имя для поиска: {}", cname_record);
            qname = cname_record;
            // Переходим на следующую итерацию с новым именем
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
                // println!("Найдена 'клейкая запись' для NS: {}", a_record);
                nameserver = a_record;
            } else {
                // println!("'Клейкой записи' нет, выполняем рекурсивный поиск для NS: {}", ns_record);
                let ns_ip_packet = lookup(ns_record.clone(), QueryType::A).await?;
                if let Some(ns_ip) = ns_ip_packet.get_random_a() {
                    nameserver = ns_ip;
                } else {
                    return Err(format!("Не удалось разрешить NS-запись для {}", ns_record).into());
                }
            }
            continue;
        }

        return Err("Не найдено ответов, CNAME или NS-записей.".into());
    }
}

async fn handle_query(socket: Arc<UdpSocket>, src: SocketAddr, req_buffer: BytePacketBuffer) -> Result<()> {
    let req_packet = DnsPacket::from_buffer(&mut req_buffer.clone())?;
    
    let mut res_packet = DnsPacket::new();
    res_packet.header.id = req_packet.header.id;
    res_packet.header.recursion_desired = true;
    res_packet.header.recursion_available = true;
    res_packet.header.response = true;

    if let Some(question) = req_packet.questions.get(0) {
        // println!("Получен запрос от {} для домена '{}'", src, question.name);
        res_packet.questions.push(question.clone());

        match lookup(question.name.clone(), question.qtype).await {
            Ok(answers) => {
                res_packet.header.rescode = ResultCode::NOERROR;
                res_packet.answers = answers.answers;
                res_packet.header.answers = res_packet.answers.len() as u16;
            }
            Err(e) => {
                eprintln!("Ошибка при разрешении домена '{}': {}", question.name, e);
                res_packet.header.rescode = ResultCode::SERVFAIL;
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
