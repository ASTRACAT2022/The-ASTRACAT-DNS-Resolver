use std::net::{Ipv4Addr, SocketAddr};

use crate::dns::{
    byte_packet_buffer::BytePacketBuffer,
    dns_header::DnsHeader,
    dns_packet::DnsPacket,
    dns_question::DnsQuestion,
    dns_record::DnsRecord,
    query_type::QueryType,
    result_code::ResultCode,
    Result,
};
use tokio::net::UdpSocket;

mod dns;

const ROOT_SERVER: Ipv4Addr = Ipv4Addr::new(198, 41, 0, 4);

// Логика итеративного поиска, которая была в предыдущей версии main.rs
async fn lookup(qname: &str, qtype: QueryType) -> Result<DnsPacket> {
    let mut nameserver = ROOT_SERVER;
    let mut num_retries = 0;
    const MAX_RETRIES: u8 = 5;

    loop {
        if num_retries >= MAX_RETRIES {
            return Err("Превышено максимальное количество попыток".into());
        }

        println!("Выполняем поиск '{}' на сервере {}", qname, nameserver);

        let mut packet = DnsPacket::new();
        packet.header.id = 6666;
        packet.header.recursion_desired = false;
        packet.header.questions = 1;
        packet
            .questions
            .push(DnsQuestion::new(qname.to_string(), qtype));

        let mut req_buffer = BytePacketBuffer::new();
        packet.write(&mut req_buffer)?;
        let req_bytes = req_buffer.get_range(0, req_buffer.pos())?;

        let socket = UdpSocket::bind(("0.0.0.0", 0)).await?;
        socket.send_to(req_bytes, (nameserver, 53)).await?;

        let mut res_buffer = BytePacketBuffer::new();
        let (_len, _src) = match tokio::time::timeout(std::time::Duration::from_secs(3), socket.recv_from(&mut res_buffer.buf)).await {
            Ok(val) => val,
            Err(_) => {
                println!("Тайм-аут, повторяем...");
                num_retries += 1;
                continue;
            }
        };

        let res_packet = DnsPacket::from_buffer(&mut res_buffer)?;

        if !res_packet.answers.is_empty() {
            println!("Найден ответ!");
            return Ok(res_packet);
        }

        if res_packet.header.rescode == ResultCode::NXDOMAIN {
            return Err("Домен не существует".into());
        }
        
        if let Some(cname_record) = res_packet.answers.iter().find_map(|rec| {
            if let DnsRecord::CNAME { domain, host, .. } = rec {
                if qname.ends_with(domain) {
                    return Some(host.clone()); 
                }
            }
            None
        }) {
            println!("Получен CNAME, перезапускаем поиск для {}", cname_record);
            return lookup(&cname_record, qtype).await;
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
                println!("Найдена 'клейкая запись' для NS: {}", a_record);
                nameserver = a_record;
            } else {
                println!("'Клейкой записи' нет, выполняем рекурсивный поиск для NS: {}", ns_record);
                let ns_ip_packet = lookup(&ns_record, QueryType::A).await?;
                if let Some(ns_ip) = ns_ip_packet.get_random_a() {
                    nameserver = ns_ip;
                } else {
                    return Err(format!("Не удалось разрешить NS-запись для {}", ns_record).into());
                }
            }
            num_retries = 0;
            continue;
        }
        
        return Err("Не найдено ответов, CNAME или NS-записей".into());
    }
}


async fn handle_query(socket: &UdpSocket, src: SocketAddr, req_buffer: BytePacketBuffer) -> Result<()> {
    // Парсим входящий запрос
    let req_packet = DnsPacket::from_buffer(&mut req_buffer.clone())?;
    
    let mut res_packet = DnsPacket::new();
    res_packet.header.id = req_packet.header.id;
    res_packet.header.recursion_desired = true;
    res_packet.header.recursion_available = true;
    res_packet.header.response = true;

    // Для каждого вопроса в запросе пытаемся найти ответ
    if let Some(question) = req_packet.questions.get(0) {
        println!("Получен запрос от {} для домена '{}'", src, question.name);

        res_packet.questions.push(question.clone());

        match lookup(&question.name, question.qtype).await {
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
        // Если в запросе нет вопросов, возвращаем FORMERR
        res_packet.header.rescode = ResultCode::FORMERR;
    }

    // Отправляем ответ обратно клиенту
    let mut res_buffer = BytePacketBuffer::new();
    res_packet.write(&mut res_buffer)?;

    let res_bytes = res_buffer.get_range(0, res_buffer.pos())?;
    socket.send_to(res_bytes, src).await?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let socket = UdpSocket::bind(("0.0.0.0", 53)).await?;
    println!("DNS-сервер запущен на порту 53");

    let mut buffer = BytePacketBuffer::new();
    loop {
        // Ожидаем входящий запрос
        let (len, src) = socket.recv_from(&mut buffer.buf).await?;

        // Создаем новую задачу (task) для асинхронной обработки запроса
        let local_socket = socket.clone();
        let local_buffer = buffer.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_query(&local_socket, src, local_buffer).await {
                eprintln!("Ошибка при обработке запроса: {}", e);
            }
        });
        
        // Сбрасываем буфер для следующего запроса
        buffer = BytePacketBuffer::new();
    }
}
