use std::net::{Ipv4Addr, UdpSocket};
use std::time::Duration;

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

mod dns;

const ROOT_SERVER: Ipv4Addr = Ipv4Addr::new(198, 41, 0, 4);

fn lookup(qname: &str, qtype: QueryType) -> Result<DnsPacket> {
    let mut nameserver = ROOT_SERVER;
    let mut num_retries = 0;
    const MAX_RETRIES: u8 = 5;

    loop {
        if num_retries >= MAX_RETRIES {
            return Err("Max retries exceeded".into());
        }

        println!("Looking up '{}' on {}", qname, nameserver);

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

        let socket = UdpSocket::bind(("0.0.0.0", 43210))?;
        socket.set_read_timeout(Some(Duration::from_secs(3)))?;
        socket.send_to(req_bytes, (nameserver, 53))?;

        let mut res_buffer = BytePacketBuffer::new();
        let (_len, _src) = match socket.recv_from(&mut res_buffer.buf) {
            Ok(val) => val,
            Err(_) => {
                println!("Timeout, retrying...");
                num_retries += 1;
                continue;
            }
        };

        let res_packet = DnsPacket::from_buffer(&mut res_buffer)?;

        if !res_packet.answers.is_empty() {
            println!("Found an answer!");
            return Ok(res_packet);
        }

        if res_packet.header.rescode == ResultCode::NXDOMAIN {
            return Err("Domain does not exist".into());
        }
        
        // CNAME-записи всегда должны быть обработаны в первую очередь
        if let Some(cname_record) = res_packet.answers.iter().find_map(|rec| {
            if let DnsRecord::CNAME { domain, host, .. } = rec {
                if domain.ends_with(qname) {
                    return Some(host.clone());
                }
            }
            None
        }) {
            // Перезапускаем поиск с новым именем из CNAME
            println!("Received CNAME, restarting lookup for {}", cname_record);
            return lookup(&cname_record, qtype);
        }

        // If no answers, but there are NS records, follow a referral
        if let Some(ns_record) = res_packet.authorities.iter().find_map(|rec| {
            if let DnsRecord::NS { domain, host, .. } = rec {
                if qname.ends_with(domain) {
                    return Some(host.clone());
                }
            }
            None
        }) {
            // Check for a glue record in the additional section
            if let Some(a_record) = res_packet.resources.iter().find_map(|rec| {
                if let DnsRecord::A { domain, addr, .. } = rec {
                    if domain == &ns_record {
                        return Some(*addr);
                    }
                }
                None
            }) {
                // If we found a glue record, we can use it directly
                println!("Found glue record for NS: {}", a_record);
                nameserver = a_record;
            } else {
                // If no glue record, we need to do another lookup for the nameserver's IP
                println!("No glue record, doing recursive lookup for NS: {}", ns_record);
                let ns_ip_packet = lookup(&ns_record, QueryType::A)?;
                if let Some(ns_ip) = ns_ip_packet.get_random_a() {
                    nameserver = ns_ip;
                } else {
                    return Err(format!("Could not resolve NS record for {}", ns_record).into());
                }
            }
            num_retries = 0; // Reset retries on successful referral
            continue;
        }
        
        // If nothing else, try the next root server (or fail)
        return Err("No answers, CNAME, or NS records found".into());
    }
}

fn main() -> Result<()> {
    let qname = "www.google.com";
    match lookup(qname, QueryType::A) {
        Ok(packet) => {
            println!("\nResolved {}:", qname);
            for rec in packet.answers.iter() {
                if let DnsRecord::A { addr, .. } = rec {
                    println!("-> A: {}", addr);
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to resolve {}: {}", qname, e);
        }
    }

    Ok(())
}
