use std::net::Ipv4Addr;
use rand::seq::SliceRandom;

use super::{
    byte_packet_buffer::BytePacketBuffer, dns_header::DnsHeader, dns_question::DnsQuestion,
    dns_record::DnsRecord, query_type::QueryType, Result,
};

/// Структура, представляющая полный DNS-пакет.
/// Она содержит заголовок, вопросы, ответы, авторитетные записи и дополнительные ресурсы.
#[derive(Clone, Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>,
}

impl DnsPacket {
    /// Создает новый пустой DNS-пакет.
    pub fn new() -> DnsPacket {
        DnsPacket {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new(),
        }
    }

    /// Создает DNS-пакет из байтового буфера.
    /// Этот метод читает все разделы пакета из буфера.
    pub fn from_buffer(buffer: &mut BytePacketBuffer) -> Result<DnsPacket> {
        let mut result = DnsPacket::new();
        result.header.read(buffer)?;

        for _ in 0..result.header.questions {
            let mut question = DnsQuestion::new("".to_string(), QueryType::UNKNOWN(0));
            question.read(buffer)?;
            result.questions.push(question);
        }

        for _ in 0..result.header.answers {
            let rec = DnsRecord::read(buffer)?;
            result.answers.push(rec);
        }

        for _ in 0..result.header.authoritative_entries {
            let rec = DnsRecord::read(buffer)?;
            result.authorities.push(rec);
        }

        for _ in 0..result.header.resource_entries {
            let rec = DnsRecord::read(buffer)?;
            result.resources.push(rec);
        }

        Ok(result)
    }

    /// Записывает DNS-пакет в байтовый буфер.
    pub fn write(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        self.header.questions = self.questions.len() as u16;
        self.header.answers = self.answers.len() as u16;
        self.header.authoritative_entries = self.authorities.len() as u16;
        self.header.resource_entries = self.resources.len() as u16;

        self.header.write(buffer)?;

        for question in &self.questions {
            question.write(buffer)?;
        }

        for record in &self.answers {
            record.write(buffer)?;
        }

        for record in &self.authorities {
            record.write(buffer)?;
        }

        for record in &self.resources {
            record.write(buffer)?;
        }
        Ok(())
    }

    /// Возвращает случайный IP-адрес из записей типа A в разделе ответов.
    pub fn get_random_a(&self) -> Option<Ipv4Addr> {
        self.answers
            .iter()
            .filter_map(|rec| {
                if let DnsRecord::A { addr, .. } = rec {
                    Some(*addr)
                } else {
                    None
                }
            })
            .collect::<Vec<Ipv4Addr>>()
            .choose(&mut rand::thread_rng())
            .copied()
    }

    /// Ищет IP-адрес NS-сервера в дополнительном разделе на основе имени хоста NS-сервера.
    pub fn get_ns_ip_from_additional(&self, qname: &str) -> Option<Ipv4Addr> {
        self.get_ns(qname)
            .flat_map(|(_, host)| {
                self.resources
                    .iter()
                    .filter_map(move |record| {
                        if let DnsRecord::A { domain, addr, .. } = record {
                            if domain == host {
                                return Some(*addr);
                            }
                        }
                        None
                    })
            })
            .next()
    }

    /// Ищет авторитативный сервер имен (NS) в разделе авторитетных записей.
    /// Возвращает имя хоста наиболее подходящего NS-сервера.
    pub fn get_unresolved_ns<'a>(&'a self, qname: &'a str) -> Option<&'a str> {
        self.get_ns(qname)
            .map(|(_, host)| host)
            .next()
    }

    /// Вспомогательный метод для поиска NS-записей, соответствующих домену.
    fn get_ns<'a>(&'a self, qname: &'a str) -> impl Iterator<Item = (&'a str, &'a str)> {
        self.authorities
            .iter()
            .filter_map(|rec| {
                if let DnsRecord::NS { domain, host, .. } = rec {
                    if qname.ends_with(domain) {
                        Some((domain.as_str(), host.as_str()))
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
    }

    /// Возвращает итератор по всем записям A (IPv4) в разделе ответов.
    pub fn answers_a(&self) -> impl Iterator<Item = &Ipv4Addr> {
        self.answers.iter().filter_map(|rec| {
            if let DnsRecord::A { addr, .. } = rec {
                Some(addr)
            } else {
                None
            }
        })
    }
    
    /// Возвращает итератор по всем записям NS (серверы имен) в разделе авторитетов.
    pub fn authorities_ns(&self) -> impl Iterator<Item = (&str, &str)> {
        self.authorities.iter().filter_map(|rec| {
            if let DnsRecord::NS { domain, host, .. } = rec {
                Some((domain.as_str(), host.as_str()))
            } else {
                None
            }
        })
    }

    /// Возвращает итератор по всем записям TXT в разделе ответов.
    pub fn answers_txt(&self) -> impl Iterator<Item = &str> {
        self.answers.iter().filter_map(|rec| {
            if let DnsRecord::TXT { data, .. } = rec {
                Some(data.as_str())
            } else {
                None
            }
        })
    }

    /// Возвращает итератор по всем записям MX в разделе ответов.
    pub fn answers_mx(&self) -> impl Iterator<Item = (&str, u16)> {
        self.answers.iter().filter_map(|rec| {
            if let DnsRecord::MX { host, priority, .. } = rec {
                Some((host.as_str(), *priority))
            } else {
                None
            }
        })
    }
}
