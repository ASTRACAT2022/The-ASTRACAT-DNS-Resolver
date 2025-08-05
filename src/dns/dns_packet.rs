use std::net::{Ipv4Addr, Ipv6Addr};

use super::{
    byte_packet_buffer::BytePacketBuffer, dns_header::DnsHeader, dns_question::DnsQuestion,
    dns_record::DnsRecord, query_type::QueryType, Result,
};

#[derive(Clone, Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>,
}

impl DnsPacket {
    pub fn new() -> DnsPacket {
        DnsPacket {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new(),
        }
    }

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

    pub fn write(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        self.header.questions = self.questions.len() as u16;
        self.header.answers = self.answers.len() as u16;
        self.header.authoritative_entries = self.authorities.len() as u16;
        self.header.resource_entries = self.resources.len() as u16;

        self.header.write(buffer)?;

        for question in &self.questions {
            question.write(buffer)?;
        }
        for answer in &self.answers {
            answer.write(buffer)?;
        }
        for auth in &self.authorities {
            auth.write(buffer)?;
        }
        for resource in &self.resources {
            resource.write(buffer)?;
        }

        Ok(())
    }

    /// Helper function to find a DNS record with the same domain and type in the answers section.
    pub fn get_resolved_a(&self, qname: &str) -> Option<Ipv4Addr> {
        self.answers.iter().find_map(|rec| {
            if let DnsRecord::A { domain, addr, .. } = rec {
                if qname.eq_ignore_ascii_case(domain) {
                    return Some(*addr);
                }
            }
            None
        })
    }
    
    /// Helper function to find any A record
    pub fn get_random_a(&self) -> Option<Ipv4Addr> {
        self.answers.iter().filter_map(|rec| {
            if let DnsRecord::A { addr, .. } = rec {
                return Some(*addr);
            }
            None
        }).next()
    }

    /// Helper function to find a NS record for a given domain in the authorities section.
    pub fn get_ns<'a>(&'a self, qname: &'a str) -> impl Iterator<Item = (&'a str, &'a str)> {
        self.authorities
            .iter()
            .filter_map(move |rec| {
                if let DnsRecord::NS { domain, host, .. } = rec {
                    // Filter for NS records
                    if qname.ends_with(domain) {
                        return Some((domain.as_str(), host.as_str()));
                    }
                }
                None
            })
    }

    /// Takes a `qname` and `query_type` and tries to find a resolved IP from the records.
    pub fn get_ns_ip_from_additional(&self, qname: &str) -> Option<Ipv4Addr> {
        self.get_ns(qname)
            .flat_map(|(_, host)| {
                self.resources
                    .iter()
                    .filter_map(move |record| match record {
                        DnsRecord::A { domain, addr, .. } if domain == host => Some(addr),
                        _ => None,
                    })
            })
            .map(|addr| *addr)
            .next()
    }
    
    /// Returns the host name of an appropriate name server.
    pub fn get_unresolved_ns<'a>(&'a self, qname: &'a str) -> Option<&'a str> {
        self.get_ns(qname)
            .map(|(_, host)| host)
            .next()
    }
}
