pub mod byte_packet_buffer;
pub mod dns_header;
pub mod dns_packet;
pub mod dns_question;
pub mod dns_record;
pub mod query_type;
pub mod result_code;

// You can define a custom error type for better error handling
#[derive(Debug)]
pub struct DnsError(Box<dyn std::error::Error + Send + Sync>);

impl From<String> for DnsError {
    fn from(s: String) -> Self {
        DnsError(s.into())
    }
}

impl From<&str> for DnsError {
    fn from(s: &str) -> Self {
        DnsError(s.into())
    }
}

pub type Result<T> = std::result::Result<T, DnsError>;
