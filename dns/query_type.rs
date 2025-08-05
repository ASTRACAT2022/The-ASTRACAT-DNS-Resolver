use std::fmt;

#[derive(Clone, PartialEq, Eq, Hash)]
pub enum QueryType {
    A,
    AAAA,
    NS,
    CNAME,
    // Добавьте другие варианты, если они есть в вашем коде
}

impl fmt::Display for QueryType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QueryType::A => write!(f, "A"),
            QueryType::AAAA => write!(f, "AAAA"),
            QueryType::NS => write!(f, "NS"),
            QueryType::CNAME => write!(f, "CNAME"),
            // Добавьте другие варианты по необходимости
        }
    }
}
