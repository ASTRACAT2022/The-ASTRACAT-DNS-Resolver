// src/cache.rs
// Модуль для реализации потокобезопасного кэша DNS-записей.

use std::sync::Arc;
use std::time::Instant;
use hickory_proto::rr::{Record, RecordType};
use dashmap::DashMap;

/// Тип, используемый для ключа в кэше.
/// Состоит из доменного имени (как String) и типа записи (RecordType).
pub type CacheKey = (String, RecordType);

/// Структура, представляющая запись в кэше.
/// Хранит DNS-записи и время их истечения.
#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub records: Vec<Record>,
    pub expires_at: Instant,
}

/// Тип-алиас для потокобезопасного кэша.
/// Использует DashMap для эффективного конкурентного доступа.
pub type Cache = Arc<DashMap<CacheKey, CacheEntry>>;
