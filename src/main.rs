// src/main.rs
// ASTRACAT DNS Resolver - V10
// Главный файл с улучшенной системой логирования для диагностики.

mod cache;
mod resolver;

use std::time::Duration;
use anyhow::{Result, Context};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use log::{info, error, warn};

use crate::resolver::{run_server, HEARTBEAT_TIMEOUT};

/// Продолжительность, через которую основной цикл сервера будет перезапущен.
const RESTART_INTERVAL: Duration = Duration::from_secs(600); // 10 минут

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    // Инициализируем систему логирования.
    // Установите переменную среды RUST_LOG=info, чтобы видеть все сообщения.
    env_logger::init();
    
    // Этот цикл действует как супервизор для логики сервера.
    loop {
        info!("Starting ASTRACAT DNS resolver on 0.0.0.0:5353 (dual-stack)");
        
        // Создаем токен отмены для корректного завершения задач.
        let shutdown_token = CancellationToken::new();
        let shutdown_token_server = shutdown_token.clone();
        let shutdown_token_monitor = shutdown_token.clone();
        let (tx, rx) = mpsc::channel(1); // Канал для сигналов "heartbeat"

        // Запускаем основную логику сервера в отдельной задаче.
        let server_task = tokio::spawn(run_server(tx, shutdown_token_server));
        
        // Запускаем монитор "heartbeat" в отдельной задаче.
        let monitor_task = tokio::spawn(heartbeat_monitor(rx, shutdown_token_monitor));

        // Используем `tokio::select!` для отслеживания сбоев или планового перезапуска.
        let result = tokio::select! {
            server_result = server_task => {
                // Задача сервера завершилась, отправляем сигнал завершения монитору.
                shutdown_token.cancel();
                server_result.context("Задача сервера завершилась с паникой")?
            },
            monitor_result = monitor_task => {
                // Задача монитора завершилась, отправляем сигнал завершения серверу.
                shutdown_token.cancel();
                monitor_result.context("Задача монитора завершилась с паникой")?
            },
            _ = tokio::time::sleep(RESTART_INTERVAL) => {
                // Сработал таймер планового перезапуска.
                shutdown_token.cancel();
                info!("Инициирован плановый перезапуск. Выключение и перезапуск сервера...");
                Ok(())
            }
        };

        if let Err(e) = result {
            error!("ASTRACAT DNS resolver столкнулся с фатальной ошибкой: {}. Перезапуск...", e);
        }
        
        warn!("Перезапуск сервера через 1 секунду...");
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// Отдельная задача, которая следит за "heartbeat" от сервера.
/// Если за установленное время не приходит сигнал, она возвращает ошибку.
async fn heartbeat_monitor(mut rx: mpsc::Receiver<()>, shutdown_token: CancellationToken) -> Result<()> {
    loop {
        tokio::select! {
            _ = shutdown_token.cancelled() => {
                info!("Монитор 'heartbeat' получил сигнал завершения. Выход...");
                return Ok(());
            },
            Some(_) = rx.recv() => {
                // "Heartbeat" получен, продолжаем цикл.
            },
            _ = tokio::time::sleep(HEARTBEAT_TIMEOUT) => {
                // Истекло время ожидания без "heartbeat", возвращаем ошибку.
                return Err(anyhow::anyhow!("Таймаут 'heartbeat': сервер не отвечает."));
            }
        }
    }
}
