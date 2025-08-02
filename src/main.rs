async fn run_health_check(_cache: Cache) -> AppResult<()> {
    let mut health_check_interval = interval(Duration::from_secs(30));
    let root_server_addr: IpAddr = ROOT_SERVER.parse()?;

    loop {
        health_check_interval.tick().await;
        
        let health_check_domain = Name::from_ascii("google.com.").unwrap();
        let query_type = RecordType::A;
        let query_id = 2; 

        info!("Running periodic health check by querying a public domain...");

        let query_message = create_query_message(&health_check_domain, query_type, query_id)?;
        
        match send_and_receive_udp(&root_server_addr, &query_message).await {
            Ok(response_message) => {
                if response_message.response_code() == ResponseCode::NoError {
                    info!("Health check passed: Successfully received a response from a root server.");
                } else {
                    error!(
                        "Health check FAILED. Reason: DNS response code was not NoError. Restarting process..."
                    );
                    return Err(AppError::from("Health check failed due to DNS response code."));
                }
            }
            Err(e) => {
                error!("Health check FAILED. Reason: {}. Restarting process...", e);
                return Err(AppError::from("Health check failed due to network error."));
            }
        }
    }
}
