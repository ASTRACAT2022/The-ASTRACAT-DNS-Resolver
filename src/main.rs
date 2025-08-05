#[async_recursion]
async fn lookup(mut qname: String, qtype: QueryType, mut current_nameserver: Ipv4Addr) -> Result<DnsPacket> {
    const MAX_DEPTH: u8 = 10;
    let mut depth = 0;

    loop {
        if depth >= MAX_DEPTH {
            return Err("Превышена максимальная глубина поиска.".into());
        }
        depth += 1;

        let mut packet = DnsPacket::new();
        packet.header.id = 6666;
        packet.header.recursion_desired = false;
        packet.header.questions = 1;
        packet.questions.push(DnsQuestion::new(qname.clone(), qtype));

        let mut req_buffer = BytePacketBuffer::new();
        packet.write(&mut req_buffer)?;
        let req_bytes = req_buffer.get_range(0, req_buffer.pos())?;

        let mut res_packet_opt = None;

        // Пробуем все корневые сервера при тайм-ауте
        for &ns in ROOT_SERVERS {
            let socket = match UdpSocket::bind(("0.0.0.0", 0)).await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Ошибка бинда сокета: {}", e);
                    continue;
                }
            };

            if let Err(e) = socket.send_to(req_bytes, (ns, 53)).await {
                eprintln!("Ошибка отправки запроса на NS {}: {}", ns, e);
                continue;
            }

            let mut res_buffer = BytePacketBuffer::new();
            match timeout(Duration::from_secs(3), socket.recv_from(&mut res_buffer.buf)).await {
                Ok(Ok(_)) => {
                    match DnsPacket::from_buffer(&mut res_buffer) {
                        Ok(response_packet) => {
                            current_nameserver = ns;
                            res_packet_opt = Some(response_packet);
                            break; // успех — выходим
                        }
                        Err(e) => {
                            eprintln!("Ошибка парсинга ответа от {}: {}", ns, e);
                        }
                    }
                }
                Ok(Err(e)) => {
                    eprintln!("Ошибка получения от {}: {}", ns, e);
                }
                Err(_) => {
                    eprintln!("⏱ Тайм-аут при обращении к NS {}", ns);
                }
            }
        }

        let res_packet = match res_packet_opt {
            Some(p) => p,
            None => return Err("Все корневые DNS-серверы недоступны.".into()),
        };

        if !res_packet.answers.is_empty() {
            return Ok(res_packet);
        }

        if res_packet.header.rescode == ResultCode::NXDOMAIN {
            return Err("Домен не существует.".into());
        }

        // Обработка CNAME
        if let Some(cname_record) = res_packet.answers.iter().find_map(|rec| {
            if let DnsRecord::CNAME { domain, host, .. } = rec {
                if qname.ends_with(domain) {
                    return Some(host.clone());
                }
            }
            None
        }) {
            eprintln!("🔁 CNAME обнаружен: {} → {}", qname, cname_record);
            qname = cname_record;
            continue;
        }

        // Поиск NS-записей
        if let Some(ns_record) = res_packet.authorities.iter().find_map(|rec| {
            if let DnsRecord::NS { domain, host, .. } = rec {
                if qname.ends_with(domain) {
                    return Some(host.clone());
                }
            }
            None
        }) {
            // Пробуем найти IP-адрес для NS из дополнительных записей
            if let Some(a_record) = res_packet.resources.iter().find_map(|rec| {
                if let DnsRecord::A { domain, addr, .. } = rec {
                    if domain == &ns_record {
                        return Some(*addr);
                    }
                }
                None
            }) {
                eprintln!("🔍 NS {} найден с IP {}", ns_record, a_record);
                current_nameserver = a_record;
            } else {
                eprintln!("🔄 Разрешение NS {} через отдельный запрос", ns_record);
                let ns_ip_packet = lookup(ns_record.clone(), QueryType::A, current_nameserver).await?;
                if let Some(ns_ip) = ns_ip_packet.get_random_a() {
                    eprintln!("✅ NS {} → {}", ns_record, ns_ip);
                    current_nameserver = ns_ip;
                } else {
                    return Err(format!("Не удалось разрешить NS-запись для {}", ns_record).into());
                }
            }
            continue;
        }

        return Err("Не найдено ответов, CNAME или NS-записей.".into());
    }
}
