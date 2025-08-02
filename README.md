Creater * **Telegram-канал:** [ASTRACAT UI](https://t.me/astracatui)  ([@astracatui](https://t.me/astracatui))
ASTRACAT DNS-резолвер 🚀

✨ Новый релиз на Rust! ✨

Добро пожаловать в ASTRACAT — высокопроизводительный, асинхронный и рекурсивный DNS-резолвер, написанный на Rust.
🌟 Преимущества

    Скорость ⚡️: Асинхронная архитектура на Tokio и оптимизированный кэш обеспечивают молниеносную обработку запросов.

    Надёжность 🛡️: Rust гарантирует безопасность памяти и стабильную работу сервера.

    Интеллект 🧠: Умное кэширование и префетчинг обновляют записи до того, как они устареют.

    Автономность 📈: Полностью рекурсивный поиск позволяет резолверу самостоятельно находить DNS-записи от корневых серверов.

💻 Описание реализации

    Конкурентность: Сервер на Tokio обрабатывает каждый входящий UDP-запрос в отдельной асинхронной задаче, что исключает блокировки.

    Рекурсивный поиск: Функция recursive_lookup_with_cache итеративно следует по ответам-ссылкам (delegation), находя актуальные записи.

    Кэш и префетчинг: Для хранения записей используется DashMap (потокобезопасная lock-free хэш-таблица). Фоновый поток постоянно проверяет TTL и обновляет записи заранее.

    Обработка ошибок: Библиотека anyhow обеспечивает простой и надёжный механизм управления ошибками.

⚙️ Технологии

    Rust: Безопасный и высокопроизводительный системный язык.

    Tokio: Асинхронный рантайм для конкурентных операций.

    hickory-proto: Библиотека для работы с DNS-протоколом.

    DashMap: Потокобезопасная хэш-таблица для быстрого кэша.

🚀 Инструкции по запуску

    Клонирование репозитория:

    git clone https://github.com/ASTRACAT2022/The-ASTRACAT-DNS-Resolver.git
    cd The-ASTRACAT-DNS-Resolver

    Сборка проекта:

    cargo build --release

    Запуск:

    RUST_LOG=info cargo run --release

🚀 Запуск как демон (systemd)

    Создайте файл службы:

    sudo nano /etc/systemd/system/astracat-dns.service

    Добавьте конфигурацию:
    Замените /path/to/your/dns-resolver-rust/ на фактический путь.

    [Unit]
    Description=ASTRACAT DNS Resolver
    After=network.target

    [Service]
    ExecStart=/path/to/your/dns-resolver-rust/target/release/dns-resolver-rust
    WorkingDirectory=/path/to/your/dns-resolver-rust
    Restart=always
    RestartSec=3
    Environment=RUST_LOG=info

    [Install]
    WantedBy=multi-user.target

    Запустите службу:

    sudo systemctl daemon-reload
    sudo systemctl enable astracat-dns.service
    sudo systemctl start astracat-dns.service

    Проверка статуса:

    sudo systemctl status astracat-dns.service

💬 Сообщество

Присоединяйтесь к нам и следите за обновлениями в нашем Telegram-канале!

t.me/ASTRACAT_UI
