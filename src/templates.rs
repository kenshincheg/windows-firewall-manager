//! Шаблоны популярных портов / сервисов.

use crate::model::{Action, Direction, FirewallRule, Protocol};

pub struct PortTemplate {
    pub label: &'static str,
    pub name: &'static str,
    pub ports: &'static str,
    /// Назначение сервиса и ограничения конкретного шаблона.
    pub purpose: &'static str,
    pub protocol: Protocol,
    pub direction: Direction,
    pub action: Action,
}

pub const TEMPLATES: &[PortTemplate] = &[
    PortTemplate {
        label: "FTP 21",
        name: "Allow_FTP_21",
        ports: "21",
        purpose: "Открывает входящий доступ к FTP-серверу\nпо TCP-порту 21 — управление передачей файлов.\nДля передачи самих файлов могут понадобиться\nдополнительные порты, например пассивный диапазон FTP.",
        protocol: Protocol::Tcp,
        direction: Direction::Inbound,
        action: Action::Allow,
    },
    PortTemplate {
        label: "SSH 22",
        name: "Allow_SSH_22",
        ports: "22",
        purpose: "Открывает входящий доступ к SSH-серверу\nпо TCP-порту 22: удалённая командная строка,\nа также передача файлов через SFTP и SCP.\nНа компьютере должен быть запущен SSH-сервер.",
        protocol: Protocol::Tcp,
        direction: Direction::Inbound,
        action: Action::Allow,
    },
    PortTemplate {
        label: "Telnet 23",
        name: "Allow_Telnet_23",
        ports: "23",
        purpose: "Открывает входящий доступ к Telnet-серверу\nпо TCP-порту 23 для удалённой командной строки.\nTelnet передаёт данные без шифрования.\nУстановка Telnet Client сама по себе сервер не создаёт.",
        protocol: Protocol::Tcp,
        direction: Direction::Inbound,
        action: Action::Allow,
    },
    PortTemplate {
        label: "HTTP 80",
        name: "Allow_HTTP_80",
        ports: "80",
        purpose: "Открывает входящий доступ к веб-серверу\nпо TCP-порту 80 — обычный HTTP.\nПозволяет открывать размещённый на компьютере\nсайт или веб-приложение без HTTPS-шифрования.",
        protocol: Protocol::Tcp,
        direction: Direction::Inbound,
        action: Action::Allow,
    },
    PortTemplate {
        label: "HTTPS 443",
        name: "Allow_HTTPS_443",
        ports: "443",
        purpose: "Открывает входящий доступ к веб-серверу\nпо TCP-порту 443 — HTTPS.\nДля защищённого сайта сервер должен быть\nнастроен на TLS и иметь подходящий сертификат.",
        protocol: Protocol::Tcp,
        direction: Direction::Inbound,
        action: Action::Allow,
    },
    PortTemplate {
        label: "RDP 3389",
        name: "Allow_RDP_3389",
        ports: "3389",
        purpose: "Открывает входящие TCP-подключения RDP\nк удалённому рабочему столу по порту 3389.\nУдалённый рабочий стол должен быть включён\nв Windows. Для транспорта UDP нужно отдельное правило.",
        protocol: Protocol::Tcp,
        direction: Direction::Inbound,
        action: Action::Allow,
    },
    PortTemplate {
        label: "DNS 53",
        name: "Allow_DNS_53",
        ports: "53",
        purpose: "Открывает входящие DNS-запросы к DNS-серверу\nпо UDP-порту 53 — преобразование имён в IP-адреса.\nДля DNS по TCP, в том числе передачи зон,\nнужно отдельное правило TCP 53.",
        protocol: Protocol::Udp,
        direction: Direction::Inbound,
        action: Action::Allow,
    },
    PortTemplate {
        label: "MySQL 3306",
        name: "Allow_MySQL_3306",
        ports: "3306",
        purpose: "Открывает входящий доступ к серверу баз данных\nMySQL или MariaDB по TCP-порту 3306.\nСервер должен слушать сетевой интерфейс,\nа учётная запись — разрешать удалённое подключение.",
        protocol: Protocol::Tcp,
        direction: Direction::Inbound,
        action: Action::Allow,
    },
    PortTemplate {
        label: "PostgreSQL 5432",
        name: "Allow_PostgreSQL_5432",
        ports: "5432",
        purpose: "Открывает входящий доступ к серверу баз данных\nPostgreSQL по TCP-порту 5432.\nУдалённые подключения также должны быть разрешены\nв настройках PostgreSQL и файле pg_hba.conf.",
        protocol: Protocol::Tcp,
        direction: Direction::Inbound,
        action: Action::Allow,
    },
    PortTemplate {
        label: "High 49152-65535",
        name: "Allow_HighPorts_49152_65535",
        ports: "49152-65535",
        purpose: "Открывает входящий TCP-доступ к диапазону\n49152–65535 — высоким динамическим портам.\nТакой диапазон могут использовать службы RPC\nи приложения. Уточните порты конкретной службы;\nшаблон разрешает весь указанный диапазон.",
        protocol: Protocol::Tcp,
        direction: Direction::Inbound,
        action: Action::Allow,
    },
];

pub fn apply(template: &PortTemplate, form: &mut FirewallRule) {
    form.name = template.name.to_string();
    form.local_ports = template.ports.to_string();
    form.protocol = template.protocol;
    form.direction = template.direction;
    form.action = template.action;
    form.enabled = true;
    // Всегда обновляем описание под выбранный шаблон
    // (в т.ч. если до этого уже был другой шаблон).
    form.description = format!("Шаблон: {}", template.label);
}
