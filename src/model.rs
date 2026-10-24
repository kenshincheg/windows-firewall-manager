use std::path::Path;

/// Направление правила.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Inbound,
    Outbound,
}

impl Direction {
    pub fn label(self) -> &'static str {
        match self {
            Self::Inbound => "Входящее",
            Self::Outbound => "Исходящее",
        }
    }
}

/// Действие правила.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Allow,
    Block,
}

impl Action {
    pub fn label(self) -> &'static str {
        match self {
            Self::Allow => "Разрешить",
            Self::Block => "Блокировать",
        }
    }
}

/// Протокол.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
    Any,
    /// Протокол Windows, который форма пока не редактирует.
    Other(i32),
}

impl Protocol {
    pub fn label(self) -> &'static str {
        match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
            Self::Any => "Любой",
            Self::Other(1) => "ICMPv4",
            Self::Other(58) => "ICMPv6",
            Self::Other(_) => "Другой",
        }
    }
}

/// Профили сети (битовая маска WFAS).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Profiles {
    pub domain: bool,
    pub private: bool,
    pub public: bool,
}

impl Default for Profiles {
    fn default() -> Self {
        Self {
            domain: true,
            private: true,
            public: true,
        }
    }
}

impl Profiles {
    pub fn as_bitmask(self) -> i32 {
        let mut mask = 0i32;
        if self.domain {
            mask |= 0x1; // NET_FW_PROFILE2_DOMAIN
        }
        if self.private {
            mask |= 0x2; // NET_FW_PROFILE2_PRIVATE
        }
        if self.public {
            mask |= 0x4; // NET_FW_PROFILE2_PUBLIC
        }
        mask
    }

    pub fn from_bitmask(mask: i32) -> Self {
        Self {
            domain: mask & 0x1 != 0,
            private: mask & 0x2 != 0,
            public: mask & 0x4 != 0,
        }
    }
}

/// Правило файрвола (форма + список).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallRule {
    pub name: String,
    pub direction: Direction,
    pub action: Action,
    pub protocol: Protocol,
    /// Порт, диапазон, список через запятую, `*` или пустая строка.
    pub local_ports: String,
    pub application_path: String,
    pub profiles: Profiles,
    pub enabled: bool,
    pub description: String,
    /// Полный снимок условий COM. None — условия не удалось прочитать полностью.
    /// Используется для поиска дублей и адресного удаления/редактирования.
    pub comparison_key: Option<Vec<String>>,
}

impl Default for FirewallRule {
    fn default() -> Self {
        Self {
            name: String::new(),
            direction: Direction::Inbound,
            action: Action::Allow,
            protocol: Protocol::Tcp,
            local_ports: String::new(),
            application_path: String::new(),
            profiles: Profiles::default(),
            enabled: true,
            description: String::new(),
            comparison_key: None,
        }
    }
}

/// Результат валидации полей формы.
pub fn validate_rule(rule: &FirewallRule) -> Result<(), String> {
    validate_rule_text(rule)?;
    if matches!(rule.protocol, Protocol::Other(_)) {
        return Err("Этот протокол пока нельзя редактировать в форме программы".into());
    }

    if !rule.profiles.domain && !rule.profiles.private && !rule.profiles.public {
        return Err("Выберите хотя бы один профиль сети".into());
    }

    let ports = rule.local_ports.trim();
    if !ports.is_empty() {
        validate_ports(ports)?;
        if matches!(rule.protocol, Protocol::Any) {
            return Err("Для портов выберите TCP или UDP (не «Любой»)".into());
        }
    }

    let app = rule.application_path.trim();
    if !app.is_empty() {
        let path = Path::new(app);
        if !path.is_file() {
            return Err(format!("Файл программы не найден: {app}"));
        }
    }

    if ports.is_empty() && app.is_empty() {
        return Err("Укажите порт/диапазон или путь к программе".into());
    }

    Ok(())
}

/// Shared checks applied before any Windows Firewall property is changed.
pub(crate) fn validate_rule_text(rule: &FirewallRule) -> Result<(), String> {
    let name = rule.name.trim();
    if name.is_empty() {
        return Err("Укажите имя правила".into());
    }
    if name.eq_ignore_ascii_case("all") {
        return Err("Имя «all» зарезервировано Windows Firewall".into());
    }
    if name.contains('|') {
        return Err("Имя правила не должно содержать символ |".into());
    }
    if name.contains('\0')
        || rule.description.contains('\0')
        || rule.application_path.contains('\0')
    {
        return Err("Поля правила не должны содержать нулевые символы".into());
    }
    if rule.description.contains('|') {
        return Err("Описание правила не должно содержать символ |".into());
    }
    Ok(())
}

/// Проверка порта, диапазона, списка через запятую либо `*`.
pub fn validate_ports(input: &str) -> Result<(), String> {
    if input.trim() == "*" {
        return Ok(());
    }
    input.split(',').try_for_each(validate_port_range)
}

fn validate_port_range(input: &str) -> Result<(), String> {
    let s = input.trim();
    if let Some((a, b)) = s.split_once('-') {
        let from = parse_port(a.trim())?;
        let to = parse_port(b.trim())?;
        if from > to {
            return Err(format!(
                "Диапазон некорректен: {from} > {to} (ожидается from <= to)"
            ));
        }
        Ok(())
    } else {
        parse_port(s).map(|_| ())
    }
}

fn parse_port(s: &str) -> Result<u16, String> {
    let n: u32 = s
        .parse()
        .map_err(|_| format!("Порт должен быть числом: «{s}»"))?;
    if n == 0 || n > 65535 {
        return Err(format!("Порт вне диапазона 1–65535: {n}"));
    }
    Ok(n as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_lists_wildcards_and_malformed_lists_are_validated() {
        for ports in ["*", "80,443", "1, 45000-45002,65535"] {
            assert!(validate_ports(ports).is_ok());
        }
        for ports in ["", ",22", "22,", "22,,443", "*,443", "1-65536", "0,22"] {
            assert!(validate_ports(ports).is_err());
        }
    }

    #[test]
    fn unsupported_protocol_and_embedded_nulls_are_rejected_before_saving() {
        let mut rule = FirewallRule {
            name: "Test".into(),
            local_ports: "22".into(),
            ..Default::default()
        };
        rule.protocol = Protocol::Other(1);
        assert!(validate_rule(&rule).is_err());
        rule.protocol = Protocol::Tcp;
        rule.description = "bad\0description".into();
        assert!(validate_rule(&rule).is_err());
    }

    #[test]
    fn single_port_ok() {
        assert!(validate_ports("21").is_ok());
        assert!(validate_ports("65535").is_ok());
    }

    #[test]
    fn range_ok() {
        assert!(validate_ports("45512-65534").is_ok());
        assert!(validate_ports("1-1").is_ok());
    }

    #[test]
    fn range_bad_order() {
        assert!(validate_ports("100-50").is_err());
    }

    #[test]
    fn port_zero_bad() {
        assert!(validate_ports("0").is_err());
    }
    #[test]
    fn firewall_rejects_reserved_or_invalid_names_before_saving() {
        for name in ["all", " ALL ", "bad|name"] {
            let rule = FirewallRule {
                name: name.into(),
                local_ports: "22".into(),
                ..Default::default()
            };
            assert!(
                validate_rule(&rule).is_err(),
                "Name {name:?} is not valid for Windows Firewall"
            );
        }
    }
    #[test]
    fn invalid_description_is_reported_before_saving() {
        let rule = FirewallRule {
            name: "Valid name".into(),
            description: "bad|description".into(),
            local_ports: "22".into(),
            ..Default::default()
        };
        assert!(validate_rule(&rule).is_err());
    }
}
