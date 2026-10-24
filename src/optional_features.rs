//! Опциональные компоненты Windows (Telnet Client и др.).

use std::fs;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Не показывать окно консоли.
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeatureState {
    Enabled,
    Disabled,
    /// Компонент установлен, но не активен (например `sshd` Stopped).
    InstalledStopped,
    /// Включение запрошено, нужна перезагрузка.
    EnablePending,
    /// Отключение запрошено, нужна перезагрузка.
    DisablePending,
    Unknown(String),
}

impl FeatureState {
    pub fn label(&self) -> String {
        match self {
            Self::Unknown(s) => format!("неизвестно ({s})"),
            other => other.label_str().to_string(),
        }
    }

    /// Без аллокации для известных состояний (удобно рисовать каждый кадр).
    pub fn label_str(&self) -> &str {
        match self {
            Self::Enabled => "включён",
            Self::Disabled => "выключен",
            Self::InstalledStopped => "sshd остановлен",
            Self::EnablePending => "включение ожидает перезагрузки",
            Self::DisablePending => "отключение ожидает перезагрузки",
            Self::Unknown(s) => s.as_str(),
        }
    }

    pub fn is_enabled(&self) -> bool {
        matches!(self, Self::Enabled)
    }

    /// Capability/feature на месте (в т.ч. если служба остановлена).
    pub fn is_installed(&self) -> bool {
        matches!(
            self,
            Self::Enabled | Self::InstalledStopped | Self::EnablePending
        )
    }
}

fn run_hidden(program: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(program)
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("Не удалось запустить {program}: {e}"))?;

    let stdout = decode_console(&output.stdout);
    let stderr = decode_console(&output.stderr);
    if !output.status.success() {
        let code = output.status.code().unwrap_or(-1);
        let detail = if !stderr.trim().is_empty() {
            stderr
        } else if !stdout.trim().is_empty() {
            stdout
        } else {
            format!("код {code}")
        };
        if code == 740 {
            return Err(
                "нужны права администратора (DISM/PowerShell, код 740)".into(),
            );
        }
        return Err(format!("{program} ошибка (код {code}): {detail}"));
    }
    Ok(stdout)
}

/// DISM/консоль часто отдают OEM или UTF-16, не UTF-8.
fn decode_console(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    // UTF-16 LE BOM
    if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE {
        let u16s: Vec<u16> = bytes[2..]
            .chunks(2)
            .filter_map(|c| {
                if c.len() == 2 {
                    Some(u16::from_le_bytes([c[0], c[1]]))
                } else {
                    None
                }
            })
            .collect();
        return String::from_utf16_lossy(&u16s);
    }
    // Если много нулевых байт — похоже на UTF-16 LE без BOM
    let nul_ratio = bytes.iter().filter(|&&b| b == 0).count() * 100 / bytes.len().max(1);
    if nul_ratio > 20 {
        let u16s: Vec<u16> = bytes
            .chunks(2)
            .filter_map(|c| {
                if c.len() == 2 {
                    Some(u16::from_le_bytes([c[0], c[1]]))
                } else {
                    None
                }
            })
            .collect();
        return String::from_utf16_lossy(&u16s);
    }
    // Сначала UTF-8, иначе Windows-1251 (часто для русских сообщений).
    match std::str::from_utf8(bytes) {
        Ok(s) => s.to_string(),
        Err(_) => bytes.iter().map(|&b| decode_cp1251(b)).collect(),
    }
}

fn decode_cp1251(b: u8) -> char {
    // Достаточный набор для разбора «Состояние : Включено/Отключено».
    match b {
        0xC0..=0xFF => {
            // А-я в CP1251: 0xC0 = А ... roughly map via unicode offset
            char::from_u32(0x0410 + u32::from(b - 0xC0)).unwrap_or('?')
        }
        0xB8 => 'ё',
        0xA8 => 'Ё',
        _ => b as char,
    }
}

/// Состояние TelnetClient через PowerShell (надёжнее DISM-парсинга).
pub fn telnet_client_state() -> FeatureState {
    match run_hidden(
        "powershell.exe",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "(Get-WindowsOptionalFeature -Online -FeatureName 'TelnetClient').State.ToString()",
        ],
    ) {
        Ok(text) => parse_state_token(text.trim()),
        Err(ps_err) => {
            // Запасной путь — DISM (с улучшенной декодировкой).
            match run_hidden(
                "dism.exe",
                &["/online", "/Get-FeatureInfo", "/FeatureName:TelnetClient"],
            ) {
                Ok(text) => parse_dism_feature_info(&text),
                Err(dism_err) => FeatureState::Unknown(format!("{ps_err}; fallback: {dism_err}")),
            }
        }
    }
}

fn parse_state_token(token: &str) -> FeatureState {
    let t = token.trim().trim_matches(|c: char| c == '"' || c == '\'');
    let lower = t.to_lowercase();
    if lower == "enabled" || lower.contains("включен") {
        FeatureState::Enabled
    } else if lower == "disabled" || lower.contains("отключен") || lower.contains("выключен") {
        FeatureState::Disabled
    } else if lower.contains("enablepending") {
        FeatureState::EnablePending
    } else if lower.contains("disablepending") {
        FeatureState::DisablePending
    } else if t.is_empty() {
        FeatureState::Unknown("пустой ответ PowerShell".into())
    } else {
        FeatureState::Unknown(t.to_string())
    }
}

fn parse_dism_feature_info(text: &str) -> FeatureState {
    for line in text.lines() {
        let lower = line.to_lowercase();
        let is_state_line = lower.contains("state") || lower.contains("состояние");
        if !is_state_line {
            continue;
        }
        if lower.contains("enablepending") {
            return FeatureState::EnablePending;
        }
        if lower.contains("disablepending") {
            return FeatureState::DisablePending;
        }
        if lower.contains("enabled") || lower.contains("включен") {
            return FeatureState::Enabled;
        }
        if lower.contains("disabled")
            || lower.contains("отключен")
            || lower.contains("выключен")
        {
            return FeatureState::Disabled;
        }
    }
    FeatureState::Unknown("не удалось разобрать вывод DISM".into())
}

/// Включить Telnet Client без немедленной перезагрузки.
pub fn enable_telnet_client() -> Result<(), String> {
    run_hidden(
        "powershell.exe",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Enable-WindowsOptionalFeature -Online -FeatureName 'TelnetClient' -NoRestart -All | Out-Null; (Get-WindowsOptionalFeature -Online -FeatureName 'TelnetClient').State.ToString()",
        ],
    )
    .map(|_| ())
    .or_else(|ps_err| {
        run_hidden(
            "dism.exe",
            &[
                "/online",
                "/Enable-Feature",
                "/FeatureName:TelnetClient",
                "/NoRestart",
            ],
        )
        .map(|_| ())
        .map_err(|dism_err| format!("{ps_err}; DISM: {dism_err}"))
    })
}

/// Отключить Telnet Client без немедленной перезагрузки.
pub fn disable_telnet_client() -> Result<(), String> {
    run_hidden(
        "powershell.exe",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Disable-WindowsOptionalFeature -Online -FeatureName 'TelnetClient' -NoRestart | Out-Null; (Get-WindowsOptionalFeature -Online -FeatureName 'TelnetClient').State.ToString()",
        ],
    )
    .map(|_| ())
    .or_else(|ps_err| {
        run_hidden(
            "dism.exe",
            &[
                "/online",
                "/Disable-Feature",
                "/FeatureName:TelnetClient",
                "/NoRestart",
            ],
        )
        .map(|_| ())
        .map_err(|dism_err| format!("{ps_err}; DISM: {dism_err}"))
    })
}

/// Имя capability OpenSSH Client (клиент `ssh.exe`).
pub const OPENSSH_CLIENT_CAPABILITY: &str = "OpenSSH.Client~~~~0.0.1.0";
/// Имя capability OpenSSH Server (`sshd`, порт 22).
pub const OPENSSH_SERVER_CAPABILITY: &str = "OpenSSH.Server~~~~0.0.1.0";

fn parse_capability_token(token: &str) -> FeatureState {
    let t = token.trim().trim_matches(|c: char| c == '"' || c == '\'');
    let lower = t.to_lowercase();
    if lower == "installed" || lower.contains("установлен") {
        FeatureState::Enabled
    } else if lower == "notpresent"
        || lower.contains("отсутствует")
        || lower.contains("не установлен")
    {
        FeatureState::Disabled
    } else if lower.contains("installpending") || lower.contains("ожидает") {
        FeatureState::EnablePending
    } else if t.is_empty() {
        FeatureState::Unknown("пустой ответ PowerShell".into())
    } else {
        FeatureState::Unknown(t.to_string())
    }
}

fn parse_dism_capability_info(text: &str) -> FeatureState {
    for line in text.lines() {
        let lower = line.to_lowercase();
        let is_state_line = lower.contains("state") || lower.contains("состояние");
        if !is_state_line {
            continue;
        }
        if lower.contains("installed") || lower.contains("установлен") {
            return FeatureState::Enabled;
        }
        if lower.contains("not present")
            || lower.contains("notpresent")
            || lower.contains("отсутствует")
            || lower.contains("не установлен")
        {
            return FeatureState::Disabled;
        }
    }
    FeatureState::Unknown("не удалось разобрать вывод DISM (capability)".into())
}

fn capability_state(name: &str) -> FeatureState {
    let ps = format!("(Get-WindowsCapability -Online -Name '{name}').State.ToString()");
    match run_hidden(
        "powershell.exe",
        &["-NoProfile", "-NonInteractive", "-Command", &ps],
    ) {
        Ok(text) => parse_capability_token(text.trim()),
        Err(ps_err) => {
            let cap = format!("/CapabilityName:{name}");
            match run_hidden("dism.exe", &["/online", "/Get-CapabilityInfo", &cap]) {
                Ok(text) => parse_dism_capability_info(&text),
                Err(dism_err) => FeatureState::Unknown(format!("{ps_err}; fallback: {dism_err}")),
            }
        }
    }
}

fn add_capability(name: &str) -> Result<(), String> {
    let ps = format!(
        "Add-WindowsCapability -Online -Name '{name}' | Out-Null; (Get-WindowsCapability -Online -Name '{name}').State.ToString()"
    );
    run_hidden(
        "powershell.exe",
        &["-NoProfile", "-NonInteractive", "-Command", &ps],
    )
    .map(|_| ())
    .or_else(|ps_err| {
        let cap = format!("/CapabilityName:{name}");
        run_hidden("dism.exe", &["/online", "/Add-Capability", &cap])
            .map(|_| ())
            .map_err(|dism_err| format!("{ps_err}; DISM: {dism_err}"))
    })
}

fn remove_capability(name: &str) -> Result<(), String> {
    let ps = format!(
        "Remove-WindowsCapability -Online -Name '{name}' | Out-Null; (Get-WindowsCapability -Online -Name '{name}').State.ToString()"
    );
    run_hidden(
        "powershell.exe",
        &["-NoProfile", "-NonInteractive", "-Command", &ps],
    )
    .map(|_| ())
    .or_else(|ps_err| {
        let cap = format!("/CapabilityName:{name}");
        run_hidden("dism.exe", &["/online", "/Remove-Capability", &cap])
            .map(|_| ())
            .map_err(|dism_err| format!("{ps_err}; DISM: {dism_err}"))
    })
}

/// Состояние OpenSSH Client (Windows Capability).
pub fn openssh_client_state() -> FeatureState {
    capability_state(OPENSSH_CLIENT_CAPABILITY)
}

/// Установить OpenSSH Client (скачивает capability с Windows Update / локального источника).
pub fn enable_openssh_client() -> Result<(), String> {
    add_capability(OPENSSH_CLIENT_CAPABILITY)
}

/// Удалить OpenSSH Client и очистить данные (`ProgramData\ssh`, `%USERPROFILE%\.ssh`).
pub fn disable_openssh_client() -> Result<(), String> {
    remove_capability(OPENSSH_CLIENT_CAPABILITY)?;
    cleanup_openssh_data_dirs()
}

fn sshd_service_running() -> Option<bool> {
    match run_hidden(
        "powershell.exe",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "(Get-Service -Name sshd -ErrorAction SilentlyContinue).Status.ToString()",
        ],
    ) {
        Ok(text) => {
            let t = text.trim().to_lowercase();
            if t.is_empty() {
                None
            } else {
                Some(t == "running")
            }
        }
        Err(_) => None,
    }
}

/// Состояние OpenSSH Server: capability + реально ли запущена служба `sshd`.
pub fn openssh_server_state() -> FeatureState {
    match capability_state(OPENSSH_SERVER_CAPABILITY) {
        FeatureState::Enabled => match sshd_service_running() {
            Some(true) => FeatureState::Enabled,
            Some(false) => FeatureState::InstalledStopped,
            None => FeatureState::Unknown("capability есть, службу sshd не найти".into()),
        },
        other => other,
    }
}

fn start_sshd_automatic() -> Result<(), String> {
    run_hidden(
        "powershell.exe",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Start-Service sshd -ErrorAction Stop; Set-Service -Name sshd -StartupType Automatic",
        ],
    )
    .map(|_| ())
    .map_err(|e| format!("служба sshd: {e}"))
}

fn stop_sshd() -> Result<(), String> {
    run_hidden(
        "powershell.exe",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Stop-Service sshd -Force -ErrorAction Stop",
        ],
    )
    .map(|_| ())
    .map_err(|e| format!("служба sshd: {e}"))
}

/// Установить OpenSSH Server (если ещё нет), запустить `sshd` и автозапуск.
pub fn enable_openssh_server() -> Result<(), String> {
    if !capability_state(OPENSSH_SERVER_CAPABILITY).is_enabled() {
        add_capability(OPENSSH_SERVER_CAPABILITY)?;
    }
    start_sshd_automatic()
}

/// Только остановить службу `sshd` (capability остаётся).
pub fn stop_openssh_server() -> Result<(), String> {
    stop_sshd()
}

/// Остановить `sshd` и удалить OpenSSH Server (папки не трогаем).
pub fn disable_openssh_server() -> Result<(), String> {
    let _ = run_hidden(
        "powershell.exe",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Stop-Service sshd -Force -ErrorAction SilentlyContinue",
        ],
    );
    remove_capability(OPENSSH_SERVER_CAPABILITY)
}

/// Каталоги данных OpenSSH, которые удаляются вместе с клиентом.
pub fn openssh_data_dirs() -> Vec<PathBuf> {
    let mut dirs = vec![PathBuf::from(r"C:\ProgramData\ssh")];
    if let Ok(profile) = std::env::var("USERPROFILE") {
        let p = PathBuf::from(profile).join(".ssh");
        if !dirs.iter().any(|d| d == &p) {
            dirs.push(p);
        }
    }
    dirs
}

/// Открыть путь в проводнике Windows.
pub fn open_in_explorer(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Err(format!("папка ещё не создана: {}", path.display()));
    }
    Command::new("explorer.exe")
        .arg(path.as_os_str())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("Не удалось открыть {}: {e}", path.display()))
}

fn remove_dir_if_exists(path: &Path) -> Result<bool, String> {
    if !path.exists() {
        return Ok(false);
    }
    fs::remove_dir_all(path)
        .map(|()| true)
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// Удалить `C:\ProgramData\ssh` и `%USERPROFILE%\.ssh` (ключи/config). Нет папки — не ошибка.
fn cleanup_openssh_data_dirs() -> Result<(), String> {
    let mut errors = Vec::new();
    for dir in openssh_data_dirs() {
        if let Err(e) = remove_dir_if_exists(&dir) {
            errors.push(e);
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "OpenSSH снят, но не удалось очистить: {}",
            errors.join("; ")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_english_state_line() {
        let t = "Feature Name : TelnetClient\r\nState : Disabled\r\n";
        assert_eq!(parse_dism_feature_info(t), FeatureState::Disabled);
    }

    #[test]
    fn parse_russian_state_line() {
        let t = "Имя компонента : TelnetClient\r\nСостояние : Отключено\r\n";
        assert_eq!(parse_dism_feature_info(t), FeatureState::Disabled);
    }

    #[test]
    fn parse_ps_token() {
        assert_eq!(parse_state_token("Enabled"), FeatureState::Enabled);
        assert_eq!(parse_state_token("Disabled\r\n"), FeatureState::Disabled);
    }

    #[test]
    fn parse_openssh_capability() {
        assert_eq!(parse_capability_token("Installed"), FeatureState::Enabled);
        assert_eq!(parse_capability_token("NotPresent"), FeatureState::Disabled);
        let t = "Capability Identity : OpenSSH.Client~~~~0.0.1.0\r\nState : Installed\r\n";
        assert_eq!(parse_dism_capability_info(t), FeatureState::Enabled);
    }
}
