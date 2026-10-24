//! Лог действий и ошибок рядом с exe: `logs/firewall_YYYY-MM-DD.log`.

use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

static LOG_PATH: Mutex<Option<PathBuf>> = Mutex::new(None);

fn logs_dir() -> PathBuf {
    let base = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("logs")
}

fn ensure_log_file() -> std::io::Result<PathBuf> {
    let mut guard = LOG_PATH.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(p) = guard.as_ref() {
        return Ok(p.clone());
    }
    let dir = logs_dir();
    create_dir_all(&dir)?;
    let name = format!(
        "firewall_{}.log",
        chrono_today()
    );
    let path = dir.join(name);
    *guard = Some(path.clone());
    Ok(path)
}

/// Без зависимости chrono — дата из системного времени.
fn chrono_today() -> String {
    local_ymd().unwrap_or_else(|| "unknown_date".into())
}

fn local_ymd() -> Option<String> {
    use windows::Win32::System::SystemInformation::GetLocalTime;
    let st = unsafe { GetLocalTime() };
    Some(format!(
        "{:04}-{:02}-{:02}",
        st.wYear, st.wMonth, st.wDay
    ))
}

fn stamp() -> String {
    use windows::Win32::System::SystemInformation::GetLocalTime;
    let st = unsafe { GetLocalTime() };
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond
    )
}

fn write_line(level: &str, msg: &str) {
    let Ok(path) = ensure_log_file() else {
        eprintln!("[{level}] {msg}");
        return;
    };
    let line = format!("[{}] [{level}] {msg}\n", stamp());
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&path) {
        let _ = f.write_all(line.as_bytes());
    }
    eprintln!("{line}");
}

pub fn info(msg: impl AsRef<str>) {
    write_line("INFO", msg.as_ref());
}

pub fn error(msg: impl AsRef<str>) {
    write_line("ERROR", msg.as_ref());
}

pub fn action(msg: impl AsRef<str>) {
    write_line("ACTION", msg.as_ref());
}

/// Путь к текущему файлу лога (если уже создан).
pub fn current_log_path() -> Option<PathBuf> {
    LOG_PATH
        .lock()
        .ok()
        .and_then(|g| g.clone())
        .or_else(|| ensure_log_file().ok())
}
