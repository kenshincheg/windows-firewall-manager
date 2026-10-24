//! Проверка elevation и перезапуск с правами администратора.

use std::os::windows::ffi::OsStrExt;
use windows::core::PCWSTR;
use windows::Win32::UI::Shell::{IsUserAnAdmin, ShellExecuteW};
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

/// Запущено ли текущее процесс с правами администратора.
pub fn is_elevated() -> bool {
    unsafe { IsUserAnAdmin().as_bool() }
}

/// Перезапуск текущего exe через UAC (`runas`). При успехе текущий процесс нужно завершить.
pub fn relaunch_as_admin() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| format!("Не удалось найти exe: {e}"))?;
    let exe_wide: Vec<u16> = exe
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let op: Vec<u16> = "runas\0".encode_utf16().collect();
    let dir = exe
        .parent()
        .map(|p| {
            p.as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect::<Vec<u16>>()
        })
        .unwrap_or_else(|| vec![0]);

    let result = unsafe {
        ShellExecuteW(
            None,
            PCWSTR(op.as_ptr()),
            PCWSTR(exe_wide.as_ptr()),
            PCWSTR::null(),
            PCWSTR(dir.as_ptr()),
            SW_SHOWNORMAL,
        )
    };

    // ShellExecute возвращает значение > 32 при успехе (как HINSTANCE).
    let code = result.0 as isize;
    if code <= 32 {
        Err(format!(
            "Не удалось запросить повышение прав (код {code}). Возможно, UAC отклонён."
        ))
    } else {
        Ok(())
    }
}
