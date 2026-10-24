//! Keep the last composited frame while Windows moves an unchanged client area.
//!
//! A move does not change the layout: DWM can move the existing surface. Avoid
//! sending its redundant WM_PAINT messages through egui, tessellation and DX12.
//! Resize and DPI changes still render, and exiting the move forces a fresh frame.

use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::Graphics::Gdi::{
    RDW_INVALIDATE, RDW_NOERASE, RDW_NOINTERNALPAINT, RDW_VALIDATE, RedrawWindow,
};
use windows::Win32::UI::Shell::{
    DefSubclassProc, GetWindowSubclass, RemoveWindowSubclass, SetWindowSubclass,
};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumThreadWindows, GetWindowThreadProcessId, WM_DPICHANGED, WM_ENTERSIZEMOVE, WM_EXITSIZEMOVE,
    WM_MOVING, WM_NCDESTROY, WM_PAINT, WM_SIZE, WM_SIZING,
};
use windows::core::BOOL;

const SUBCLASS_ID: usize = 0x4657_4D56;
const MOVING: usize = 1;
const RESIZING: usize = 2;
const NEEDS_PAINT: usize = 4;

// Stored per HWND in subclass reference data, never shared across windows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct RepaintState(usize);

impl RepaintState {
    fn preserve_frame(self) -> bool {
        self.0 == MOVING
    }

    fn on_message(self, message: u32) -> Self {
        Self(match message {
            WM_ENTERSIZEMOVE | WM_EXITSIZEMOVE | WM_NCDESTROY => 0,
            WM_MOVING => MOVING | (self.0 & NEEDS_PAINT),
            WM_SIZING => RESIZING | (self.0 & NEEDS_PAINT),
            WM_SIZE | WM_DPICHANGED => self.0 | NEEDS_PAINT,
            WM_PAINT => self.0 & !NEEDS_PAINT,
            _ => self.0,
        })
    }
}

pub fn install(hwnd: HWND) {
    if hwnd.0.is_null() {
        return;
    }
    unsafe {
        if GetWindowSubclass(hwnd, Some(subclass_proc), SUBCLASS_ID, None).as_bool() {
            return;
        }
        if !SetWindowSubclass(hwnd, Some(subclass_proc), SUBCLASS_ID, 0).as_bool() {
            crate::logutil::error("Не удалось установить обработчик перемещения окна");
        }
    }
}

/// Include secondary native viewports belonging to the same GUI thread.
pub fn install_thread_windows(hwnd: HWND) {
    unsafe {
        let thread_id = GetWindowThreadProcessId(hwnd, None);
        if thread_id != 0 {
            let _ = EnumThreadWindows(thread_id, Some(install_window), LPARAM(0));
        }
    }
}

unsafe extern "system" fn install_window(hwnd: HWND, _: LPARAM) -> BOOL {
    install(hwnd);
    BOOL(1)
}

unsafe extern "system" fn subclass_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
    _uid: usize,
    data: usize,
) -> LRESULT {
    let state = RepaintState(data);
    let next = state.on_message(msg);
    unsafe {
        if next != state {
            let _ = SetWindowSubclass(hwnd, Some(subclass_proc), SUBCLASS_ID, next.0);
        }
        if msg == WM_PAINT && state.preserve_frame() {
            // Validate without erasing or presenting a replacement surface.
            // https://learn.microsoft.com/windows/win32/gdi/wm-paint
            let _ = RedrawWindow(
                Some(hwnd),
                None,
                None,
                RDW_VALIDATE | RDW_NOINTERNALPAINT | RDW_NOERASE,
            );
            return LRESULT(0);
        }
        if msg == WM_NCDESTROY {
            let _ = RemoveWindowSubclass(hwnd, Some(subclass_proc), SUBCLASS_ID);
        }
        let result = DefSubclassProc(hwnd, msg, wparam, lparam);
        if msg == WM_EXITSIZEMOVE {
            let _ = RedrawWindow(Some(hwnd), None, None, RDW_INVALIDATE | RDW_NOERASE);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn moving_preserves_surface_and_exit_restores_paint() {
        let state = RepaintState::default()
            .on_message(WM_ENTERSIZEMOVE)
            .on_message(WM_MOVING);
        assert!(state.preserve_frame());
        assert!(state.on_message(WM_PAINT).preserve_frame());
        assert!(!state.on_message(WM_EXITSIZEMOVE).preserve_frame());
        assert!(!state.on_message(WM_NCDESTROY).preserve_frame());
    }

    #[test]
    fn resizing_never_skips_paint() {
        let state = RepaintState::default()
            .on_message(WM_ENTERSIZEMOVE)
            .on_message(WM_SIZING);
        assert!(!state.preserve_frame());
        assert!(
            !state
                .on_message(WM_SIZE)
                .on_message(WM_PAINT)
                .preserve_frame()
        );
    }

    #[test]
    fn dpi_or_size_change_during_move_gets_a_fresh_frame() {
        for message in [WM_DPICHANGED, WM_SIZE] {
            let state = RepaintState(MOVING)
                .on_message(message)
                .on_message(WM_MOVING);
            assert!(!state.preserve_frame());
            assert!(state.on_message(WM_PAINT).preserve_frame());
        }
    }

    #[test]
    fn windows_have_independent_paint_state() {
        let main = RepaintState::default().on_message(WM_MOVING);
        let rules = RepaintState::default().on_message(WM_SIZING);
        assert!(main.preserve_frame());
        assert!(!rules.preserve_frame());
    }
}
