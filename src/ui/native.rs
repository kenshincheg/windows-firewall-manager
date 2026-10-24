//! Иконка заголовка и подключение нативной оптимизации перемещения окон.

use firewall_windows::win_move;
use raw_window_handle::{HasWindowHandle, RawWindowHandle};
use windows::Win32::Foundation::HWND;

pub(super) fn load_header_icon(ctx: &egui::Context) -> Option<egui::TextureHandle> {
    let bytes = include_bytes!("../../assets/icon.png");
    let image = image::load_from_memory(bytes).ok()?.into_rgba8();
    let size = [image.width() as usize, image.height() as usize];
    let color = egui::ColorImage::from_rgba_unmultiplied(size, image.as_raw());
    Some(ctx.load_texture("header_icon", color, egui::TextureOptions::LINEAR))
}

fn hwnd_from_handle(handle: RawWindowHandle) -> Option<HWND> {
    match handle {
        RawWindowHandle::Win32(h) => Some(HWND(h.hwnd.get() as *mut _)),
        _ => None,
    }
}

pub(super) fn install_move_hook(cc: &eframe::CreationContext<'_>) {
    if let Ok(wh) = cc.window_handle() {
        if let Some(hwnd) = hwnd_from_handle(wh.as_raw()) {
            win_move::install(hwnd);
        }
    }
}

pub(super) fn install_move_hook_frame(frame: &eframe::Frame) {
    if let Ok(wh) = frame.window_handle() {
        if let Some(hwnd) = hwnd_from_handle(wh.as_raw()) {
            win_move::install_thread_windows(hwnd);
        }
    }
}
