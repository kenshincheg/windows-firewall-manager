#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod ui;

use eframe::egui;
use eframe::wgpu;
use std::sync::Arc;

fn main() {
    install_panic_hook();
    firewall_windows::logutil::info("Старт приложения");

    // Авто-запрос UAC: без прав админа сразу просим повышение.
    if !firewall_windows::admin::is_elevated() {
        firewall_windows::logutil::info("Нет прав администратора — запрос UAC (runas)");
        match firewall_windows::admin::relaunch_as_admin() {
            Ok(()) => {
                firewall_windows::logutil::info("UAC принят, завершаем неподнятый процесс");
                std::process::exit(0);
            }
            Err(e) => {
                firewall_windows::logutil::error(format!("UAC отклонён/ошибка: {e}"));
                show_error_dialog(&format!(
                    "{e}\n\nПрограмма продолжит работу без прав администратора.\n\
                     Добавление и удаление правил будут недоступны."
                ));
            }
        }
    }

    let result = run_with_renderer(false).or_else(|e1| {
        eprintln!("Обычный DX12/wgpu не поднялся: {e1}. Пробуем WARP (software)...");
        run_with_renderer(true)
    });

    if let Err(e) = result {
        let msg = format!(
            "Не удалось запустить графику.\n\n{e}\n\n\
             На системах без драйверов видеокарты нужен DX12 WARP \
             (обычно есть в Windows 10/11). Обновите «Microsoft Basic Display Adapter» \
             или установите базовые драйверы дисплея."
        );
        eprintln!("{msg}");
        show_error_dialog(&msg);
        std::process::exit(1);
    }
}

fn install_panic_hook() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let msg = format!("Критическая ошибка при запуске:\n\n{info}");
        show_error_dialog(&msg);
        default_hook(info);
    }));
}

fn load_app_icon() -> Option<egui::IconData> {
    let bytes = include_bytes!("../assets/icon.png");
    let image = image::load_from_memory(bytes).ok()?.into_rgba8();
    let (width, height) = image.dimensions();
    Some(egui::IconData {
        rgba: image.into_raw(),
        width,
        height,
    })
}

fn run_with_renderer(force_warp: bool) -> eframe::Result {
    let title = if force_warp {
        "Windows Firewall Manager (WARP)"
    } else {
        "Windows Firewall Manager"
    };

    let mut viewport = egui::ViewportBuilder::default()
        .with_inner_size([1180.0, 820.0])
        .with_min_inner_size([1000.0, 620.0])
        .with_title(format!("{title} {}", env!("CARGO_PKG_VERSION")));

    if let Some(icon) = load_app_icon() {
        viewport = viewport.with_icon(Arc::new(icon));
    }

    let wgpu_options = eframe::egui_wgpu::WgpuConfiguration {
        // AutoVsync (Fifo) при перетаскивании окна часто «цепляется» за DWM и даёт рывки.
        // AutoNoVsync → Mailbox/Immediate с откатом — окно двигается заметно плавнее.
        present_mode: wgpu::PresentMode::AutoNoVsync,
        desired_maximum_frame_latency: Some(2),
        wgpu_setup: eframe::egui_wgpu::WgpuSetup::CreateNew(
            eframe::egui_wgpu::WgpuSetupCreateNew {
                instance_descriptor: wgpu::InstanceDescriptor {
                    // DX12 обязателен: egui-wgpu по умолчанию не включает backends.
                    backends: wgpu::Backends::DX12,
                    ..Default::default()
                },
                power_preference: if force_warp {
                    wgpu::PowerPreference::LowPower
                } else {
                    wgpu::PowerPreference::HighPerformance
                },
                native_adapter_selector: Some(Arc::new(move |adapters, _surface| {
                    select_adapter(adapters, force_warp)
                })),
                device_descriptor: Arc::new(|adapter| {
                    let base_limits = if adapter.get_info().backend == wgpu::Backend::Gl {
                        wgpu::Limits::downlevel_webgl2_defaults()
                    } else {
                        wgpu::Limits::default()
                    };
                    wgpu::DeviceDescriptor {
                        label: Some("firewall_windows"),
                        required_limits: base_limits,
                        ..Default::default()
                    }
                }),
            },
        ),
        ..Default::default()
    };

    let options = eframe::NativeOptions {
        viewport,
        renderer: eframe::Renderer::Wgpu,
        wgpu_options,
        vsync: false,
        ..Default::default()
    };

    eframe::run_native(
        "Windows Firewall Manager",
        options,
        Box::new(|cc| Ok(Box::new(ui::FirewallApp::new(cc)))),
    )
}

fn select_adapter(
    adapters: &[wgpu::Adapter],
    force_warp: bool,
) -> Result<wgpu::Adapter, String> {
    if adapters.is_empty() {
        return Err("DX12-адаптеры не найдены".into());
    }

    let is_warp = |a: &wgpu::Adapter| {
        let info = a.get_info();
        let name = info.name.to_lowercase();
        name.contains("warp")
            || name.contains("microsoft basic render")
            || info.device_type == wgpu::DeviceType::Cpu
    };

    let chosen = if force_warp {
        adapters
            .iter()
            .find(|a| is_warp(a))
            .unwrap_or(&adapters[0])
            .clone()
    } else {
        adapters
            .iter()
            .find(|a| !is_warp(a))
            .unwrap_or(&adapters[0])
            .clone()
    };
    let info = chosen.get_info();
    firewall_windows::logutil::info(format!(
        "wgpu adapter: {} ({:?}, {:?})",
        info.name, info.backend, info.device_type
    ));
    Ok(chosen)
}

fn show_error_dialog(msg: &str) {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK};

    fn wide(s: &str) -> Vec<u16> {
        std::ffi::OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    let text = wide(msg);
    let caption = wide("Windows Firewall Manager");
    unsafe {
        let _ = MessageBoxW(
            None,
            PCWSTR(text.as_ptr()),
            PCWSTR(caption.as_ptr()),
            MB_OK | MB_ICONERROR,
        );
    }
}
