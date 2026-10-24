//! Состояние приложения и компоновка главного окна.
//! Секции интерфейса и их действия находятся в приватных подмодулях `ui/`.

mod components;
mod duplicates;
mod form;
mod help;
mod native;
mod network_panel;
mod rules;
mod widgets;

use self::components::{ComponentJobResult, ComponentOp, WinComponent};
use self::native::{install_move_hook, install_move_hook_frame, load_header_icon};
use self::widgets::styled_button;
use egui::{Color32, RichText};
use firewall_windows::{
    admin, logutil,
    model::FirewallRule,
    network::NetworkAdapter,
    optional_features::FeatureState,
    theme::{self, ACCENT, BG_DEEP},
};
use std::{sync::mpsc::Receiver, time::Instant};

#[derive(Clone, Copy, PartialEq, Eq)]
enum SortColumn {
    Name,
    Direction,
    Action,
    Protocol,
    Ports,
    Application,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SortDir {
    Asc,
    Desc,
}

pub struct FirewallApp {
    form: FirewallRule,
    /// Исходный снимок выбранной копии для проверки перед сохранением.
    editing_rule: Option<FirewallRule>,
    rules: Vec<FirewallRule>,
    selected: Option<usize>,
    status: StatusMsg,
    filter: String,
    duplicates_only: bool,
    duplicates: duplicates::DuplicateIndex,
    loaded: bool,
    header_icon: Option<egui::TextureHandle>,
    is_admin: bool,
    sort_col: SortColumn,
    sort_dir: SortDir,
    /// Отдельное системное окно списка правил.
    rules_window_open: bool,
    help_window_open: bool,
    /// Кэш фильтра/сортировки — не пересчитывать каждый кадр.
    cached_indices: Vec<usize>,
    indices_dirty: bool,
    /// Кэш папок SSH (exists на диск каждый кадр — главный тормоз при drag).
    ssh_folders: Vec<(String, std::path::PathBuf, bool)>,
    telnet_state: FeatureState,
    ssh_client_state: FeatureState,
    ssh_server_state: FeatureState,
    /// Текущая фоновая операция компонента (кнопки заблокированы).
    component_job: Option<(WinComponent, ComponentOp)>,
    component_rx: Option<Receiver<ComponentJobResult>>,
    network_adapters: Vec<NetworkAdapter>,
    network_rx: Option<Receiver<Result<Vec<NetworkAdapter>, String>>>,
    network_error: Option<String>,
    network_loaded: bool,
    next_network_refresh: Instant,
}

enum StatusMsg {
    None,
    Ok(String),
    Err(String),
}

impl Default for FirewallApp {
    fn default() -> Self {
        Self {
            form: FirewallRule::default(),
            editing_rule: None,
            rules: Vec::new(),
            selected: None,
            status: StatusMsg::None,
            filter: String::new(),
            duplicates_only: false,
            duplicates: duplicates::DuplicateIndex::default(),
            loaded: false,
            header_icon: None,
            is_admin: admin::is_elevated(),
            sort_col: SortColumn::Name,
            sort_dir: SortDir::Asc,
            rules_window_open: false,
            help_window_open: false,
            cached_indices: Vec::new(),
            indices_dirty: true,
            ssh_folders: Vec::new(),
            telnet_state: FeatureState::Unknown("проверка…".into()),
            ssh_client_state: FeatureState::Unknown("проверка…".into()),
            ssh_server_state: FeatureState::Unknown("проверка…".into()),
            component_job: None,
            component_rx: None,
            network_adapters: Vec::new(),
            network_rx: None,
            network_error: None,
            network_loaded: false,
            next_network_refresh: Instant::now(),
        }
    }
}

impl FirewallApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        theme::apply(&cc.egui_ctx);
        install_move_hook(cc);
        let mut app = Self::default();
        app.header_icon = load_header_icon(&cc.egui_ctx);
        for &c in WinComponent::ALL {
            app.refresh_component_state(c);
        }
        app.refresh_ssh_folders();
        app.reload();
        app.start_network_refresh(&cc.egui_ctx);
        app
    }

    fn set_ok(&mut self, msg: impl Into<String>) {
        let msg = msg.into();
        logutil::action(&msg);
        self.status = StatusMsg::Ok(msg);
    }

    fn set_err(&mut self, msg: impl Into<String>) {
        let msg = msg.into();
        logutil::error(&msg);
        self.status = StatusMsg::Err(msg);
    }

    fn relaunch_admin(&mut self) {
        match admin::relaunch_as_admin() {
            Ok(()) => {
                std::process::exit(0);
            }
            Err(e) => self.set_err(e),
        }
    }
}

impl FirewallApp {
    fn draw_header(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("title_bar")
            .frame(egui::Frame::NONE.fill(BG_DEEP).inner_margin(10.0))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    if let Some(tex) = &self.header_icon {
                        ui.add(egui::Image::new(tex).fit_to_exact_size(egui::vec2(28.0, 28.0)));
                        ui.add_space(6.0);
                    }
                    ui.vertical(|ui| {
                        ui.add(
                            egui::Label::new(
                                RichText::new(format!(
                                    "Windows Firewall Manager {}",
                                    env!("CARGO_PKG_VERSION")
                                ))
                                .color(Color32::WHITE)
                                .strong()
                                .size(22.0),
                            )
                            .selectable(false),
                        );
                        ui.add(
                            egui::Label::new(
                                RichText::new("create by Kenshin")
                                    .color(Color32::from_rgb(0xB8, 0xDC, 0xEE))
                                    .size(13.0),
                            )
                            .selectable(false),
                        );
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if self.is_admin {
                            ui.add(
                                egui::Label::new(
                                    RichText::new("Администратор")
                                        .color(Color32::from_rgb(0x7E, 0xE0, 0xB0))
                                        .strong()
                                        .size(15.0),
                                )
                                .selectable(false),
                            );
                        } else {
                            if styled_button(
                                ui,
                                "Запуск от администратора",
                                ACCENT,
                                Color32::WHITE,
                                egui::Stroke::new(1.8_f32, BG_DEEP),
                                10.0,
                                15.0,
                                None,
                                true,
                            )
                            .clicked()
                            {
                                self.relaunch_admin();
                            }
                            ui.add(
                                egui::Label::new(
                                    RichText::new("Обычный пользователь")
                                        .color(Color32::from_rgb(0xF0, 0xC0, 0x80))
                                        .strong(),
                                )
                                .selectable(false),
                            );
                        }
                    });
                });
            });
    }

    fn draw_status_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.add_space(4.0);
            match &self.status {
                StatusMsg::None => {
                    ui.label(
                        RichText::new("Готово к работе")
                            .strong()
                            .color(theme::muted(ui)),
                    );
                }
                StatusMsg::Ok(m) => {
                    ui.label(RichText::new(m).strong().color(theme::success(ui)));
                }
                StatusMsg::Err(m) => {
                    ui.label(RichText::new(m).strong().color(theme::danger(ui)));
                }
            }
            ui.add_space(4.0);
        });
    }

    fn draw_workspace(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default()
            .frame(egui::Frame::NONE.inner_margin(12.0))
            .show(ctx, |ui| {
                let h = ui.available_height();
                let total = ui.available_width();
                let network_w = (total * 0.31).clamp(240.0, 340.0);
                let form_w = (total - network_w - 20.0).max(440.0);
                ui.horizontal_top(|ui| {
                    ui.allocate_ui_with_layout(
                        egui::vec2(form_w, h),
                        egui::Layout::top_down(egui::Align::Min),
                        |ui| {
                            self.draw_form_column(ui);
                        },
                    );
                    ui.separator();
                    ui.allocate_ui_with_layout(
                        egui::vec2(network_w, h),
                        egui::Layout::top_down(egui::Align::Min),
                        |ui| {
                            self.draw_network_panel(ui, h);
                        },
                    );
                });
            });
    }
}

impl eframe::App for FirewallApp {
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        self.poll_component_job();
        self.poll_network(ctx);
        if self.component_busy() {
            // Не крутить 60 FPS зря — опрос фона раз в ~100 мс.
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }

        self.draw_header(ctx);
        self.draw_status_bar(ctx);
        self.draw_workspace(ctx);
        self.draw_rules_window(ctx);
        self.draw_help_window(ctx);
        // Include the detached rules window once its native HWND has been created.
        install_move_hook_frame(frame);
    }
}

#[cfg(test)]
mod tests;
