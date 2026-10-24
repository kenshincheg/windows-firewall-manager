//! Сетевые адаптеры: обновление кэша в фоне и закреплённая панель.

use super::{FirewallApp, widgets::styled_button};
use egui::{RichText, Ui};
use firewall_windows::{
    network::{self, NetworkAdapter},
    theme::{self, ACCENT},
};
use std::{
    sync::mpsc,
    time::{Duration, Instant},
};

impl FirewallApp {
    pub(super) fn start_network_refresh(&mut self, ctx: &egui::Context) {
        if self.network_rx.is_some() {
            return;
        }
        let (tx, rx) = mpsc::channel();
        self.network_rx = Some(rx);
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let _ = tx.send(network::list_adapters());
            ctx.request_repaint_of(egui::ViewportId::ROOT);
        });
    }

    pub(super) fn poll_network(&mut self, ctx: &egui::Context) {
        if let Some(rx) = &self.network_rx {
            let result = match rx.try_recv() {
                Ok(result) => Some(result),
                Err(mpsc::TryRecvError::Disconnected) => {
                    Some(Err("Проверка сети прервалась".into()))
                }
                Err(mpsc::TryRecvError::Empty) => None,
            };
            if let Some(result) = result {
                self.apply_network_result(result);
            }
        }
        if self.network_rx.is_none() {
            if Instant::now() >= self.next_network_refresh {
                self.start_network_refresh(ctx);
            } else {
                ctx.request_repaint_after(
                    self.next_network_refresh
                        .saturating_duration_since(Instant::now()),
                );
            }
        }
    }

    pub(super) fn draw_network_panel(&mut self, ui: &mut Ui, height: f32) {
        let width = ui.available_width();
        let bottom = ui.cursor().top() + height - 12.0;
        egui::Frame::NONE
            .fill(theme::field(ui))
            .corner_radius(8)
            .inner_margin(8.0)
            .stroke(ui.visuals().widgets.noninteractive.bg_stroke)
            .show(ui, |ui| {
                ui.set_width((width - 18.0).max(100.0));
                self.draw_network_header(ui);
                self.draw_network_summary(ui);
                egui::ScrollArea::vertical()
                    .id_salt("network_scroll")
                    .max_height((bottom - ui.cursor().top()).max(70.0))
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        self.draw_network_addresses(ui);
                    });
            });
    }

    fn apply_network_result(&mut self, result: Result<Vec<NetworkAdapter>, String>) {
        self.network_rx = None;
        self.next_network_refresh = Instant::now() + Duration::from_secs(15);
        match result {
            Ok(adapters) => {
                self.network_adapters = adapters;
                self.network_error = None;
                self.network_loaded = true;
            }
            Err(error) => self.network_error = Some(error),
        }
    }

    fn draw_network_header(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("Сеть компьютера").strong().size(17.0));
            if styled_button(
                ui,
                "Обновить сеть",
                theme::panel(ui),
                theme::text(ui),
                egui::Stroke::new(1.0_f32, ACCENT),
                6.0,
                12.0,
                None,
                self.network_rx.is_none(),
            )
            .clicked()
            {
                self.start_network_refresh(ui.ctx());
            }
        });
    }

    fn draw_network_summary(&self, ui: &mut Ui) {
        let count: usize = self
            .network_adapters
            .iter()
            .map(|a| a.addresses.len())
            .sum();
        ui.label(
            RichText::new(format!(
                "Адаптеров: {} · IP-адресов: {}",
                self.network_adapters.len(),
                count
            ))
            .small(),
        );
        if self.network_rx.is_some() {
            ui.label(RichText::new("Обновление…").small().color(theme::muted(ui)));
        } else {
            ui.label(
                RichText::new("Автообновление каждые 15 секунд")
                    .small()
                    .color(theme::muted(ui)),
            );
        }
        if let Some(error) = &self.network_error {
            ui.label(
                RichText::new(if self.network_loaded {
                    "Ошибка обновления · сохранены прежние данные"
                } else {
                    "Не удалось прочитать сеть"
                })
                .small()
                .color(theme::danger(ui)),
            )
            .on_hover_text(error);
        }
    }

    fn draw_network_addresses(&self, ui: &mut Ui) {
        if self.network_adapters.is_empty() {
            ui.label(if self.network_loaded {
                "Сетевые адаптеры не найдены"
            } else {
                "Чтение сетевых адаптеров…"
            });
        }
        for adapter in &self.network_adapters {
            draw_network_adapter(ui, adapter);
        }
    }
}

fn draw_network_adapter(ui: &mut Ui, adapter: &NetworkAdapter) {
    ui.separator();
    ui.add(egui::Label::new(RichText::new(&adapter.name).strong().size(15.0)).wrap());
    ui.label(
        RichText::new(format!("{} · {}", adapter.kind, adapter.status))
            .small()
            .color(if adapter.is_up {
                theme::success(ui)
            } else {
                theme::muted(ui)
            }),
    )
    .on_hover_text(&adapter.description);
    if adapter.addresses.is_empty() {
        ui.label(
            RichText::new("IP-адреса не назначены")
                .small()
                .color(theme::muted(ui)),
        );
    }
    for address in &adapter.addresses {
        ui.add(egui::Label::new(RichText::new(format!("{}  {}",
            if address.ip.is_ipv4() { "IPv4" } else { "IPv6" }, address.display()))
            .monospace().size(13.0)).wrap().selectable(true))
            .on_hover_text("Адрес этого адаптера и длина префикса сети.\nУ IPv6 после % указан номер области интерфейса.\nТекст можно выделить и скопировать сочетанием Ctrl+C.");
    }
    ui.add_space(5.0);
}
