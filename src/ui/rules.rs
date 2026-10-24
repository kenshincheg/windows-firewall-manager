//! Окно правил: загрузка, поиск, сортировка, редактирование и таблица.

use super::{
    FirewallApp, SortColumn, SortDir, StatusMsg,
    widgets::{choice_chip, choice_chip_enabled, help_hover, styled_button},
};
use egui::{Color32, RichText, TextEdit, Ui};
use firewall_windows::model::FirewallRule;

use firewall_windows::{
    firewall,
    theme::{self, ACCENT, BG_DEEP, BG_MID, DANGER, bold},
};

mod query;
mod table;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod live_tests;

impl FirewallApp {
    pub(super) fn reload(&mut self) {
        match firewall::list_rules() {
            Ok(rules) => {
                let n = rules.len();
                self.replace_rules(rules);
                self.set_ok(format!("Загружено правил: {n}"));
            }
            Err(e) => self.set_err(e),
        }
        self.loaded = true;
    }

    fn replace_rules(&mut self, rules: Vec<FirewallRule>) {
        self.duplicates = super::duplicates::DuplicateIndex::build(&rules);
        self.rules = rules;
        self.selected = None;
        self.invalidate_indices();
    }

    pub(super) fn open_rules_window(&mut self) {
        self.rules_window_open = true;
    }

    pub(super) fn close_rules_window(&mut self) {
        self.rules_window_open = false;
    }

    pub(super) fn load_selected_for_edit(&mut self) {
        let Some(idx) = self.require_selected_rule_index() else {
            return;
        };
        let rule = self.rules[idx].clone();
        if matches!(rule.protocol, firewall_windows::model::Protocol::Other(_)) {
            self.set_err("Этот протокол пока нельзя редактировать в форме программы. Используйте расширенные настройки Windows Firewall");
            return;
        }
        self.editing_rule = Some(rule.clone());
        self.form = rule;
        self.close_rules_window();
        self.set_ok("Режим редактирования: измените поля и нажмите «Сохранить»");
    }

    fn remove_selected(&mut self) {
        let Some(idx) = self.require_selected_rule_index() else {
            return;
        };
        if !self.is_admin {
            self.set_err("Для удаления правила нужны права администратора");
            return;
        }
        let rule = &self.rules[idx];
        let name = rule.name.clone();
        let clears_editing = self.editing_rule.as_ref() == Some(rule);
        match firewall::remove_rule_snapshot(rule) {
            Ok(()) => {
                if clears_editing {
                    self.clear_form();
                }
                self.reload();
                if matches!(self.status, StatusMsg::Ok(_)) {
                    self.set_ok(format!("Одна копия правила «{name}» удалена"));
                }
            }
            Err(e) => self.set_err(e),
        }
    }

    pub(super) fn draw_rules_window(&mut self, ctx: &egui::Context) {
        if !self.rules_window_open {
            return;
        }
        ctx.show_viewport_immediate(
            egui::ViewportId::from_hash_of("rules_window"),
            egui::ViewportBuilder::default()
                .with_title(format!(
                    "Существующие правила · {}",
                    env!("CARGO_PKG_VERSION")
                ))
                .with_inner_size([1120.0, 700.0])
                .with_min_inner_size([780.0, 480.0]),
            |ctx, class| {
                if ctx.input(|i| i.viewport().close_requested()) {
                    self.close_rules_window();
                }
                if class == egui::ViewportClass::Embedded {
                    let mut open = self.rules_window_open;
                    egui::Window::new("Существующие правила")
                        .open(&mut open)
                        .default_size([1000.0, 620.0])
                        .show(ctx, |ui| self.draw_list(ui));
                    self.rules_window_open &= open;
                } else {
                    egui::CentralPanel::default().show(ctx, |ui| self.draw_list(ui));
                }
                if !self.rules_window_open {
                    ctx.request_repaint_of(egui::ViewportId::ROOT);
                }
            },
        );
    }

    pub(super) fn draw_list(&mut self, ui: &mut Ui) {
        let list_height = (ui.available_height() - 28.0).max(200.0);

        egui::Frame::NONE
            .fill(theme::panel(ui))
            .corner_radius(10)
            .inner_margin(12.0)
            .stroke(egui::Stroke::new(2.0_f32, BG_MID))
            .show(ui, |ui| {
                ui.set_min_height(list_height);

                self.draw_rules_toolbar(ui);

                self.draw_rules_status(ui);
                self.draw_rules_filter(ui);

                self.draw_rules_table(ui);

                if self.cached_indices.is_empty() && self.loaded {
                    ui.label(
                        RichText::new(if self.duplicates_only {
                            "Дубли по текущему фильтру не найдены"
                        } else {
                            "Правила по текущему фильтру не найдены"
                        })
                        .color(theme::muted(ui)),
                    );
                }
            });
    }

    fn draw_rules_toolbar(&mut self, ui: &mut Ui) {
        // Заголовок + кнопки (вторая строка — не сжимают таблицу).
        ui.label(
            RichText::new("Существующие правила")
                .strong()
                .size(18.0)
                .color(theme::text(ui)),
        );
        ui.add_space(4.0);
        ui.horizontal_wrapped(|ui| {
            if styled_button(
                ui,
                "Закрыть окно",
                BG_MID,
                Color32::WHITE,
                egui::Stroke::new(1.8_f32, BG_DEEP),
                10.0,
                16.0,
                None,
                true,
            )
            .clicked()
            {
                self.close_rules_window();
            }
            if choice_chip(
                ui,
                "Обновить",
                false,
                Color32::WHITE,
                theme::text(ui),
                ACCENT,
            )
            .clicked()
            {
                self.reload();
            }
            let has_selection = self.selected_visible_index().is_some();
            if choice_chip_enabled(
                ui,
                "Изменить выбранное",
                false,
                Color32::WHITE,
                theme::text(ui),
                ACCENT,
                has_selection,
            )
            .clicked()
            {
                self.load_selected_for_edit();
                ui.ctx()
                    .send_viewport_cmd_to(egui::ViewportId::ROOT, egui::ViewportCommand::Focus);
            }
            if choice_chip_enabled(
                ui,
                "Удалить выбранное",
                false,
                Color32::WHITE,
                theme::text(ui),
                DANGER,
                has_selection && self.is_admin,
            )
            .clicked()
            {
                self.remove_selected();
            }
        });
    }

    fn draw_rules_status(&self, ui: &mut Ui) {
        match &self.status {
            StatusMsg::Err(message) => {
                ui.colored_label(theme::danger(ui), message);
            }
            StatusMsg::Ok(message) => {
                ui.colored_label(theme::success(ui), message);
            }
            StatusMsg::None => {}
        }
    }

    fn draw_rules_filter(&mut self, ui: &mut Ui) {
        ui.add_space(6.0);
        self.draw_rules_search(ui);
        self.draw_duplicates_filter(ui);
        self.draw_rules_summary(ui);
        ui.label(
            RichText::new("Клик по заголовку колонки — сортировка")
                .strong()
                .small()
                .color(theme::muted(ui)),
        );
        ui.add_space(6.0);
    }

    fn draw_rules_search(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            ui.label(bold("Фильтр:"));
            let edit = TextEdit::singleline(&mut self.filter)
                .desired_width(ui.available_width().clamp(200.0, 420.0))
                .hint_text("имя, порты или путь к программе")
                .frame(true);
            if ui.add(edit).changed() {
                self.rules_filter_changed();
            }
        });
    }

    fn draw_duplicates_filter(&mut self, ui: &mut Ui) {
        ui.horizontal_wrapped(|ui| {
            let toggle = ui.checkbox(&mut self.duplicates_only, "Только дубли");
            let changed = toggle.changed();
            help_hover(toggle, "Показывает все копии правил с одинаковыми условиями.\nИмена и описания могут различаться. Учитываются\nпрофили, IP-адреса, порты, программа, служба,\nинтерфейсы и дополнительные ограничения Windows.\nНомер перед именем обозначает группу дублей.");
            if changed {
                self.rules_filter_changed();
            }
            let count = self.duplicates.rule_count;
            ui.label(format!("Дубли: {count} правил в {} группах", self.duplicates.sizes.len()));
        });
        if self.duplicates_only {
            ui.label(
                RichText::new("Выберите лишнюю копию и нажмите «Удалить выбранное».")
                    .small()
                    .color(theme::muted(ui)),
            );
        }
    }

    fn draw_rules_summary(&mut self, ui: &mut Ui) {
        self.ensure_indices();
        ui.label(
            RichText::new(format!(
                "Показано: {} из {} правил",
                self.cached_indices.len(),
                self.rules.len()
            ))
            .small()
            .color(theme::muted(ui)),
        );
        let unreadable = self.duplicates.unreadable_count;
        if unreadable > 0 {
            help_hover(
                ui.label(
                    RichText::new(format!("Не проверено на дубли: {unreadable}"))
                        .small()
                        .color(theme::muted(ui)),
                ),
                "Windows не предоставила все условия этих правил.\nОни доступны в общем списке, но не считаются\nдублями на основании неполных данных.",
            );
        }
    }
}
