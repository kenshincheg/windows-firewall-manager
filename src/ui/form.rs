//! Форма создания и редактирования правила и шаблоны портов.

use super::{
    FirewallApp, StatusMsg,
    widgets::{choice_chip, rounded_field, styled_button},
};
use egui::{Color32, RichText, Ui};
use firewall_windows::{
    file_dialog, firewall,
    model::{Action, Direction, FirewallRule, Profiles, Protocol, validate_rule},
    templates::{self, TEMPLATES},
    theme::{self, ACCENT, BG_DEEP, DANGER, FOCUS_RING, OK, bold},
};

impl FirewallApp {
    fn apply_template(&mut self, index: usize) {
        if let Some(t) = TEMPLATES.get(index) {
            templates::apply(t, &mut self.form);
            self.editing_rule = None;
            self.set_ok(format!("Шаблон «{}» подставлен в форму", t.label));
        }
    }

    pub(super) fn clear_form(&mut self) {
        self.editing_rule = None;
        self.form = FirewallRule {
            profiles: Profiles::default(),
            ..FirewallRule::default()
        };
    }

    pub(super) fn add_or_save(&mut self) {
        if !self.is_admin {
            self.set_err("Для изменения правил нужны права администратора");
            return;
        }
        if let Err(e) = validate_rule(&self.form) {
            self.set_err(e);
            return;
        }

        let (result, verb) = match self.editing_rule.as_ref() {
            Some(original) => (
                firewall::update_rule_snapshot(original, &self.form),
                "обновлено",
            ),
            None => (firewall::add_rule(&self.form), "добавлено"),
        };
        match result {
            Ok(()) => {
                let name = self.form.name.trim().to_string();
                self.clear_form();
                self.reload();
                if matches!(self.status, StatusMsg::Ok(_)) {
                    self.set_ok(format!("Правило «{name}» {verb}"));
                }
                self.open_rules_window();
            }
            Err(error) => self.set_err(error),
        }
    }

    fn form_title(&self) -> &'static str {
        if self.editing_rule.is_some() {
            "Редактирование правила"
        } else {
            "Новое правило"
        }
    }

    fn draw_form_toolbar(&mut self, ui: &mut Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new(self.form_title()).strong().size(17.0));
            if let Some(rule) = &self.editing_rule {
                ui.label(
                    RichText::new(format!("({})", rule.name))
                        .small()
                        .color(theme::muted(ui)),
                );
            }
        });
        ui.horizontal(|ui| {
            if styled_button(
                ui,
                "Существующие правила",
                ACCENT,
                Color32::WHITE,
                egui::Stroke::new(1.8_f32, BG_DEEP),
                8.0,
                16.0,
                None,
                true,
            )
            .clicked()
            {
                self.open_rules_window();
                ui.ctx().send_viewport_cmd_to(
                    egui::ViewportId::from_hash_of("rules_window"),
                    egui::ViewportCommand::Focus,
                );
            }
            if styled_button(
                ui,
                "Как настроить правило",
                theme::field(ui),
                theme::text(ui),
                egui::Stroke::new(1.8_f32, ACCENT),
                8.0,
                16.0,
                None,
                true,
            )
            .clicked()
            {
                self.help_window_open = true;
                ui.ctx().send_viewport_cmd_to(
                    egui::ViewportId::from_hash_of("help_window"),
                    egui::ViewportCommand::Focus,
                );
            }
        });
    }

    /// Колонка формы — один и тот же вид всегда.
    pub(super) fn draw_form_column(&mut self, ui: &mut Ui) {
        self.draw_form_toolbar(ui);
        ui.add_space(6.0);
        egui::ScrollArea::vertical()
            .id_salt("form_scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                self.draw_templates(ui);
                ui.add_space(6.0);
                self.draw_form_fields(ui);
                ui.add_space(8.0);
                self.draw_form_buttons(ui);
                ui.add_space(12.0);
                self.draw_windows_components(ui);
            });
    }

    fn draw_templates(&mut self, ui: &mut Ui) {
        ui.label(bold("Шаблоны портов"));
        let columns = if ui.available_width() >= 600.0 { 3 } else { 2 };
        let width = ((ui.available_width() - 6.0 * (columns - 1) as f32) / columns as f32).floor();
        egui::Grid::new("template_grid")
            .num_columns(columns)
            .spacing([6.0, 6.0])
            .show(ui, |ui| {
                ui.spacing_mut().button_padding = egui::vec2(6.0, 5.0);
                for (i, t) in TEMPLATES.iter().enumerate() {
                    let response = styled_button(
                        ui,
                        t.label,
                        theme::field(ui),
                        theme::text(ui),
                        egui::Stroke::new(1.0_f32, ACCENT),
                        6.0,
                        14.0,
                        Some(egui::vec2(width, 30.0)),
                        true,
                    );
                    if response.clicked() {
                        self.apply_template(i);
                    }
                    if (i + 1) % columns == 0 {
                        ui.end_row();
                    }
                }
            });
        ui.add_space(4.0);
        ui.separator();
    }

    fn draw_form_fields(&mut self, ui: &mut Ui) {
        egui::Grid::new("form_grid")
            .num_columns(2)
            .spacing([12.0, 10.0])
            .show(ui, |ui| {
                ui.label(bold("Имя:"));
                rounded_field(ui, &mut self.form.name, "например FTP_21", FOCUS_RING);
                ui.end_row();

                ui.label(bold("Описание:"));
                rounded_field(ui, &mut self.form.description, "необязательно", ACCENT);
                ui.end_row();

                ui.label(bold("Направление:"));
                choice_options(
                    ui,
                    &mut self.form.direction,
                    &[(Direction::Inbound, ACCENT), (Direction::Outbound, ACCENT)],
                    Direction::label,
                );
                ui.end_row();

                ui.label(bold("Действие:"));
                choice_options(
                    ui,
                    &mut self.form.action,
                    &[(Action::Allow, OK), (Action::Block, DANGER)],
                    Action::label,
                );
                ui.end_row();

                ui.label(bold("Протокол:"));
                choice_options(
                    ui,
                    &mut self.form.protocol,
                    &[
                        (Protocol::Tcp, ACCENT),
                        (Protocol::Udp, ACCENT),
                        (Protocol::Any, ACCENT),
                    ],
                    Protocol::label,
                );
                ui.end_row();

                ui.label(bold("Порты:"));
                rounded_field(
                    ui,
                    &mut self.form.local_ports,
                    "21  или  45512-65534",
                    Color32::from_rgb(0x3A, 0xA0, 0x6A),
                );
                ui.end_row();

                ui.label(bold("Программа:"));
                self.draw_program_field(ui);
                ui.end_row();

                ui.label(bold("Профили:"));
                self.draw_profile_fields(ui);
                ui.end_row();

                ui.label(bold("Включено:"));
                ui.checkbox(&mut self.form.enabled, RichText::new("да").strong())
                    .on_hover_text(
                        "Активность правила\nСнимите флажок, чтобы сохранить правило выключенным.",
                    );
                ui.end_row();
            });
    }

    fn draw_form_buttons(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            let save_label = if self.editing_rule.is_some() {
                "Сохранить"
            } else {
                "Добавить правило"
            };
            if styled_button(
                ui,
                save_label,
                ACCENT,
                Color32::WHITE,
                egui::Stroke::new(1.8_f32, BG_DEEP),
                10.0,
                16.0,
                None,
                true,
            )
            .clicked()
            {
                self.add_or_save();
            }
            if self.editing_rule.is_some() {
                if choice_chip(ui, "Отмена", false, Color32::WHITE, theme::text(ui), ACCENT)
                    .clicked()
                {
                    self.clear_form();
                    self.status = StatusMsg::Ok("Редактирование отменено".into());
                }
            } else if choice_chip(
                ui,
                "Очистить форму",
                false,
                Color32::WHITE,
                theme::text(ui),
                ACCENT,
            )
            .clicked()
            {
                self.clear_form();
            }
        });
    }
    fn draw_program_field(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            rounded_field(
                ui,
                &mut self.form.application_path,
                r"C:\Path\app.exe (необязательно)",
                Color32::from_rgb(0x6A, 0x5A, 0xC8),
            );
            if styled_button(
                ui,
                "Обзор…",
                ACCENT,
                Color32::WHITE,
                egui::Stroke::new(1.8_f32, BG_DEEP),
                10.0,
                16.0,
                None,
                true,
            )
            .clicked()
            {
                if let Some(path) = file_dialog::pick_executable() {
                    self.form.application_path = path;
                    self.set_ok("Путь к программе выбран");
                }
            }
        });
    }

    fn draw_profile_fields(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            ui.checkbox(
                &mut self.form.profiles.domain,
                RichText::new("Domain").strong(),
            )
            .on_hover_text("Доменная сеть\nСеть организации с доменной аутентификацией.");
            ui.checkbox(
                &mut self.form.profiles.private,
                RichText::new("Private").strong(),
            )
            .on_hover_text("Частная сеть\nДомашняя или другая доверенная сеть.");
            ui.checkbox(
                &mut self.form.profiles.public,
                RichText::new("Public").strong(),
            )
            .on_hover_text("Общедоступная сеть\nНапример, Wi-Fi в кафе или гостинице.");
        });
    }
}

/// Keep the same horizontal layout and per-choice color for each enum field.
fn choice_options<T: Copy + PartialEq>(
    ui: &mut Ui,
    selected: &mut T,
    options: &[(T, Color32)],
    label: fn(T) -> &'static str,
) {
    ui.horizontal(|ui| {
        for &(value, color) in options {
            if choice_chip(
                ui,
                label(value),
                *selected == value,
                Color32::WHITE,
                theme::text(ui),
                color,
            )
            .clicked()
            {
                *selected = value;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_save_preserves_editing_draft() {
        let mut app = FirewallApp::default();
        app.is_admin = true;
        app.editing_rule = Some(FirewallRule {
            name: "Existing rule".into(),
            ..Default::default()
        });
        app.form.local_ports = "22".into();
        app.add_or_save();
        assert!(matches!(app.status, StatusMsg::Err(_)));
        assert_eq!(
            app.editing_rule.as_ref().map(|rule| rule.name.as_str()),
            Some("Existing rule")
        );
        assert_eq!(app.form.local_ports, "22");
        assert!(!app.rules_window_open);
    }

    #[test]
    fn unelevated_save_never_reaches_firewall_api() {
        let mut app = FirewallApp {
            is_admin: false,
            form: FirewallRule {
                name: "Valid but unauthorized".into(),
                local_ports: "22".into(),
                ..Default::default()
            },
            ..Default::default()
        };
        app.add_or_save();
        assert!(
            matches!(&app.status, StatusMsg::Err(message) if message.contains("администратора"))
        );
        assert_eq!(app.form.name, "Valid but unauthorized");
        assert!(app.rules.is_empty());
    }
}
