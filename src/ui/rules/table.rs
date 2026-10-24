//! Виртуализированная таблица: строки, заголовки и оформление.

use super::super::widgets::styled_button;
use super::{FirewallApp, SortColumn, SortDir};
use egui::{Color32, Ui};
use firewall_windows::{
    model::FirewallRule,
    theme::{self, ACCENT},
};

type RuleColumns = [(SortColumn, &'static str, f32); 6];

fn format_ports_display(ports: &str) -> String {
    let s = ports.trim();
    if s.is_empty() {
        "—".into()
    } else if s == "*" {
        "все (*)".into()
    } else {
        truncate(s, 16)
    }
}

fn truncate(s: &str, max: usize) -> String {
    let mut chars = s.chars();
    let mut result: String = chars.by_ref().take(max).collect();
    if chars.next().is_some() {
        result.pop();
        result.push('…');
    }
    result
}

impl FirewallApp {
    fn draw_rule_row(
        &mut self,
        ui: &mut Ui,
        row: usize,
        cols: &RuleColumns,
        row_width: f32,
        row_height: f32,
    ) {
        let idx = self.cached_indices[row];
        let selected = self.selected == Some(idx);
        let rule = &self.rules[idx];
        let mut cells = rule_cells(rule, cols);
        let group = self.duplicates.group(idx);
        if self.duplicates_only
            && let Some(group) = group
        {
            cells[0] = format!("[{}] {}", group + 1, cells[0]);
        }

        let (fill, text_color, stroke) = rule_row_style(ui, selected, row);

        // Одна кликабельная строка вместо 6 Button — сильно дешевле при drag/scroll.
        let (row_rect, row_resp) =
            ui.allocate_exact_size(egui::vec2(row_width, row_height), egui::Sense::click());
        ui.painter()
            .rect(row_rect, 6.0, fill, stroke, egui::StrokeKind::Inside);
        paint_rule_cells(ui, row_rect, cols, &cells, row_height, text_color);
        let tooltip = |ui: &mut Ui| {
            // Текст собирается только при показе подсказки.
            let mut details = rule_details(rule);
            if let Some(group) = group {
                details.push_str(&format!(
                    "\n\nГруппа дублей №{}: {} правил с одинаковыми условиями.",
                    group + 1,
                    self.duplicates.sizes[group]
                ));
            }
            ui.set_max_width(320.0);
            ui.add(egui::Label::new(details).wrap());
        };
        let row_resp = row_resp.on_hover_ui(tooltip).on_disabled_hover_ui(tooltip);
        if row_resp.clicked() {
            self.selected = Some(idx);
        }
        if row_resp.double_clicked() {
            self.selected = Some(idx);
            self.load_selected_for_edit();
            ui.ctx()
                .send_viewport_cmd_to(egui::ViewportId::ROOT, egui::ViewportCommand::Focus);
        }
    }

    fn draw_rule_headers(&mut self, ui: &mut Ui, cols: &RuleColumns) {
        ui.horizontal(|ui| {
            ui.spacing_mut().button_padding = egui::vec2(4.0, 4.0);
            for &(col, label, width) in cols {
                let marker = if self.sort_col == col {
                    match self.sort_dir {
                        SortDir::Asc => " ^",
                        SortDir::Desc => " v",
                    }
                } else {
                    ""
                };
                let text = format!("{label}{marker}");
                let resp = styled_button(
                    ui,
                    &text,
                    theme::field(ui),
                    theme::text(ui),
                    egui::Stroke::new(1.5_f32, ACCENT),
                    8.0,
                    16.0,
                    Some(egui::vec2(width, 28.0)),
                    true,
                );
                if resp.clicked() {
                    self.toggle_sort(col);
                }
            }
        });
    }

    pub(super) fn draw_rules_table(&mut self, ui: &mut Ui) {
        let cols = rule_columns(ui.available_width());
        let row_width: f32 = cols.iter().map(|c| c.2).sum::<f32>() + 40.0;

        self.draw_rule_headers(ui, &cols);

        self.ensure_indices();
        let row_height = 28.0_f32;
        let row_count = self.cached_indices.len();
        let table_h = (ui.available_height() - 8.0).max(80.0);

        egui::ScrollArea::both()
            .id_salt("rules_body_scroll")
            .max_height(table_h)
            .auto_shrink([false, false])
            .show_rows(ui, row_height, row_count, |ui, row_range| {
                ui.set_min_width(row_width);
                for row in row_range {
                    self.draw_rule_row(ui, row, &cols, row_width, row_height);
                }
            });
    }
}

fn rule_cells(rule: &FirewallRule, cols: &RuleColumns) -> [String; 6] {
    let name_chars = ((cols[0].2 / 8.0) as usize).clamp(18, 64);
    let ports_chars = ((cols[4].2 / 8.0) as usize).clamp(8, 28);
    let app_chars = ((cols[5].2 / 8.0) as usize).clamp(14, 48);
    let name = truncate(&rule.name, name_chars);
    let ports = {
        let p = format_ports_display(&rule.local_ports);
        truncate(&p, ports_chars)
    };
    let app = if rule.application_path.is_empty() {
        "—".to_string()
    } else {
        truncate(&rule.application_path, app_chars)
    };
    [
        name,
        rule.direction.label().to_string(),
        rule.action.label().to_string(),
        rule.protocol.label().to_string(),
        ports,
        app,
    ]
}

fn rule_row_style(ui: &Ui, selected: bool, row: usize) -> (Color32, Color32, egui::Stroke) {
    if selected {
        (
            Color32::from_rgb(0x1A, 0x5A, 0x85),
            Color32::WHITE,
            egui::Stroke::new(1.5_f32, Color32::from_rgb(0xFF, 0xD0, 0x80)),
        )
    } else if ui.visuals().dark_mode {
        (
            if row.is_multiple_of(2) {
                theme::field(ui)
            } else {
                theme::panel(ui)
            },
            theme::text(ui),
            ui.visuals().widgets.noninteractive.bg_stroke,
        )
    } else if row.is_multiple_of(2) {
        (
            Color32::from_rgb(0xF5, 0xFA, 0xFC),
            theme::text(ui),
            egui::Stroke::new(1.0_f32, Color32::from_rgb(0xA8, 0xC8, 0xD8)),
        )
    } else {
        (
            Color32::from_rgb(0xD8, 0xEA, 0xF2),
            theme::text(ui),
            egui::Stroke::new(1.0_f32, Color32::from_rgb(0x90, 0xB8, 0xCC)),
        )
    }
}

fn paint_rule_cells(
    ui: &Ui,
    row_rect: egui::Rect,
    cols: &RuleColumns,
    cells: &[String; 6],
    row_height: f32,
    text_color: Color32,
) {
    let mut x = row_rect.left();
    for (i, &(_, _, width)) in cols.iter().enumerate() {
        let cell = egui::Rect::from_min_size(
            egui::pos2(x + 4.0, row_rect.top()),
            egui::vec2((width - 8.0).max(4.0), row_height),
        );
        ui.painter()
            .with_clip_rect(cell.intersect(ui.clip_rect()))
            .text(
                cell.left_center(),
                egui::Align2::LEFT_CENTER,
                &cells[i],
                egui::FontId::proportional(14.0),
                text_color,
            );
        x += width + 8.0;
    }
}

fn rule_details(rule: &FirewallRule) -> String {
    format!(
        "{}\n{} · {} · {}\nПорты: {}\nПрограмма: {}\nСостояние: {}\nОписание: {}\n\nДвойной щелчок — редактировать в основной форме.",
        rule.name,
        rule.direction.label(),
        rule.action.label(),
        rule.protocol.label(),
        rule.local_ports,
        if rule.application_path.is_empty() {
            "все программы"
        } else {
            &rule.application_path
        },
        if rule.enabled {
            "включено"
        } else {
            "выключено"
        },
        rule.description,
    )
}

fn rule_columns(available_width: f32) -> RuleColumns {
    // Адаптивные ширины колонок от доступной ширины панели.
    let avail = (available_width - 56.0).max(680.0);
    [
        (SortColumn::Name, "Имя", (avail * 0.34).clamp(160.0, 420.0)),
        (
            SortColumn::Direction,
            "Напр.",
            (avail * 0.10).clamp(70.0, 110.0),
        ),
        (
            SortColumn::Action,
            "Действие",
            (avail * 0.12).clamp(80.0, 130.0),
        ),
        (
            SortColumn::Protocol,
            "Прот.",
            (avail * 0.08).clamp(55.0, 90.0),
        ),
        (
            SortColumn::Ports,
            "Порты",
            (avail * 0.14).clamp(90.0, 160.0),
        ),
        (
            SortColumn::Application,
            "Программа",
            (avail * 0.22).clamp(140.0, 360.0),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::truncate;

    #[test]
    fn truncation_preserves_unicode_and_existing_boundaries() {
        for text in ["", "SSH", "Печать 🖨️", "👩‍💻示例", "Длинное имя правила"]
        {
            for max in 0..30 {
                let expected = if text.chars().count() <= max {
                    text.to_owned()
                } else {
                    format!(
                        "{}…",
                        text.chars().take(max.saturating_sub(1)).collect::<String>()
                    )
                };
                assert_eq!(truncate(text, max), expected);
            }
        }
    }
}
