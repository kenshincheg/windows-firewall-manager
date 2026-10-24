//! Общие элементы управления, многострочные подсказки и обратная связь кнопок.

use egui::{Color32, RichText, TextEdit, Ui};
use firewall_windows::{
    templates::TEMPLATES,
    theme::{self, ACCENT, BG_DEEP, BG_MID},
};

const BTN_FLASH_SECS: f64 = 0.32;

pub(super) fn help_hover(response: egui::Response, text: &str) -> egui::Response {
    let contents = |ui: &mut Ui| {
        ui.set_max_width(320.0);
        ui.add(egui::Label::new(text).wrap());
    };
    response
        .on_hover_ui(contents)
        .on_disabled_hover_ui(contents)
}

fn button_help(label: &str) -> Option<String> {
    if let Some(t) = TEMPLATES.iter().find(|t| t.label == label) {
        return Some(format!(
            "{}\n\nПодставляет настройки в форму.\nДоступ откроется после нажатия\n«Добавить правило», если служба запущена\nи подключение разрешено её настройками.",
            t.purpose,
        ));
    }
    let help = match label {
        "Как настроить правило" => {
            "Открыть справку в отдельном окне.\nПояснения к шаблонам, портам, протоколам,\nпрограммам и профилям сети."
        }
        "Существующие правила" => {
            "Открыть отдельное окно правил Windows Firewall.\nВ нём доступны поиск, сортировка,\nредактирование и удаление правил."
        }
        "Закрыть окно" => {
            "Закрыть окно списка правил.\nОсновная форма останется открытой."
        }
        "Запуск от администратора" => {
            "Перезапустить программу с правами администратора.\nWindows запросит подтверждение UAC.\nНесохранённые поля формы будут потеряны."
        }
        "Обзор…" => {
            "Выбрать исполняемый файл программы.\nПравило будет действовать для указанного файла."
        }
        "Добавить правило" => {
            "Проверить поля и создать правило Windows Firewall.\nДля изменения брандмауэра нужны\nправа администратора."
        }
        "Сохранить" => {
            "Применить изменения к редактируемому правилу.\nДля сохранения нужны права администратора."
        }
        "Отмена" => {
            "Завершить редактирование и очистить форму.\nНесохранённые изменения будут потеряны."
        }
        "Очистить форму" => {
            "Сбросить все поля к исходным значениям.\nСозданные правила сохранятся в Windows Firewall."
        }
        "Обновить сеть" => {
            "Заново определить сетевые адаптеры компьютера\nи все назначенные им IPv4- и IPv6-адреса.\nПроверка выполняется в фоне; данные также\nобновляются автоматически каждые 15 секунд."
        }
        "Обновить" => {
            "Заново загрузить правила из Windows Firewall.\nТекущий выбор строки будет сброшен."
        }
        "Изменить выбранное" => {
            "Открыть выбранное правило в основной форме.\nОкно списка закроется. После правки\nнажмите «Сохранить»."
        }
        "Удалить выбранное" => {
            "Удалить одну выбранную копию из Windows Firewall.\nВ режиме «Только дубли» остальные копии сохранятся.\nДействие выполняется сразу.\nНужны права администратора."
        }
        "Входящее" => {
            "Настроить подключения к этому компьютеру.\nНапример, доступ к локальному серверу."
        }
        "Исходящее" => {
            "Настроить подключения с этого компьютера.\nНапример, доступ программы к сети."
        }
        "Разрешить" => {
            "Разрешать трафик, соответствующий правилу.\nУчитываются протокол, порты, программа и профили."
        }
        "Блокировать" => {
            "Блокировать трафик, соответствующий правилу.\nУчитываются протокол, порты, программа и профили."
        }
        "TCP" => {
            "Протокол TCP — соединения с доставкой данных.\nИспользуется, например, для HTTP и SSH."
        }
        "UDP" => "Протокол UDP — обмен отдельными датаграммами.\nИспользуется, например, для DNS.",
        "Любой" => {
            "Применять правило ко всем протоколам.\nПоле портов должно оставаться пустым;\nукажите путь к программе."
        }
        "Статус" => {
            "Повторно проверить состояние компонента Windows.\nПроверка не устанавливает и не удаляет компонент."
        }
        _ if ["Имя", "Напр.", "Действие", "Прот.", "Порты", "Программа"]
            .iter()
            .any(|name| label.trim_end_matches([' ', '^', 'v']) == *name) =>
        {
            "Сортировать правила по этому столбцу.\nПовторное нажатие меняет порядок сортировки."
        }
        _ => return None,
    };
    Some(help.into())
}

fn is_light_fill(c: Color32) -> bool {
    // Яркий фон → при нажатии красим в ACCENT, иначе затемняем.
    (c.r() as u16) + (c.g() as u16) + (c.b() as u16) > 600
}

fn darken_color(c: Color32, factor: f32) -> Color32 {
    Color32::from_rgba_unmultiplied(
        ((c.r() as f32) * factor).round().clamp(0.0, 255.0) as u8,
        ((c.g() as f32) * factor).round().clamp(0.0, 255.0) as u8,
        ((c.b() as f32) * factor).round().clamp(0.0, 255.0) as u8,
        c.a(),
    )
}

/// Кнопка с заметным press/hover и короткой вспышкой после клика.
pub(super) fn styled_button(
    ui: &mut Ui,
    label: &str,
    fill: Color32,
    text: Color32,
    stroke: egui::Stroke,
    corner: f32,
    text_size: f32,
    min_size: Option<egui::Vec2>,
    enabled: bool,
) -> egui::Response {
    let (fill, text) = if ui.visuals().dark_mode && is_light_fill(fill) {
        (theme::field(ui), theme::text(ui))
    } else {
        (fill, text)
    };
    let feedback = ButtonFeedback::read(ui, label, text_size, min_size);
    let (draw_fill, draw_text, draw_stroke) = feedback.colors(fill, text, stroke);

    let mut btn = egui::Button::new(
        RichText::new(label)
            .strong()
            .size(text_size)
            .color(draw_text),
    )
    .fill(draw_fill)
    .stroke(draw_stroke)
    .corner_radius(corner);
    if let Some(sz) = min_size {
        btn = btn.min_size(sz);
    }

    let resp = ui.add_enabled(enabled, btn);
    // Disabled buttons also report contains_pointer. Build explanatory text only
    // for the button under the pointer, rather than allocating it every frame.
    let resp = if resp.contains_pointer() {
        if let Some(help) = button_help(label) {
            help_hover(resp, &help)
        } else {
            resp
        }
    } else {
        resp
    };

    feedback.update(ui, &resp);

    resp
}

/// Чип выбора: выбранный — цветной фон + белый текст; иначе белый фон + тёмный текст + обводка.
pub(super) fn choice_chip(
    ui: &mut Ui,
    label: &str,
    selected: bool,
    idle_fill: Color32,
    idle_text: Color32,
    selected_fill: Color32,
) -> egui::Response {
    choice_chip_enabled(
        ui,
        label,
        selected,
        idle_fill,
        idle_text,
        selected_fill,
        true,
    )
}

pub(super) fn choice_chip_enabled(
    ui: &mut Ui,
    label: &str,
    selected: bool,
    idle_fill: Color32,
    idle_text: Color32,
    selected_fill: Color32,
    enabled: bool,
) -> egui::Response {
    let (fill, text, stroke) = if selected {
        (
            selected_fill,
            Color32::WHITE,
            egui::Stroke::new(1.8_f32, BG_DEEP),
        )
    } else {
        (idle_fill, idle_text, egui::Stroke::new(1.8_f32, BG_MID))
    };
    styled_button(ui, label, fill, text, stroke, 8.0, 16.0, None, enabled)
}

pub(super) fn tile_btn(
    ui: &mut Ui,
    size: egui::Vec2,
    label: &str,
    fill: Option<Color32>,
    enabled: bool,
) -> egui::Response {
    let (fill, text, stroke) = match fill {
        Some(c) => (c, Color32::WHITE, egui::Stroke::new(1.5_f32, BG_DEEP)),
        None => (
            Color32::WHITE,
            theme::text(ui),
            egui::Stroke::new(1.8_f32, BG_MID),
        ),
    };
    styled_button(
        ui,
        label,
        fill,
        text,
        stroke,
        7.0,
        15.0,
        Some(size),
        enabled,
    )
}

pub(super) fn rounded_field(ui: &mut Ui, text: &mut String, hint: &str, focus_color: Color32) {
    let edit_id = ui.next_auto_id().with("rounded_edit");
    let hover_id = edit_id.with("hovered");
    let focused = ui.memory(|m| m.has_focus(edit_id));
    let was_hovered = ui
        .ctx()
        .data(|d| d.get_temp::<bool>(hover_id).unwrap_or(false));

    let stroke = if focused {
        egui::Stroke::new(2.6_f32, focus_color)
    } else if was_hovered {
        egui::Stroke::new(2.2_f32, theme::HOVER_RING)
    } else {
        egui::Stroke::new(1.8_f32, ACCENT)
    };

    let out = egui::Frame::NONE
        .fill(theme::field(ui))
        .corner_radius(12)
        .inner_margin(egui::Margin::symmetric(10, 6))
        .stroke(stroke)
        .show(ui, |ui| {
            let field_w = ui.available_width().clamp(60.0, 340.0);
            ui.add(
                TextEdit::singleline(text)
                    .id(edit_id)
                    .desired_width(field_w)
                    .hint_text(RichText::new(hint).italics())
                    .frame(false)
                    .text_color(theme::text(ui)),
            )
        });

    let hovered = out.response.hovered() || out.inner.hovered();
    ui.ctx().data_mut(|d| d.insert_temp(hover_id, hovered));
    if hovered != was_hovered || out.inner.has_focus() != focused {
        ui.ctx().request_repaint();
    }
}

/// Transient interaction state for one stable egui button ID.
#[derive(Clone, Copy)]
struct ButtonFeedback {
    id: egui::Id,
    time: f64,
    held: bool,
    hovered: bool,
    flashing: bool,
}

impl ButtonFeedback {
    fn read(ui: &Ui, label: &str, text_size: f32, min_size: Option<egui::Vec2>) -> Self {
        // Стабильный id (не auto_id): иначе вспышка сбрасывается каждый кадр.
        let size_key = min_size
            .map(|s| (s.x.to_bits(), s.y.to_bits()))
            .unwrap_or((0, 0));
        let fx_id = ui
            .id()
            .with("btn_fx")
            .with(label)
            .with(text_size.to_bits())
            .with(size_key);
        let now = ui.ctx().input(|i| i.time);
        let (flash_until, held_prev, hovered_prev) = ui.ctx().data(|d| {
            (
                d.get_temp::<f64>(fx_id),
                d.get_temp::<bool>(fx_id.with("held")).unwrap_or(false),
                d.get_temp::<bool>(fx_id.with("hov")).unwrap_or(false),
            )
        });
        let flashing = flash_until.map(|t| now < t).unwrap_or(false);

        Self {
            id: fx_id,
            time: now,
            held: held_prev,
            hovered: hovered_prev,
            flashing,
        }
    }

    fn colors(
        self,
        fill: Color32,
        text: Color32,
        stroke: egui::Stroke,
    ) -> (Color32, Color32, egui::Stroke) {
        if self.held || self.flashing {
            let pressed_fill = if is_light_fill(fill) {
                ACCENT
            } else {
                darken_color(fill, 0.62)
            };
            (
                pressed_fill,
                Color32::WHITE,
                egui::Stroke::new(2.4_f32, BG_DEEP),
            )
        } else if self.hovered {
            let hover_fill = if is_light_fill(fill) {
                Color32::from_rgb(0xE8, 0xF4, 0xFA)
            } else {
                darken_color(fill, 0.88)
            };
            let hover_text = if is_light_fill(fill) {
                text
            } else {
                Color32::WHITE
            };
            (
                hover_fill,
                hover_text,
                egui::Stroke::new(stroke.width + 0.4, theme::HOVER_RING),
            )
        } else {
            (fill, text, stroke)
        }
    }

    fn update(self, ui: &Ui, resp: &egui::Response) {
        if resp.clicked() {
            ui.ctx()
                .data_mut(|d| d.insert_temp(self.id, self.time + BTN_FLASH_SECS));
        }
        if self.held != resp.is_pointer_button_down_on() || self.hovered != resp.hovered() {
            ui.ctx().data_mut(|d| {
                d.insert_temp(self.id.with("held"), resp.is_pointer_button_down_on());
                d.insert_temp(self.id.with("hov"), resp.hovered());
            });
            ui.ctx().request_repaint();
        }
        if resp.clicked() || self.flashing {
            ui.ctx()
                .request_repaint_after(std::time::Duration::from_millis(40));
        }
    }
}
