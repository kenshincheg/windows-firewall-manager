//! Тёплая голубая тема для egui.

use egui::{
    Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, Stroke, Style, TextStyle,
    Visuals,
};
use std::sync::Arc;

pub const BG_DEEP: Color32 = Color32::from_rgb(0x0B, 0x3A, 0x5C);
pub const BG_MID: Color32 = Color32::from_rgb(0x1A, 0x6B, 0x8A);
pub const PANEL: Color32 = Color32::from_rgb(0xE8, 0xF4, 0xF8);
pub const PANEL_ALT: Color32 = Color32::from_rgb(0xD0, 0xE8, 0xF0);
pub const ACCENT: Color32 = Color32::from_rgb(0x2E, 0x8B, 0xC0);
pub const ACCENT_HOVER: Color32 = Color32::from_rgb(0x3F, 0xA4, 0xD8);
/// Почти чёрный — чётче на светлых панелях / втором мониторе.
pub const TEXT_DARK: Color32 = Color32::from_rgb(0x0C, 0x18, 0x24);
pub const TEXT_MUTED: Color32 = Color32::from_rgb(0x2A, 0x45, 0x58);
pub const DANGER: Color32 = Color32::from_rgb(0xC0, 0x4A, 0x3E);
pub const OK: Color32 = Color32::from_rgb(0x1E, 0x7A, 0x5A);
/// Обводка поля в фокусе (тёплый оранжево-янтарный).
pub const FOCUS_RING: Color32 = Color32::from_rgb(0xE0, 0x8A, 0x28);
/// Обводка поля при наведении.
pub const HOVER_RING: Color32 = Color32::from_rgb(0x2A, 0xB0, 0xC8);

pub fn apply(ctx: &egui::Context) {
    install_system_fonts(ctx);

    let mut style = Style::default();
    style.visuals = warm_blue_visuals();
    style.spacing.item_spacing = egui::vec2(8.0, 8.0);
    style.spacing.button_padding = egui::vec2(14.0, 8.0);
    style.spacing.interact_size.y = 28.0;
    // Не выделять label мышкой (белый текст шапки становился нечитаемым).
    style.interaction.selectable_labels = false;

    // Segoe UI + чуть крупнее базовые кегли.
    style.text_styles = [
        (
            TextStyle::Small,
            FontId::new(13.5, FontFamily::Proportional),
        ),
        (TextStyle::Body, FontId::new(16.0, FontFamily::Proportional)),
        (
            TextStyle::Button,
            FontId::new(16.0, FontFamily::Proportional),
        ),
        (
            TextStyle::Heading,
            FontId::new(22.0, FontFamily::Proportional),
        ),
        (
            TextStyle::Monospace,
            FontId::new(14.5, FontFamily::Monospace),
        ),
    ]
    .into();

    style.spacing.tooltip_width = 320.0;
    ctx.set_style_of(egui::Theme::Light, style.clone());
    style.visuals = Visuals::dark();
    style.visuals.panel_fill = Color32::from_rgb(25, 34, 44);
    style.visuals.window_fill = Color32::from_rgb(31, 43, 55);
    style.visuals.extreme_bg_color = Color32::from_rgb(18, 27, 36);
    style.visuals.selection.bg_fill = BG_MID;
    style.visuals.hyperlink_color = Color32::from_rgb(110, 195, 240);
    style.visuals.window_corner_radius = CornerRadius::same(10);
    ctx.set_style_of(egui::Theme::Dark, style);
    ctx.set_theme(egui::ThemePreference::System);

    // Чуть дешевле tessellation при частых перерисовках (перетаскивание окна).
    ctx.tessellation_options_mut(|t| {
        t.feathering = true;
        t.feathering_size_in_pixels = 0.75;
        t.coarse_tessellation_culling = true;
        t.parallel_tessellation = true;
    });
}

/// Подключить Segoe UI / Consolas вместо тонкого Ubuntu Light из egui.
fn install_system_fonts(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();

    // Segoe UI заметно чётче штатного Ubuntu Light, особенно кириллица.
    if let Ok(bytes) = std::fs::read(r"C:\Windows\Fonts\segoeui.ttf") {
        fonts
            .font_data
            .insert("segoe_ui".into(), Arc::new(FontData::from_owned(bytes)));
        if let Some(family) = fonts.families.get_mut(&FontFamily::Proportional) {
            family.insert(0, "segoe_ui".into());
        }
    }

    if let Ok(bytes) = std::fs::read(r"C:\Windows\Fonts\consola.ttf") {
        fonts
            .font_data
            .insert("consolas".into(), Arc::new(FontData::from_owned(bytes)));
        if let Some(family) = fonts.families.get_mut(&FontFamily::Monospace) {
            family.insert(0, "consolas".into());
        }
    }

    ctx.set_fonts(fonts);
}

fn warm_blue_visuals() -> Visuals {
    let round = CornerRadius::same(12);
    let mut v = Visuals::light();
    v.window_fill = PANEL;
    v.panel_fill = PANEL;
    v.extreme_bg_color = Color32::WHITE;
    v.faint_bg_color = Color32::from_rgb(0xF2, 0xF9, 0xFC);
    v.override_text_color = Some(TEXT_DARK);

    // Обычное поле: белый фон + заметная голубая обводка.
    v.widgets.inactive.bg_fill = Color32::WHITE;
    v.widgets.inactive.weak_bg_fill = Color32::from_rgb(0xD8, 0xEC, 0xF4);
    v.widgets.inactive.bg_stroke = Stroke::new(1.8_f32, ACCENT);
    v.widgets.inactive.fg_stroke = Stroke::new(1.2_f32, TEXT_DARK);
    v.widgets.inactive.corner_radius = round;
    // expansion > 0 заставляет пересчитывать layout при hover — лишняя работа каждый кадр.
    v.widgets.inactive.expansion = 0.0;

    // Hover: бирюзовая оконтовка.
    v.widgets.hovered.bg_fill = Color32::from_rgb(0xFB, 0xFD, 0xFF);
    v.widgets.hovered.weak_bg_fill = Color32::from_rgb(0xE0, 0xF4, 0xFA);
    v.widgets.hovered.bg_stroke = Stroke::new(2.4_f32, HOVER_RING);
    v.widgets.hovered.fg_stroke = Stroke::new(1.2_f32, TEXT_DARK);
    v.widgets.hovered.corner_radius = round;
    v.widgets.hovered.expansion = 0.0;

    // Active / кнопка нажата.
    v.widgets.active.bg_fill = ACCENT;
    v.widgets.active.weak_bg_fill = ACCENT_HOVER;
    v.widgets.active.bg_stroke = Stroke::new(2.0_f32, BG_DEEP);
    v.widgets.active.fg_stroke = Stroke::new(1.2_f32, Color32::WHITE);
    v.widgets.active.corner_radius = round;
    v.widgets.active.expansion = 0.0;

    // Фокус TextEdit (open): яркая цветная оконтовка.
    v.widgets.open.bg_fill = Color32::WHITE;
    v.widgets.open.weak_bg_fill = Color32::from_rgb(0xFF, 0xF8, 0xEE);
    v.widgets.open.bg_stroke = Stroke::new(3.0_f32, FOCUS_RING);
    v.widgets.open.fg_stroke = Stroke::new(1.2_f32, TEXT_DARK);
    v.widgets.open.corner_radius = round;
    v.widgets.open.expansion = 0.0;

    v.widgets.noninteractive.bg_fill = PANEL;
    // Разделители панелей — не чёрные, а мягкий голубой.
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, Color32::from_rgb(0xA0, 0xC8, 0xD8));
    v.widgets.noninteractive.fg_stroke = Stroke::new(1.0_f32, TEXT_DARK);
    v.widgets.noninteractive.corner_radius = CornerRadius::same(8);

    // Выделение текста: тёмно-синий фон + белая «обводка» — читаемо на светлом и тёмном.
    v.selection.bg_fill = Color32::from_rgb(0x1A, 0x5A, 0x85);
    v.selection.stroke = Stroke::new(1.0_f32, Color32::from_rgb(0xFF, 0xD0, 0x80));

    v.hyperlink_color = ACCENT;
    v.warn_fg_color = Color32::from_rgb(0xB0, 0x7A, 0x20);
    v.error_fg_color = DANGER;
    v.window_corner_radius = CornerRadius::same(10);
    v.menu_corner_radius = CornerRadius::same(10);
    v
}

/// Жирный текст тела.
pub fn bold(text: impl Into<String>) -> egui::RichText {
    egui::RichText::new(text).strong()
}

pub fn text(ui: &egui::Ui) -> Color32 {
    ui.visuals().text_color()
}
pub fn muted(ui: &egui::Ui) -> Color32 {
    ui.visuals().weak_text_color()
}
pub fn panel(ui: &egui::Ui) -> Color32 {
    ui.visuals().panel_fill
}
pub fn field(ui: &egui::Ui) -> Color32 {
    ui.visuals().extreme_bg_color
}
pub fn success(ui: &egui::Ui) -> Color32 {
    if ui.visuals().dark_mode {
        Color32::from_rgb(108, 218, 166)
    } else {
        OK
    }
}
pub fn danger(ui: &egui::Ui) -> Color32 {
    if ui.visuals().dark_mode {
        Color32::from_rgb(255, 145, 135)
    } else {
        DANGER
    }
}
