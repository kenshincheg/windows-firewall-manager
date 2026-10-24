//! Отдельное окно справки по настройке правила.

use super::FirewallApp;
use egui::{RichText, Ui};
use firewall_windows::theme;

fn draw_help_window_content(ui: &mut Ui) {
    egui::ScrollArea::vertical()
        .id_salt("help_window_scroll")
        .auto_shrink([false, false])
        .show(ui, draw_help_panel_content);
}

fn draw_help_panel_content(ui: &mut Ui) {
    ui.heading("Как настроить правило");
    ui.label("Заполните форму в основном окне программы. Изменения применяются после добавления или сохранения.");
    ui.add_space(8.0);
    tip(
        ui,
        "01  Шаблоны",
        "Подставляют имя, порт, протокол и действие. Проверьте путь к программе и профили: они сохраняются из формы. Сам шаблон правило не создаёт.",
    );
    tip(
        ui,
        "02  Направление и действие",
        "Входящее — подключения к этому компьютеру. Исходящее — подключения с него. Выберите, разрешать или блокировать такой трафик.",
    );
    tip(
        ui,
        "03  Порты и протокол",
        "Один порт: 21\nДиапазон: 45512-65534\nДопустимые значения: 1–65535. Для портов выберите TCP или UDP. Списки через запятую форма не принимает.",
    );
    tip(
        ui,
        "04  Программа",
        "«Обзор…» выбирает исполняемый файл. Пустые порты допустимы, если задана программа. Если указаны оба поля, правило ограничено и программой, и портами.",
    );
    tip(
        ui,
        "05  Профили сети",
        "Domain — сеть домена организации.\nPrivate — доверенная частная сеть.\nPublic — общедоступная сеть.\nНужен хотя бы один профиль; выбирайте только подходящие сети.",
    );
    tip(
        ui,
        "06  Существующие правила",
        "Открываются в отдельном окне. Фильтр ищет по имени, портам и программе. Заголовки сортируют список. Двойной щелчок переносит правило в форму для редактирования.",
    );
    tip(
        ui,
        "Обозначения в списке",
        "«все (*)» — все порты.\n«—» — значение отсутствует.\nДлинные имена и пути сокращаются; наведите указатель на строку для подробностей.",
    );
    tip(
        ui,
        "Компоненты Windows",
        "Установка Telnet и OpenSSH выполняется отдельно от создания правил. OpenSSH Server также запускает службу sshd. Удаление OpenSSH Client очищает папки SSH, включая пользовательские ключи.",
    );
    tip(
        ui,
        "Права и журнал",
        "Для изменения правил и компонентов нужны права администратора. Результаты и ошибки записываются в папку logs рядом с программой.",
    );
}

fn tip(ui: &mut Ui, title: &str, body: &str) {
    ui.separator();
    ui.add_space(5.0);
    ui.label(RichText::new(title).strong().size(15.0));
    ui.add(egui::Label::new(RichText::new(body).color(theme::muted(ui)).size(14.0)).wrap());
    ui.add_space(7.0);
}

impl FirewallApp {
    pub(super) fn draw_help_window(&mut self, ctx: &egui::Context) {
        if !self.help_window_open {
            return;
        }
        ctx.show_viewport_immediate(
            egui::ViewportId::from_hash_of("help_window"),
            egui::ViewportBuilder::default()
                .with_title(format!(
                    "Как настроить правило · {}",
                    env!("CARGO_PKG_VERSION")
                ))
                .with_inner_size([600.0, 760.0])
                .with_min_inner_size([440.0, 360.0]),
            |ctx, class| {
                if ctx.input(|i| i.viewport().close_requested()) {
                    self.help_window_open = false;
                }
                if class == egui::ViewportClass::Embedded {
                    let mut open = self.help_window_open;
                    egui::Window::new("Как настроить правило")
                        .open(&mut open)
                        .default_size([580.0, 680.0])
                        .show(ctx, draw_help_window_content);
                    self.help_window_open &= open;
                } else {
                    egui::CentralPanel::default().show(ctx, draw_help_window_content);
                }
                if !self.help_window_open {
                    ctx.request_repaint_of(egui::ViewportId::ROOT);
                }
            },
        );
    }
}
