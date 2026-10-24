//! Компоненты Windows: действия, фоновая задача и карточки.

use super::{
    FirewallApp,
    widgets::{help_hover, styled_button, tile_btn},
};
use egui::{Color32, RichText, Ui};
use firewall_windows::{
    logutil,
    optional_features::{self, FeatureState},
    theme::{self, ACCENT, BG_MID, DANGER},
};
use std::sync::mpsc;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum WinComponent {
    Telnet,
    OpenSshClient,
    OpenSshServer,
}

impl WinComponent {
    pub(super) const ALL: &[Self] = &[Self::Telnet, Self::OpenSshClient, Self::OpenSshServer];

    fn title(self) -> &'static str {
        match self {
            Self::Telnet => "Telnet",
            Self::OpenSshClient => "OpenSSH Client",
            Self::OpenSshServer => "OpenSSH Server",
        }
    }

    fn full_name(self) -> &'static str {
        match self {
            Self::Telnet => "Telnet Client",
            Self::OpenSshClient => "OpenSSH Client",
            Self::OpenSshServer => "OpenSSH Server",
        }
    }

    fn hint(self) -> &'static str {
        match self {
            Self::Telnet => "Feature · telnet.exe",
            Self::OpenSshClient => "Capability · ssh.exe",
            Self::OpenSshServer => "sshd · порт 22",
        }
    }

    fn enable_label(self) -> &'static str {
        match self {
            Self::Telnet => "Включить",
            Self::OpenSshClient | Self::OpenSshServer => "Установить",
        }
    }

    fn disable_label(self) -> &'static str {
        match self {
            Self::Telnet => "Отключить",
            Self::OpenSshClient | Self::OpenSshServer => "Удалить",
        }
    }

    fn hover_enable(self) -> &'static str {
        match self {
            Self::Telnet => {
                "Включить клиент Telnet в Windows.\nПосле установки станет доступна команда telnet."
            }
            Self::OpenSshClient => {
                "Установить клиент OpenSSH.\nДобавляет команду ssh для подключения к SSH-серверам."
            }
            Self::OpenSshServer => {
                "Установить сервер OpenSSH и запустить sshd.\nСлужба будет запускаться автоматически вместе с Windows."
            }
        }
    }

    fn hover_disable(self) -> &'static str {
        match self {
            Self::Telnet => "Отключить клиент Telnet.\nКоманда telnet перестанет быть доступна.",
            Self::OpenSshClient => {
                "Удалить клиент OpenSSH и очистить папки SSH.\nБудут удалены настройки и ключи из ProgramData\\ssh\nи пользовательской папки .ssh."
            }
            Self::OpenSshServer => {
                "Остановить службу sshd и удалить сервер OpenSSH.\nВходящие SSH-подключения станут недоступны."
            }
        }
    }

    fn query_state(self) -> FeatureState {
        match self {
            Self::Telnet => optional_features::telnet_client_state(),
            Self::OpenSshClient => optional_features::openssh_client_state(),
            Self::OpenSshServer => optional_features::openssh_server_state(),
        }
    }

    fn run_op(self, op: ComponentOp) -> Result<(), String> {
        match (self, op) {
            (Self::Telnet, ComponentOp::Enable) => optional_features::enable_telnet_client(),
            (Self::Telnet, ComponentOp::Disable) => optional_features::disable_telnet_client(),
            (Self::OpenSshClient, ComponentOp::Enable) => {
                optional_features::enable_openssh_client()
            }
            (Self::OpenSshClient, ComponentOp::Disable) => {
                optional_features::disable_openssh_client()
            }
            (Self::OpenSshServer, ComponentOp::Enable) => {
                optional_features::enable_openssh_server()
            }
            (Self::OpenSshServer, ComponentOp::Disable) => {
                optional_features::disable_openssh_server()
            }
            (Self::OpenSshServer, ComponentOp::Stop) => optional_features::stop_openssh_server(),
            (_, ComponentOp::Stop) => Err("остановка доступна только для OpenSSH Server".into()),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ComponentOp {
    Enable,
    Disable,
    /// Только для OpenSSH Server: Stop-Service sshd.
    Stop,
}

pub(super) struct ComponentJobResult {
    component: WinComponent,
    op: ComponentOp,
    outcome: Result<FeatureState, String>,
}

impl FirewallApp {
    pub(super) fn refresh_ssh_folders(&mut self) {
        self.ssh_folders = optional_features::openssh_data_dirs()
            .into_iter()
            .enumerate()
            .map(|(i, path)| {
                let label = if i == 0 {
                    "ProgramData\\ssh".to_string()
                } else {
                    "Профиль\\.ssh".to_string()
                };
                let exists = path.exists();
                (label, path, exists)
            })
            .collect();
    }

    pub(super) fn component_busy(&self) -> bool {
        self.component_job.is_some()
    }

    fn component_state(&self, c: WinComponent) -> &FeatureState {
        match c {
            WinComponent::Telnet => &self.telnet_state,
            WinComponent::OpenSshClient => &self.ssh_client_state,
            WinComponent::OpenSshServer => &self.ssh_server_state,
        }
    }

    fn set_component_state(&mut self, c: WinComponent, state: FeatureState) {
        match c {
            WinComponent::Telnet => self.telnet_state = state,
            WinComponent::OpenSshClient => self.ssh_client_state = state,
            WinComponent::OpenSshServer => self.ssh_server_state = state,
        }
    }

    pub(super) fn refresh_component_state(&mut self, c: WinComponent) {
        let state = c.query_state();
        logutil::info(format!("{}: {}", c.full_name(), state.label()));
        self.set_component_state(c, state);
    }

    pub(super) fn poll_component_job(&mut self) {
        let Some(rx) = &self.component_rx else {
            return;
        };
        match rx.try_recv() {
            Ok(job) => {
                self.finish_component_job(job);
            }
            Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) => {
                self.component_rx = None;
                self.component_job = None;
                self.set_err("Фоновая операция компонента Windows прервалась");
            }
        }
    }

    fn start_component_job(
        &mut self,
        ctx: &egui::Context,
        component: WinComponent,
        op: ComponentOp,
    ) {
        if self.component_busy() {
            return;
        }
        let (tx, rx) = mpsc::channel();
        self.component_rx = Some(rx);
        self.component_job = Some((component, op));
        let name = component.full_name();
        match op {
            ComponentOp::Enable => self.set_ok(format!("Установка / включение {name}…")),
            ComponentOp::Disable => self.set_ok(format!("Отключение {name}…")),
            ComponentOp::Stop => self.set_ok(format!("Остановка sshd ({name})…")),
        }

        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let outcome = component.run_op(op).map(|()| component.query_state());
            let _ = tx.send(ComponentJobResult {
                component,
                op,
                outcome,
            });
            ctx.request_repaint();
        });
    }

    pub(super) fn draw_windows_components(&mut self, ui: &mut Ui) {
        ui.separator();
        ui.label(RichText::new("Компоненты Windows").strong().size(18.0));
        ui.add_space(6.0);
        ui.columns(3, |columns| {
            for (column, &component) in columns.iter_mut().zip(WinComponent::ALL) {
                self.draw_component_tile(column, component);
            }
        });
        ui.add_space(8.0);
        self.draw_ssh_folder_buttons(ui);
    }

    fn draw_ssh_folder_buttons(&mut self, ui: &mut Ui) {
        ui.label(RichText::new("Папки SSH").strong().size(15.0));
        let size = egui::vec2(((ui.available_width() - 8.0) / 2.0).floor(), 36.0);
        let folders = self.ssh_folders.clone();
        ui.horizontal_wrapped(|ui| {
            for (label, path, exists) in folders {
                let tip = format!(
                    "Открыть папку SSH в Проводнике.\n{}{}",
                    path.display(),
                    if exists {
                        ""
                    } else {
                        "\nПапка ещё не существует."
                    }
                );
                if help_hover(
                    styled_button(
                        ui,
                        &label,
                        theme::field(ui),
                        theme::text(ui),
                        egui::Stroke::new(1.0_f32, ACCENT),
                        7.0,
                        15.0,
                        Some(size),
                        exists,
                    ),
                    &tip,
                )
                .clicked()
                {
                    match optional_features::open_in_explorer(&path) {
                        Ok(()) => self.set_ok(format!("Открыто: {}", path.display())),
                        Err(e) => self.set_err(e),
                    }
                }
            }
        });
    }

    fn draw_component_tile(&mut self, ui: &mut Ui, component: WinComponent) {
        let busy = self.component_busy();
        let state = self.component_state(component);
        let stopped = matches!(state, FeatureState::InstalledStopped);
        let running = state.is_enabled();
        let status = state.label();
        let status_color = if running {
            theme::success(ui)
        } else if stopped {
            ui.visuals().warn_fg_color
        } else {
            theme::muted(ui)
        };
        let this_op = self
            .component_job
            .filter(|(c, _)| *c == component)
            .map(|(_, op)| op);
        let permission = self.component_blocked_reason(busy);
        let can_click = !busy && self.is_admin;
        let actions = component_actions(component, state, this_op, permission, can_click);
        let inner_width = (ui.available_width() - 22.0).max(100.0);
        ui.push_id(component.title(), |ui| {
            egui::Frame::NONE
                .fill(theme::field(ui))
                .corner_radius(8)
                .inner_margin(10.0)
                .stroke(egui::Stroke::new(1.0_f32, BG_MID))
                .show(ui, |ui| {
                    ui.set_width(inner_width);
                    ui.set_min_height(220.0);
                    ui.spacing_mut().item_spacing.y = 7.0;
                    ui.label(RichText::new(component.title()).strong().size(16.0));
                    ui.label(
                        RichText::new(component.hint())
                            .size(13.0)
                            .color(theme::muted(ui)),
                    );
                    ui.add(
                        egui::Label::new(RichText::new(&status).size(14.0).color(status_color))
                            .truncate(),
                    )
                    .on_hover_text(&status);
                    ui.separator();
                    let size = egui::vec2(inner_width, 36.0);
                    for action in actions {
                        if help_hover(
                            tile_btn(ui, size, action.label, Some(action.fill), action.enabled),
                            action.help,
                        )
                        .clicked()
                        {
                            self.start_component_job(ui.ctx(), component, action.op);
                        }
                    }
                    if tile_btn(ui, size, "Статус", None, !busy).clicked() {
                        self.refresh_component_state(component);
                        self.set_ok(format!(
                            "Статус {}: {}",
                            component.full_name(),
                            self.component_state(component).label()
                        ));
                    }
                });
        });
    }
    fn finish_component_job(&mut self, job: ComponentJobResult) {
        self.component_rx = None;
        self.component_job = None;
        let name = job.component.full_name();
        match job.outcome {
            Ok(state) => {
                logutil::info(format!("{name}: {}", state.label()));
                self.set_component_state(job.component, state);
                self.refresh_ssh_folders();
                let enabled = self.component_state(job.component).is_enabled();
                let label = self.component_state(job.component).label();
                let stopped = matches!(
                    self.component_state(job.component),
                    FeatureState::InstalledStopped
                );
                match job.op {
                    ComponentOp::Enable if enabled => {
                        self.set_ok(format!("Компонент {name} включён"));
                    }
                    ComponentOp::Disable if !enabled => {
                        self.set_ok(format!("Компонент {name} отключён"));
                    }
                    ComponentOp::Stop if stopped || !enabled => {
                        self.set_ok(format!("Служба sshd остановлена. {name}: {label}"));
                    }
                    _ => self.set_ok(format!(
                        "Команда выполнена. {name}: {label}. При необходимости перезагрузите ПК / проверьте Windows Update."
                    )),
                }
            }
            Err(e) => {
                let verb = match job.op {
                    ComponentOp::Enable => "включить",
                    ComponentOp::Disable => "отключить",
                    ComponentOp::Stop => "остановить",
                };
                self.set_err(format!("Не удалось {verb} {name}: {e}"));
                self.refresh_component_state(job.component);
                self.refresh_ssh_folders();
            }
        }
    }

    fn component_blocked_reason(&self, busy: bool) -> Option<&'static str> {
        if busy {
            Some("Выполняется операция с компонентом Windows.\nДождитесь её завершения.")
        } else if !self.is_admin {
            Some("Нужны права администратора.\nПерезапустите программу с повышенными правами.")
        } else {
            None
        }
    }
}

#[derive(Clone, Copy)]
struct ComponentAction {
    op: ComponentOp,
    label: &'static str,
    help: &'static str,
    enabled: bool,
    fill: Color32,
}

/// Compute both buttons from one snapshot before either click can start a job.
fn component_actions(
    component: WinComponent,
    state: &FeatureState,
    pending: Option<ComponentOp>,
    blocked_reason: Option<&'static str>,
    can_click: bool,
) -> [ComponentAction; 2] {
    let reboot_pending = matches!(
        state,
        FeatureState::EnablePending | FeatureState::DisablePending
    );
    let can_click = can_click && !reboot_pending;
    let blocked_reason = blocked_reason.or(if reboot_pending {
        Some("Компонент ожидает перезагрузки Windows.\nПерезагрузите компьютер перед повторной операцией.")
    } else { None });
    let running = state.is_enabled();
    let stopped = matches!(state, FeatureState::InstalledStopped);
    let (op, label, help, allowed) = if component == WinComponent::OpenSshServer && running {
        (
            ComponentOp::Stop,
            "Остановить",
            "Остановить службу SSH-сервера sshd.\nКомпонент останется установленным.",
            true,
        )
    } else {
        (
            ComponentOp::Enable,
            if stopped {
                "Запустить"
            } else {
                component.enable_label()
            },
            if stopped {
                "Запустить SSH-сервер sshd.\nВключить автоматический запуск с Windows."
            } else {
                component.hover_enable()
            },
            !running,
        )
    };
    [
        ComponentAction {
            op,
            label: if pending == Some(op) {
                "Выполняется…"
            } else {
                label
            },
            help: blocked_reason.unwrap_or(if !allowed {
                "Компонент уже включён.\nПовторная установка не требуется."
            } else {
                help
            }),
            enabled: can_click && allowed,
            fill: ACCENT,
        },
        ComponentAction {
            op: ComponentOp::Disable,
            label: if pending == Some(ComponentOp::Disable) {
                "Выполняется…"
            } else {
                component.disable_label()
            },
            help: blocked_reason.unwrap_or(if state.is_installed() {
                component.hover_disable()
            } else {
                "Компонент не установлен или уже отключён.\nУдалять или отключать его не требуется."
            }),
            enabled: can_click && state.is_installed(),
            fill: DANGER,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn component_actions_follow_installed_and_running_state() {
        let actions = component_actions(
            WinComponent::OpenSshServer,
            &FeatureState::InstalledStopped,
            None,
            None,
            true,
        );
        assert!(actions[0].op == ComponentOp::Enable);
        assert_eq!(actions[0].label, "Запустить");
        assert!(actions[0].enabled && actions[1].enabled);

        let actions = component_actions(
            WinComponent::OpenSshServer,
            &FeatureState::Enabled,
            None,
            None,
            true,
        );
        assert!(actions[0].op == ComponentOp::Stop);
        assert!(actions[0].enabled && actions[1].enabled);

        let actions = component_actions(
            WinComponent::OpenSshClient,
            &FeatureState::Enabled,
            None,
            None,
            true,
        );
        assert!(!actions[0].enabled && actions[1].enabled);

        let actions = component_actions(
            WinComponent::Telnet,
            &FeatureState::Disabled,
            None,
            None,
            true,
        );
        assert!(actions[0].enabled && !actions[1].enabled);
    }

    #[test]
    fn busy_or_unelevated_components_cannot_start_actions() {
        let reason = "Already working";
        let actions = component_actions(
            WinComponent::OpenSshServer,
            &FeatureState::Enabled,
            Some(ComponentOp::Disable),
            Some(reason),
            false,
        );
        assert!(
            actions
                .iter()
                .all(|action| !action.enabled && action.help == reason)
        );
        assert_eq!(actions[1].label, "Выполняется…");
    }
    #[test]
    fn restart_pending_components_block_repeated_operations() {
        for state in [FeatureState::EnablePending, FeatureState::DisablePending] {
            for &component in WinComponent::ALL {
                let actions = component_actions(component, &state, None, None, true);
                assert!(
                    actions.iter().all(|action| !action.enabled),
                    "Pending reboot must block mutations"
                );
                assert!(
                    actions
                        .iter()
                        .all(|action| action.help.contains("перезагруз"))
                );
            }
        }
    }
}
