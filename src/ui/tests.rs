//! Проверки поведения и компоновки UI.

use super::widgets::styled_button;
use super::*;
use firewall_windows::network;
use std::sync::mpsc;

#[test]
fn form_fits_supported_sizes_in_both_themes() {
    for theme in [egui::Theme::Light, egui::Theme::Dark] {
        for width in [654.0, 794.0] {
            let ctx = egui::Context::default();
            theme::apply(&ctx);
            ctx.set_theme(theme);
            let mut app = FirewallApp::default();
            let input = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(width, 740.0),
                )),
                ..Default::default()
            };
            let _ = ctx.run(input, |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    let right = ui.max_rect().right();
                    app.draw_form_column(ui);
                    assert!(
                        ui.min_rect().right() <= right + 1.0,
                        "Form overflows at {width}, {theme:?}: {:?} > {right}",
                        ui.min_rect()
                    );
                    assert_eq!(ui.visuals().dark_mode, theme == egui::Theme::Dark);
                });
            });
        }
    }
}

#[test]
fn list_fits_minimum_window_width_in_both_themes() {
    for theme in [egui::Theme::Light, egui::Theme::Dark] {
        for duplicates_only in [false, true] {
            let ctx = egui::Context::default();
            theme::apply(&ctx);
            ctx.set_theme(theme);
            let mut app = FirewallApp::default();
            app.rules = (0..600)
                .map(|i| FirewallRule {
                    name: format!("Very long rule name {i}"),
                    application_path: r"C:\Program Files\Example\application.exe".into(),
                    comparison_key: Some(vec![format!("group {}", i % 10)]),
                    ..Default::default()
                })
                .collect();
            app.duplicates_only = duplicates_only;
            app.duplicates = duplicates::DuplicateIndex::build(&app.rules);
            let input = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(780.0, 480.0),
                )),
                ..Default::default()
            };
            let _ = ctx.run(input, |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    let right = ui.max_rect().right();
                    app.draw_list(ui);
                    assert!(
                        ui.min_rect().right() <= right + 1.0,
                        "List overflows: {:?} > {right}",
                        ui.min_rect()
                    );
                });
            });
        }
    }
}

#[test]
fn stationary_hover_stops_requesting_immediate_frames() {
    let ctx = egui::Context::default();
    theme::apply(&ctx);
    let mut last_delay = std::time::Duration::ZERO;
    for frame in 0..40 {
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(600.0, 400.0),
            )),
            time: Some(frame as f64 * 0.1),
            events: if frame == 0 {
                vec![egui::Event::PointerMoved(egui::pos2(25.0, 25.0))]
            } else {
                vec![]
            },
            ..Default::default()
        };
        let output = ctx.run(input, |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                styled_button(
                    ui,
                    "Существующие правила",
                    ACCENT,
                    Color32::WHITE,
                    egui::Stroke::NONE,
                    6.0,
                    16.0,
                    None,
                    true,
                );
            });
        });
        last_delay = output.viewport_output[&egui::ViewportId::ROOT].repaint_delay;
    }
    assert!(
        last_delay > std::time::Duration::from_millis(100),
        "Stationary hover must let rendering sleep; delay was {last_delay:?}"
    );
}

fn sample_network() -> Vec<NetworkAdapter> {
    (0..8)
        .map(|i| NetworkAdapter {
            name: format!("Ethernet / VPN {i}"),
            description: "Virtual network adapter".into(),
            kind: "Ethernet",
            status: "Подключён",
            is_up: true,
            is_loopback: false,
            addresses: vec![
                network::NetworkAddress {
                    ip: "192.168.10.20".parse().unwrap(),
                    prefix_len: 24,
                    scope_id: 0,
                },
                network::NetworkAddress {
                    ip: "192.168.10.21".parse().unwrap(),
                    prefix_len: 24,
                    scope_id: 0,
                },
                network::NetworkAddress {
                    ip: "fe80::ffff:aaaa:bbbb:cccc".parse().unwrap(),
                    prefix_len: 64,
                    scope_id: 17,
                },
            ],
        })
        .collect()
}

#[test]
fn network_panel_fits_with_many_adapters_and_addresses() {
    for theme in [egui::Theme::Light, egui::Theme::Dark] {
        for show_error in [false, true] {
            let ctx = egui::Context::default();
            theme::apply(&ctx);
            ctx.set_theme(theme);
            let mut app = FirewallApp::default();
            app.network_adapters = sample_network();
            app.network_loaded = true;
            if show_error {
                app.network_error = Some("Test network error".into());
            }
            let input = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(302.0, 500.0),
                )),
                ..Default::default()
            };
            let _ = ctx.run(input, |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    let right = ui.max_rect().right();
                    let top = ui.cursor().top();
                    app.draw_network_panel(ui, 250.0);
                    assert!(
                        ui.min_rect().right() <= right + 1.0,
                        "Network overflows: {:?} > {right}",
                        ui.min_rect()
                    );
                    assert!(
                        ui.cursor().top() <= top + 260.0,
                        "Network panel grows beyond its own scroll area: {:?}",
                        ui.cursor()
                    );
                });
            });
        }
    }
}

#[test]
fn failed_refresh_keeps_last_network_snapshot_and_schedules_retry() {
    let ctx = egui::Context::default();
    let mut app = FirewallApp::default();
    app.network_adapters = sample_network();
    app.network_loaded = true;
    let (tx, rx) = mpsc::channel();
    app.network_rx = Some(rx);
    tx.send(Err("Test network error".into())).unwrap();
    app.poll_network(&ctx);
    assert_eq!(app.network_adapters.len(), 8);
    assert_eq!(app.network_adapters[0].addresses.len(), 3);
    assert!(app.network_error.is_some());
    assert!(app.network_rx.is_none());
    assert!(app.next_network_refresh > Instant::now());
}

#[test]
fn editing_returns_to_form_and_keeps_rule_values() {
    let mut app = FirewallApp::default();
    app.rules.push(FirewallRule {
        name: "SSH test".into(),
        local_ports: "22".into(),
        ..Default::default()
    });
    app.selected = Some(0);
    app.open_rules_window();
    app.load_selected_for_edit();
    assert!(!app.rules_window_open);
    assert_eq!(
        app.editing_rule.as_ref().map(|rule| rule.name.as_str()),
        Some("SSH test")
    );
    assert_eq!(app.form.local_ports, "22");
    app.open_rules_window();
    app.close_rules_window();
    assert_eq!(app.form.name, "SSH test");
}

#[test]
fn filtered_out_selection_cannot_be_opened_for_editing() {
    let mut app = FirewallApp {
        rules: vec![FirewallRule {
            name: "Hidden SSH".into(),
            ..Default::default()
        }],
        selected: Some(0),
        filter: "HTTP".into(),
        ..Default::default()
    };
    app.load_selected_for_edit();
    assert!(
        app.editing_rule.is_none(),
        "A rule hidden by the filter must not be edited"
    );
    assert!(app.selected.is_none());
}

#[test]
fn unsupported_protocol_cannot_be_silently_changed_to_any_by_editing() {
    let mut app = FirewallApp::default();
    app.rules.push(FirewallRule {
        name: "ICMP".into(),
        protocol: firewall_windows::model::Protocol::Other(1),
        ..Default::default()
    });
    app.selected = Some(0);
    app.load_selected_for_edit();
    assert!(app.editing_rule.is_none());
    assert!(matches!(app.status, StatusMsg::Err(_)));
    assert!(app.form.name.is_empty());
}
