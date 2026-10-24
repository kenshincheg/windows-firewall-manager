//! Проверки состояния списка без изменения Windows Firewall.

use super::*;

#[test]
fn cached_sort_preserves_order_for_every_column_direction_and_filter() {
    use firewall_windows::model::{Action, Direction, Protocol};
    let mut app = FirewallApp::default();
    app.replace_rules(
        (0..96)
            .map(|i| FirewallRule {
                name: ["SSH", "ssh", "Правило", "HTTP", "ПРАВИЛО"][i % 5].into(),
                local_ports: ["", "*", "22", "100-200", "80,443", " RPC "][i % 6].into(),
                application_path: [r"C:\Apps\SSH.exe", "", r"c:\apps\ssh.exe"][i % 3].into(),
                direction: if i % 2 == 0 {
                    Direction::Inbound
                } else {
                    Direction::Outbound
                },
                action: if i % 3 == 0 {
                    Action::Block
                } else {
                    Action::Allow
                },
                protocol: [Protocol::Tcp, Protocol::Udp, Protocol::Any][i % 3],
                comparison_key: (i % 4 != 0).then(|| vec![format!("{}", i % 7)]),
                ..Default::default()
            })
            .collect(),
    );
    for column in [
        SortColumn::Name,
        SortColumn::Direction,
        SortColumn::Action,
        SortColumn::Protocol,
        SortColumn::Ports,
        SortColumn::Application,
    ] {
        for direction in [SortDir::Asc, SortDir::Desc] {
            for duplicates_only in [false, true] {
                for filter in ["", "SSH", "прав", "443", "not found"] {
                    app.sort_col = column;
                    app.sort_dir = direction;
                    app.duplicates_only = duplicates_only;
                    app.filter = filter.into();
                    let lower = filter.to_lowercase();
                    let mut expected: Vec<_> = app
                        .rules
                        .iter()
                        .enumerate()
                        .filter(|(index, rule)| {
                            (!duplicates_only || app.duplicates.group(*index).is_some())
                                && (lower.is_empty()
                                    || rule.name.to_lowercase().contains(&lower)
                                    || rule.local_ports.to_lowercase().contains(&lower)
                                    || rule.application_path.to_lowercase().contains(&lower))
                        })
                        .map(|(index, _)| index)
                        .collect();
                    // Прежний компаратор: независимая проверка порядка и стабильности.
                    expected.sort_by(|&a, &b| {
                        if duplicates_only {
                            let order = app.duplicates.group(a).cmp(&app.duplicates.group(b));
                            if !order.is_eq() {
                                return order;
                            }
                        }
                        let (a, b) = (&app.rules[a], &app.rules[b]);
                        let ports = |s: &str| {
                            let s = s.trim();
                            (
                                s.split(['-', ',', ' '])
                                    .next()
                                    .unwrap_or(s)
                                    .parse::<u32>()
                                    .unwrap_or(u32::MAX),
                                s.to_lowercase(),
                            )
                        };
                        let order = match column {
                            SortColumn::Name => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
                            SortColumn::Direction => a.direction.label().cmp(b.direction.label()),
                            SortColumn::Action => a.action.label().cmp(b.action.label()),
                            SortColumn::Protocol => a.protocol.label().cmp(b.protocol.label()),
                            SortColumn::Ports => ports(&a.local_ports).cmp(&ports(&b.local_ports)),
                            SortColumn::Application => a
                                .application_path
                                .to_lowercase()
                                .cmp(&b.application_path.to_lowercase()),
                        };
                        if direction == SortDir::Desc {
                            order.reverse()
                        } else {
                            order
                        }
                    });
                    assert_eq!(app.compute_filtered_sorted_indices(), expected);
                }
            }
        }
    }
}

#[test]
fn replacing_rules_and_changing_filters_invalidates_cached_rows_and_selection() {
    let mut app = FirewallApp::default();
    app.replace_rules(vec![FirewallRule {
        name: "SSH".into(),
        ..Default::default()
    }]);
    app.ensure_indices();
    assert_eq!(app.cached_indices, vec![0]);
    assert!(!app.indices_dirty);
    app.selected = Some(0);
    app.filter = "HTTP".into();
    app.rules_filter_changed();
    assert!(app.indices_dirty);
    assert!(app.selected.is_none());
    app.ensure_indices();
    assert!(app.cached_indices.is_empty());
    app.filter.clear();
    app.replace_rules(Vec::new());
    app.ensure_indices();
    assert!(app.cached_indices.is_empty());
    assert_eq!(app.duplicates.rule_count, 0);
    assert_eq!(app.duplicates.unreadable_count, 0);
}

#[test]
fn hidden_or_stale_selection_cannot_be_used_by_delete_handler() {
    let mut app = FirewallApp {
        rules: vec![FirewallRule {
            name: "SSH".into(),
            ..Default::default()
        }],
        selected: Some(0),
        filter: "HTTP".into(),
        is_admin: true,
        ..Default::default()
    };
    // The handler must return before invoking the real Windows Firewall API.
    app.remove_selected();
    assert_eq!(app.rules.len(), 1);
    assert!(app.selected.is_none());
    assert!(matches!(app.status, StatusMsg::Err(_)));
    app.selected = Some(99);
    assert!(app.require_selected_rule_index().is_none());
}

#[test]
fn selection_matching_filter_by_application_remains_valid_after_sorting() {
    let mut app = FirewallApp {
        rules: vec![
            FirewallRule {
                name: "SSH".into(),
                application_path: r"C:\Apps\SSH.exe".into(),
                local_ports: "22".into(),
                ..Default::default()
            },
            FirewallRule {
                name: "HTTP".into(),
                local_ports: "80".into(),
                ..Default::default()
            },
        ],
        selected: Some(0),
        filter: r"c:\apps".into(),
        ..Default::default()
    };
    assert_eq!(app.selected_visible_index(), Some(0));
    app.toggle_sort(SortColumn::Ports);
    assert_eq!(app.selected_visible_index(), Some(0));
    app.filter = "22".into();
    assert_eq!(app.selected_visible_index(), Some(0));
}

#[test]
fn duplicate_filter_combines_with_search_and_blocks_hidden_selection() {
    let mut app = FirewallApp::default();
    app.rules = ["SSH original", "HTTP", "SSH copy", "Unique"]
        .into_iter()
        .enumerate()
        .map(|(i, name)| FirewallRule {
            name: name.into(),
            comparison_key: Some(vec![if i == 0 || i == 2 {
                "ssh".into()
            } else {
                name.into()
            }]),
            ..Default::default()
        })
        .collect();
    app.duplicates = super::super::duplicates::DuplicateIndex::build(&app.rules);
    app.duplicates_only = true;
    assert_eq!(app.compute_filtered_sorted_indices(), vec![2, 0]);
    app.filter = "original".into();
    assert_eq!(app.compute_filtered_sorted_indices(), vec![0]);
    app.selected = Some(1);
    assert!(app.selected_visible_index().is_none());
    app.filter.clear();
    app.rules.remove(2);
    app.duplicates = super::super::duplicates::DuplicateIndex::build(&app.rules);
    assert!(app.compute_filtered_sorted_indices().is_empty());
}
