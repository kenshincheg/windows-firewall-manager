//! Явно включаемые проверки реального Firewall через обработчик кнопки UI.
//! Никогда не запускаются обычным cargo test. Требуются администратор,
//! резервная копия и FWMGR_LIVE_DELETE=verify либо cleanup.

use super::*;
use std::{collections::HashSet, path::Path};

fn checked_app(mode: &str) -> FirewallApp {
    assert_eq!(std::env::var("FWMGR_LIVE_DELETE").as_deref(), Ok(mode));
    assert!(
        firewall_windows::admin::is_elevated(),
        "Administrator required"
    );
    let backup = std::env::var("FWMGR_LIVE_BACKUP")
        .unwrap_or_else(|_| "target/live-duplicate-check/before-cleanup.wfw".into());
    assert!(Path::new(&backup).metadata().unwrap().len() > 0);
    let mut app = FirewallApp::default();
    app.reload();
    assert!(matches!(app.status, StatusMsg::Ok(_)), "Cannot load rules");
    assert!(
        app.rules.iter().all(|r| r.comparison_key.is_some()),
        "Incomplete conditions; abort"
    );
    app.duplicates_only = true;
    app
}

fn fingerprints(rules: &[FirewallRule]) -> Vec<String> {
    let mut result: Vec<_> = rules.iter().map(|r| format!("{r:?}")).collect();
    result.sort();
    result
}

fn check_filter(app: &FirewallApp) {
    // Независимый попарный поиск, без использования индекса групп UI.
    let expected: HashSet<_> = app
        .rules
        .iter()
        .enumerate()
        .filter_map(|(i, rule)| {
            let key = rule.comparison_key.as_ref()?;
            app.rules
                .iter()
                .enumerate()
                .any(|(j, other)| i != j && other.comparison_key.as_ref() == Some(key))
                .then_some(i)
        })
        .collect();
    let visible: HashSet<_> = app.compute_filtered_sorted_indices().into_iter().collect();
    assert_eq!(visible, expected, "Duplicate filter mismatch");
}

fn delete_through_button_handler(app: &mut FirewallApp, index: usize) {
    let selected = format!("{:?}", app.rules[index]);
    let name = app.rules[index].name.clone();
    let mut expected = fingerprints(&app.rules);
    let position = expected.iter().position(|s| s == &selected).unwrap();
    expected.remove(position);
    app.selected = Some(index);
    // Тот же метод, который вызывается кнопкой «Удалить выбранное».
    app.remove_selected();
    let status = match &app.status {
        StatusMsg::Ok(message) => message,
        StatusMsg::Err(message) => panic!("Deletion failed for {name}: {message}"),
        StatusMsg::None => panic!("Missing deletion result"),
    };
    assert!(status.contains("удалена"), "Unexpected status: {status}");
    assert_eq!(
        fingerprints(&app.rules),
        expected,
        "Deleted more than the selected copy, or changed another rule"
    );
    println!("Deleted exactly one copy through UI handler: {name}");
}

struct TestRuleCleanup(String);
impl Drop for TestRuleCleanup {
    fn drop(&mut self) {
        if let Ok(rules) = firewall::list_rules() {
            for rule in rules.into_iter().filter(|r| r.name.starts_with(&self.0)) {
                if let Err(error) = firewall::remove_rule_snapshot(&rule) {
                    eprintln!("Test cleanup failed for {}: {error}", rule.name);
                }
            }
        }
    }
}

#[test]
#[ignore = "Modifies real firewall: administrator and explicit verify opt-in required"]
fn live_verify_duplicate_deletion() {
    let mut app = checked_app("verify");
    check_filter(&app);
    let original = fingerprints(&app.rules);
    let prefix = format!(
        "FWMgr_LiveDuplicateTest_{:?}_",
        unsafe { windows::Win32::System::Com::CoCreateGuid() }.unwrap()
    );
    let _cleanup = TestRuleCleanup(prefix.clone());
    let first = FirewallRule {
        name: format!("{prefix}A"),
        description: "Live deletion test A".into(),
        enabled: false,
        local_ports: "65534".into(),
        ..Default::default()
    };
    let second = FirewallRule {
        name: format!("{prefix}B"),
        description: "Live deletion test B".into(),
        ..first.clone()
    };
    firewall::add_rule(&first).unwrap();
    firewall::add_rule(&second).unwrap();
    app.reload();
    check_filter(&app);
    let a = app.rules.iter().position(|r| r.name == first.name).unwrap();
    let b = app
        .rules
        .iter()
        .position(|r| r.name == second.name)
        .unwrap();
    assert_eq!(app.duplicates.group(a), app.duplicates.group(b));
    assert!(app.duplicates.group(a).is_some());
    delete_through_button_handler(&mut app, b);
    assert!(app.rules.iter().any(|r| r.name == first.name));
    assert!(!app.rules.iter().any(|r| r.name == second.name));
    // Повторяем на двух правилах с одним именем и разными описаниями.
    firewall::add_rule(&second).unwrap();
    firewall::update_rule(
        &second.name,
        &FirewallRule {
            name: first.name.clone(),
            ..second
        },
    )
    .unwrap();
    app.reload();
    let same: Vec<_> = app
        .rules
        .iter()
        .enumerate()
        .filter(|(_, r)| r.name == first.name)
        .collect();
    assert_eq!(same.len(), 2, "Could not prepare equal-name rules");
    let selected = same
        .iter()
        .find(|(_, r)| r.description == "Live deletion test B")
        .unwrap()
        .0;
    delete_through_button_handler(&mut app, selected);
    assert_eq!(app.rules.iter().filter(|r| r.name == first.name).count(), 1);
    let survivor = app.rules.iter().position(|r| r.name == first.name).unwrap();
    assert_eq!(app.rules[survivor].description, "Live deletion test A");
    app.duplicates_only = false;
    delete_through_button_handler(&mut app, survivor);
    assert_eq!(
        fingerprints(&app.rules),
        original,
        "Test must leave the original policy intact"
    );
    println!("LIVE VERIFICATION PASSED; original rules unchanged");
}

#[test]
#[ignore = "Deletes redundant real rules: administrator and explicit cleanup opt-in required"]
fn live_remove_redundant_copies() {
    let mut app = checked_app("cleanup");
    check_filter(&app);
    let before = app.rules.len();
    let groups = app.duplicates.sizes.len();
    let mut retained = HashSet::new();
    let mut planned = Vec::new();
    for (index, rule) in app.rules.iter().enumerate() {
        if let Some(group) = app.duplicates.group(index) {
            if !retained.insert(group) {
                planned.push(rule.clone());
            }
        }
    }
    std::fs::write(
        "target/live-duplicate-check/deletion-plan.txt",
        format!("{planned:#?}"),
    )
    .unwrap();
    let mut expected = fingerprints(&app.rules);
    for rule in &planned {
        app.reload();
        assert!(matches!(app.status, StatusMsg::Ok(_)));
        assert_eq!(
            fingerprints(&app.rules),
            expected,
            "Policy changed outside the cleanup; abort"
        );
        let fingerprint = format!("{rule:?}");
        let index = app
            .rules
            .iter()
            .position(|r| format!("{r:?}") == fingerprint)
            .unwrap();
        assert!(
            app.duplicates.group(index).is_some(),
            "No surviving copy; abort"
        );
        delete_through_button_handler(&mut app, index);
        expected.remove(expected.iter().position(|s| s == &fingerprint).unwrap());
        assert_eq!(fingerprints(&app.rules), expected);
    }
    check_filter(&app);
    assert!(app.compute_filtered_sorted_indices().is_empty());
    assert!(app.duplicates.sizes.is_empty());
    let result = format!(
        "Before: {before}; groups: {groups}; removed: {}; after: {}; remaining duplicate groups: 0\n",
        planned.len(),
        app.rules.len()
    );
    std::fs::write("target/live-duplicate-check/result.txt", &result).unwrap();
    println!("{result}");
}

fn assert_saved_rule(app: &FirewallApp, expected: &FirewallRule) {
    let saved = app
        .rules
        .iter()
        .find(|r| r.name == expected.name && r.description == expected.description)
        .unwrap();
    assert_eq!(saved.protocol, expected.protocol);
    assert_eq!(saved.direction, expected.direction);
    assert_eq!(saved.action, expected.action);
    assert_eq!(saved.profiles, expected.profiles);
    assert_eq!(saved.enabled, expected.enabled);
    assert!(
        saved
            .application_path
            .eq_ignore_ascii_case(&expected.application_path)
    );
    if expected.protocol != firewall_windows::model::Protocol::Any {
        assert_eq!(
            saved.local_ports,
            if expected.local_ports.is_empty() {
                "*"
            } else {
                &expected.local_ports
            }
        );
    }
}

#[test]
#[ignore = "Live add/edit/delete: administrator, backup and lifecycle opt-in required"]
fn live_rule_lifecycle_matrix() {
    use firewall_windows::model::{Action, Direction, Profiles, Protocol};
    let mut app = checked_app("lifecycle");
    app.duplicates_only = false;
    let original = fingerprints(&app.rules);
    let prefix = format!(
        "FWMgr_Lifecycle_{:?}_",
        unsafe { windows::Win32::System::Com::CoCreateGuid() }.unwrap()
    );
    let _cleanup = TestRuleCleanup(prefix.clone());
    let executable = std::env::current_exe().unwrap().display().to_string();
    let mut cases = 0;
    for protocol in [Protocol::Tcp, Protocol::Udp, Protocol::Any] {
        for direction in [Direction::Inbound, Direction::Outbound] {
            for action in [Action::Allow, Action::Block] {
                for profiles in [
                    Profiles {
                        domain: false,
                        private: true,
                        public: false,
                    },
                    Profiles {
                        domain: true,
                        private: false,
                        public: true,
                    },
                ] {
                    let rule = FirewallRule {
                        name: format!("{prefix}{cases}_Тест"),
                        description: format!("Lifecycle case {cases}"),
                        protocol,
                        direction,
                        action,
                        profiles,
                        enabled: false,
                        application_path: executable.clone(),
                        local_ports: if protocol == Protocol::Any {
                            String::new()
                        } else {
                            ["1", "65535", "45000-45002", "80,443", "*", ""][cases % 6].into()
                        },
                        ..Default::default()
                    };
                    app.form = rule.clone();
                    app.add_or_save();
                    assert!(matches!(&app.status, StatusMsg::Ok(s) if s.contains("добавлено")));
                    assert_saved_rule(&app, &rule);
                    for next_protocol in [Protocol::Tcp, Protocol::Udp, Protocol::Any] {
                        app.selected = app.rules.iter().position(|r| r.name == rule.name);
                        app.load_selected_for_edit();
                        app.form.protocol = next_protocol;
                        app.form.local_ports = if next_protocol == Protocol::Any {
                            String::new()
                        } else {
                            "45100-45102".into()
                        };
                        app.form.description = format!("Edited {cases} {}", next_protocol.label());
                        app.form.action = if action == Action::Allow {
                            Action::Block
                        } else {
                            Action::Allow
                        };
                        app.form.direction = if direction == Direction::Inbound {
                            Direction::Outbound
                        } else {
                            Direction::Inbound
                        };
                        let expected = app.form.clone();
                        app.add_or_save();
                        assert!(
                            matches!(&app.status, StatusMsg::Ok(s) if s.contains("обновлено")),
                            "Edit failed"
                        );
                        assert_saved_rule(&app, &expected);
                    }
                    let index = app.rules.iter().position(|r| r.name == rule.name).unwrap();
                    delete_through_button_handler(&mut app, index);
                    assert_eq!(fingerprints(&app.rules), original);
                    cases += 1;
                }
            }
        }
    }
    println!(
        "MATRIX PASSED: {cases} additions, {} edits and {cases} deletions",
        cases * 3
    );

    let first = FirewallRule {
        name: format!("{prefix}Same"),
        description: "First".into(),
        local_ports: "45200".into(),
        enabled: false,
        ..Default::default()
    };
    let second = FirewallRule {
        name: format!("{prefix}Second"),
        description: "Second".into(),
        ..first.clone()
    };
    for rule in [&first, &second] {
        app.form = rule.clone();
        app.add_or_save();
    }
    app.selected = app.rules.iter().position(|r| r.name == second.name);
    app.load_selected_for_edit();
    app.form.name = first.name.clone();
    app.add_or_save();
    assert_eq!(app.rules.iter().filter(|r| r.name == first.name).count(), 2);
    app.selected = app
        .rules
        .iter()
        .position(|r| r.name == first.name && r.description == "Second");
    app.load_selected_for_edit();
    app.form.local_ports = "45201".into();
    app.add_or_save();
    assert!(matches!(&app.status, StatusMsg::Ok(s) if s.contains("обновлено")));
    assert_eq!(
        app.rules
            .iter()
            .find(|r| r.description == "First" && r.name == first.name)
            .unwrap()
            .local_ports,
        "45200"
    );
    assert_eq!(
        app.rules
            .iter()
            .find(|r| r.description == "Second" && r.name == first.name)
            .unwrap()
            .local_ports,
        "45201"
    );
    println!("EQUAL-NAME EDIT PASSED: only selected copy changed");

    app.selected = app
        .rules
        .iter()
        .position(|r| r.name == first.name && r.description == "Second");
    app.load_selected_for_edit();
    let editing = app.form.clone();
    let baseline = fingerprints(&app.rules);
    for invalid in ["0", "65536", "100-1", "22,", "abc"] {
        app.form.local_ports = invalid.into();
        app.add_or_save();
        assert!(matches!(app.status, StatusMsg::Err(_)));
        assert_eq!(app.form.local_ports, invalid);
        assert!(app.editing_rule.is_some());
        assert_eq!(fingerprints(&firewall::list_rules().unwrap()), baseline);
    }
    app.form = editing.clone();
    let external = FirewallRule {
        description: "External change".into(),
        ..editing.clone()
    };
    firewall::update_rule_snapshot(app.editing_rule.as_ref().unwrap(), &external).unwrap();
    app.form.description = "Stale save".into();
    app.add_or_save();
    assert!(matches!(app.status, StatusMsg::Err(_)));
    assert!(firewall::remove_rule_snapshot(app.editing_rule.as_ref().unwrap()).is_err());
    app.clear_form();
    app.reload();
    assert_saved_rule(&app, &external);
    println!("INVALID INPUT AND STALE SNAPSHOT PASSED");
    while let Some(index) = app.rules.iter().position(|r| r.name.starts_with(&prefix)) {
        delete_through_button_handler(&mut app, index);
    }
    assert_eq!(fingerprints(&app.rules), original);
    println!("LIVE LIFECYCLE PASSED; all temporary rules removed; original policy unchanged");
}
