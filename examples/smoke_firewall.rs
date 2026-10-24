//! Проверка add / list / remove тестового правила.
//! Запуск: cargo run --example smoke_firewall --release
//! (нужны права администратора)

use firewall_windows::admin;
use firewall_windows::firewall;
use firewall_windows::model::{Action, Direction, FirewallRule, Protocol};

const RULE_NAME: &str = "FWMgr_Smoke_Test_49152";

fn main() {
    let log_path = std::env::temp_dir().join("fwmgr_smoke_result.txt");
    let mut log = String::new();
    macro_rules! logln {
        ($($t:tt)*) => {{
            let line = format!($($t)*);
            println!("{line}");
            log.push_str(&line);
            log.push('\n');
        }};
    }

    let write_log = |log: &str, code: i32| -> ! {
        let _ = std::fs::write(&log_path, log);
        std::process::exit(code);
    };

    logln!("elevated: {}", admin::is_elevated());
    logln!("log: {}", log_path.display());

    let rule = FirewallRule {
        name: RULE_NAME.into(),
        direction: Direction::Inbound,
        action: Action::Allow,
        protocol: Protocol::Tcp,
        local_ports: "49152".into(),
        description: "smoke test by Kenshin FW manager".into(),
        enabled: true,
        ..FirewallRule::default()
    };

    let _ = firewall::remove_rule(RULE_NAME);

    logln!("add…");
    if let Err(e) = firewall::add_rule(&rule) {
        logln!("ADD FAIL: {e}");
        write_log(&log, 1);
    }

    logln!("list…");
    let rules = match firewall::list_rules() {
        Ok(r) => r,
        Err(e) => {
            logln!("LIST FAIL: {e}");
            write_log(&log, 2);
        }
    };
    let found = rules.into_iter().find(|r| r.name == RULE_NAME);
    match found {
        Some(r) => {
            logln!(
                "OK found: name={}, ports={}, proto={}, dir={:?}, action={:?}",
                r.name,
                r.local_ports,
                r.protocol.label(),
                r.direction,
                r.action
            );
        }
        None => {
            logln!("LIST OK but rule «{RULE_NAME}» not found");
            write_log(&log, 3);
        }
    }

    logln!("remove…");
    if let Err(e) = firewall::remove_rule(RULE_NAME) {
        logln!("REMOVE FAIL: {e}");
        write_log(&log, 4);
    }

    let still = firewall::list_rules()
        .unwrap_or_default()
        .into_iter()
        .any(|r| r.name == RULE_NAME);
    if still {
        logln!("REMOVE reported OK but rule still listed");
        write_log(&log, 5);
    }

    logln!("SMOKE PASS");
    let _ = std::fs::write(&log_path, &log);
}
