//! Только чтение: статистика дублей без вывода имён и изменения правил.
use firewall_windows::firewall;
use std::collections::HashMap;

fn main() -> Result<(), String> {
    let started = std::time::Instant::now();
    let rules = firewall::list_rules()?;
    let mut groups = HashMap::new();
    let mut unreadable = 0;
    for rule in &rules {
        if let Some(key) = &rule.comparison_key {
            *groups.entry(key).or_insert(0usize) += 1;
        } else {
            unreadable += 1;
        }
    }
    let duplicates: Vec<_> = groups.values().filter(|&&n| n > 1).collect();
    println!(
        "Rules: {}; unreadable: {}; duplicate groups: {}; duplicate rules: {}; elapsed: {:?}",
        rules.len(),
        unreadable,
        duplicates.len(),
        duplicates.into_iter().sum::<usize>(),
        started.elapsed()
    );
    Ok(())
}
