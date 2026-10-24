//! Фильтрация, сортировка и допустимость выбранной строки.

use super::{FirewallApp, SortColumn, SortDir};
use firewall_windows::model::FirewallRule;

#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum RuleSortKey {
    Label(&'static str),
    Text(String),
    Ports(u32, String),
}

struct SortEntry {
    index: usize,
    group: Option<usize>,
    key: RuleSortKey,
}

fn rule_sort_key(rule: &FirewallRule, column: SortColumn) -> RuleSortKey {
    match column {
        SortColumn::Name => RuleSortKey::Text(rule.name.to_lowercase()),
        SortColumn::Direction => RuleSortKey::Label(rule.direction.label()),
        SortColumn::Action => RuleSortKey::Label(rule.action.label()),
        SortColumn::Protocol => RuleSortKey::Label(rule.protocol.label()),
        SortColumn::Ports => {
            let (number, text) = port_sort_key(&rule.local_ports);
            RuleSortKey::Ports(number, text)
        }
        SortColumn::Application => RuleSortKey::Text(rule.application_path.to_lowercase()),
    }
}

/// Ключ сортировки портов: первый номер в строке, иначе u32::MAX.
fn port_sort_key(ports: &str) -> (u32, String) {
    let s = ports.trim();
    if s.is_empty() {
        return (u32::MAX, String::new());
    }
    let first = s.split(['-', ',', ' ']).next().unwrap_or(s);
    let n = first.parse::<u32>().unwrap_or(u32::MAX);
    (n, s.to_lowercase())
}

impl FirewallApp {
    pub(super) fn invalidate_indices(&mut self) {
        self.indices_dirty = true;
    }

    pub(super) fn ensure_indices(&mut self) {
        if !self.indices_dirty {
            return;
        }
        self.cached_indices = self.compute_filtered_sorted_indices();
        self.indices_dirty = false;
    }

    pub(super) fn selected_visible_index(&self) -> Option<usize> {
        let index = self.selected?;
        let rule = self.rules.get(index)?;
        self.rule_is_visible(index, rule, &self.filter.to_lowercase())
            .then_some(index)
    }

    fn rule_is_visible(&self, index: usize, rule: &FirewallRule, filter: &str) -> bool {
        (!self.duplicates_only || self.duplicates.group(index).is_some())
            && rule_matches_filter(rule, filter)
    }

    pub(super) fn rules_filter_changed(&mut self) {
        self.invalidate_indices();
        self.selected = self.selected_visible_index();
    }

    pub(super) fn require_selected_rule_index(&mut self) -> Option<usize> {
        if let Some(index) = self.selected_visible_index() {
            return Some(index);
        }
        self.selected = None;
        self.set_err("Выберите правило в текущем списке");
        None
    }

    pub(super) fn toggle_sort(&mut self, col: SortColumn) {
        if self.sort_col == col {
            self.sort_dir = match self.sort_dir {
                SortDir::Asc => SortDir::Desc,
                SortDir::Desc => SortDir::Asc,
            };
        } else {
            self.sort_col = col;
            self.sort_dir = SortDir::Asc;
        }
        self.invalidate_indices();
    }

    pub(super) fn compute_filtered_sorted_indices(&self) -> Vec<usize> {
        let filter = self.filter.to_lowercase();
        // Ключ создаётся один раз на строку, а не на каждое сравнение сортировки.
        let mut entries: Vec<_> = self
            .rules
            .iter()
            .enumerate()
            .filter(|(i, rule)| self.rule_is_visible(*i, rule, &filter))
            .map(|(index, rule)| SortEntry {
                index,
                group: if self.duplicates_only {
                    self.duplicates.group(index)
                } else {
                    None
                },
                key: rule_sort_key(rule, self.sort_col),
            })
            .collect();

        entries.sort_by(|a, b| {
            a.group.cmp(&b.group).then_with(|| {
                let ord = a.key.cmp(&b.key);
                match self.sort_dir {
                    SortDir::Asc => ord,
                    SortDir::Desc => ord.reverse(),
                }
            })
        });
        entries.into_iter().map(|entry| entry.index).collect()
    }
}

fn rule_matches_filter(rule: &FirewallRule, lowercase_filter: &str) -> bool {
    lowercase_filter.is_empty()
        || rule.name.to_lowercase().contains(lowercase_filter)
        || rule.local_ports.to_lowercase().contains(lowercase_filter)
        || rule
            .application_path
            .to_lowercase()
            .contains(lowercase_filter)
}
