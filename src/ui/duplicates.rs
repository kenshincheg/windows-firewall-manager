//! Индекс одинаковых условий, вычисляется один раз при загрузке правил.

use firewall_windows::model::FirewallRule;
use std::collections::HashMap;

#[derive(Default)]
pub(super) struct DuplicateIndex {
    pub group_by_rule: Vec<Option<usize>>,
    pub sizes: Vec<usize>,
    pub rule_count: usize,
    pub unreadable_count: usize,
}

impl DuplicateIndex {
    pub fn build(rules: &[FirewallRule]) -> Self {
        let mut matches: HashMap<&Vec<String>, Vec<usize>> = HashMap::new();
        let mut unreadable_count = 0;
        for (index, rule) in rules.iter().enumerate() {
            if let Some(key) = &rule.comparison_key {
                matches.entry(key).or_default().push(index);
            } else {
                unreadable_count += 1;
            }
        }
        let mut groups: Vec<_> = matches.into_values().filter(|v| v.len() > 1).collect();
        groups.sort_by_key(|v| v[0]);
        let mut result = Self {
            group_by_rule: vec![None; rules.len()],
            sizes: Vec::with_capacity(groups.len()),
            rule_count: 0,
            unreadable_count,
        };
        for (group, indices) in groups.into_iter().enumerate() {
            result.sizes.push(indices.len());
            result.rule_count += indices.len();
            for index in indices {
                result.group_by_rule[index] = Some(group);
            }
        }
        result
    }

    pub fn group(&self, index: usize) -> Option<usize> {
        self.group_by_rule.get(index).copied().flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn includes_every_copy_and_excludes_unreadable_rules() {
        let rules: Vec<_> = [Some("a"), Some("b"), Some("a"), None, None, Some("a")]
            .into_iter()
            .map(|key| FirewallRule {
                comparison_key: key.map(|s| vec![s.into()]),
                ..Default::default()
            })
            .collect();
        let index = DuplicateIndex::build(&rules);
        assert_eq!(index.sizes, vec![3]);
        assert_eq!(index.rule_count, 3);
        assert_eq!(index.unreadable_count, 2);
        assert_eq!(
            index.group_by_rule,
            vec![Some(0), None, Some(0), None, None, Some(0)]
        );
    }
}
