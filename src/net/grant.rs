//! Сводка гранта B для отображения на A (только информативно; enforcement — на B).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, JsonSchema)]
pub struct GrantSummary {
    pub allowed_paths: Vec<String>, // пусто = весь диск
    pub allow_shell: bool,
    pub allow_dangerous: bool,
    pub ttl_secs: Option<u64>, // None = без лимита
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn serde_roundtrip() {
        let g = GrantSummary { allowed_paths: vec!["/tmp".into()], allow_shell: false, allow_dangerous: true, ttl_secs: Some(300) };
        let j = serde_json::to_string(&g).unwrap();
        assert_eq!(serde_json::from_str::<GrantSummary>(&j).unwrap(), g);
    }
    #[test]
    fn default_is_restrictive_empty() {
        let g = GrantSummary::default();
        assert!(g.allowed_paths.is_empty() && !g.allow_shell && !g.allow_dangerous && g.ttl_secs.is_none());
    }
}
