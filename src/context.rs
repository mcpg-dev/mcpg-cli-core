//! The `use` context: sticky org/workspace/env defaults.
//!
//! `mcpg cloud use --org acme --workspace prod --env eu` stores the
//! coordinates every cloud command would otherwise re-take as flags;
//! afterwards `mcpg cloud publish edge --config gw.yaml` is a complete
//! command. Resolution precedence is flag > env var > context >
//! error-with-hint — the context is a *default*, never an override.

use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub struct Context {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<String>,
}

fn path(state_dir: &Path) -> std::path::PathBuf {
    state_dir.join("context.json")
}

/// Load the stored context. A missing or unreadable file is an empty
/// context, not an error — the flags/env fallbacks still apply.
pub fn load(state_dir: &Path) -> Context {
    std::fs::read(path(state_dir))
        .ok()
        .and_then(|raw| serde_json::from_slice(&raw).ok())
        .unwrap_or_default()
}

pub fn save(state_dir: &Path, ctx: &Context) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec_pretty(ctx)?;
    std::fs::write(path(state_dir), bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_is_an_empty_context() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(load(dir.path()), Context::default());
    }

    #[test]
    fn round_trips_partial_contexts() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = Context {
            org: Some("acme".into()),
            workspace: None,
            env: Some("eu".into()),
        };
        save(dir.path(), &ctx).unwrap();
        assert_eq!(load(dir.path()), ctx);
    }

    #[test]
    fn corrupt_file_degrades_to_empty() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("context.json"), b"{not json").unwrap();
        assert_eq!(load(dir.path()), Context::default());
    }
}
