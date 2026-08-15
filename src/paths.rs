//! State directory + canonical paths.

use std::path::{Path, PathBuf};

/// `$HOME/.mcpg` on Linux/macOS, `%APPDATA%\mcpg` on Windows.
pub fn default_state_dir() -> PathBuf {
    if let Ok(env) = std::env::var("MCPG_STATE_DIR")
        && !env.is_empty()
    {
        return PathBuf::from(env);
    }
    if let Some(home) = dirs::home_dir() {
        return home.join(".mcpg");
    }
    // Last-resort fallback for headless environments.
    PathBuf::from("./mcpg-state")
}

pub fn default_db_path(state_dir: &Path) -> PathBuf {
    state_dir.join("cp-state.db")
}

pub fn db_url(state_dir: &Path) -> String {
    format!(
        "sqlite://{}?mode=rwc",
        default_db_path(state_dir).to_string_lossy()
    )
}

pub fn ensure_dir(p: &Path) -> std::io::Result<()> {
    if !p.exists() {
        std::fs::create_dir_all(p)?;
    }
    Ok(())
}
