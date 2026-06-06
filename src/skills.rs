use std::{
    env,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use serde::Serialize;

pub const SKILL_NAME: &str = "sniper-operator";

pub const CODEX_SKILL_TEMPLATE: &str =
    include_str!("../packaging/skills/codex/sniper-operator/SKILL.md");
pub const CLAUDE_SKILL_TEMPLATE: &str =
    include_str!("../packaging/skills/claude/sniper-operator/SKILL.md");

#[derive(Debug, Serialize)]
pub struct InstalledSkill {
    pub agent: &'static str,
    pub path: String,
}

#[derive(Debug, Serialize)]
pub struct SkillsInstallResult {
    pub installed: Vec<InstalledSkill>,
}

/// Install skill files into the given root directory while preserving user files.
pub fn install_skill_folder(root: &Path, name: &str, skill_md: &str) -> Result<PathBuf> {
    validate_skill_folder_name(name)?;
    fs::create_dir_all(root)
        .with_context(|| format!("failed to create skills dir {}", root.display()))?;
    let skill_dir = root.join(name);
    fs::create_dir_all(&skill_dir)
        .with_context(|| format!("failed to create {}", skill_dir.display()))?;
    let skill_path = skill_dir.join("SKILL.md");
    let tmp_path = skill_dir.join(format!("SKILL.{}.tmp", uuid::Uuid::new_v4()));
    fs::write(&tmp_path, skill_md)
        .with_context(|| format!("failed to write {}", tmp_path.display()))?;
    if let Err(error) = fs::rename(&tmp_path, &skill_path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(error).with_context(|| {
            format!(
                "failed to replace {} with {}",
                tmp_path.display(),
                skill_path.display()
            )
        });
    }
    Ok(skill_dir)
}

fn validate_skill_folder_name(name: &str) -> Result<()> {
    if name.trim().is_empty()
        || name.contains('/')
        || name.contains('\\')
        || name == "."
        || name == ".."
    {
        bail!("skill folder name must be a single directory name");
    }
    Ok(())
}

pub fn default_codex_skills_dir() -> PathBuf {
    if let Some(codex_home) = agent_home_dir(env::var_os("CODEX_HOME")) {
        return PathBuf::from(codex_home).join("skills");
    }
    user_home_dir().join(".codex/skills")
}

pub fn default_claude_skills_dir() -> PathBuf {
    if let Some(claude_home) = agent_home_dir(env::var_os("CLAUDE_HOME")) {
        return PathBuf::from(claude_home).join("skills");
    }
    user_home_dir().join(".claude/skills")
}

fn agent_home_dir(value: Option<OsString>) -> Option<OsString> {
    let value = value?;
    if value.to_string_lossy().trim().is_empty() {
        return None;
    }
    Some(value)
}

pub fn user_home_dir() -> PathBuf {
    env::var_os("HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("USERPROFILE").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("."))
}

pub fn ensure_distinct_skill_install_targets(codex_root: &Path, claude_root: &Path) -> Result<()> {
    let codex_target = codex_root.join(SKILL_NAME).join("SKILL.md");
    let claude_target = claude_root.join(SKILL_NAME).join("SKILL.md");
    let canonical_conflict = match (
        canonicalize_existing_prefix(&codex_target),
        canonicalize_existing_prefix(&claude_target),
    ) {
        (Some(codex_target), Some(claude_target)) => codex_target == claude_target,
        _ => false,
    };
    if codex_target == claude_target || canonical_conflict {
        bail!(
            "codex and claude skill destinations resolve to the same SKILL.md path: {}",
            codex_target.display()
        );
    }
    Ok(())
}

fn canonicalize_existing_prefix(path: &Path) -> Option<PathBuf> {
    if let Ok(path) = fs::canonicalize(path) {
        return Some(path);
    }

    let mut current = path;
    let mut missing = Vec::new();
    while !current.exists() {
        missing.push(current.file_name()?.to_os_string());
        current = current.parent()?;
    }

    let mut canonical = fs::canonicalize(current).ok()?;
    for component in missing.iter().rev() {
        canonical.push(component);
    }
    Some(canonical)
}

/// Install both Claude and Codex skills silently.
/// Returns the list of installed skills, or an empty vec if nothing was installed.
pub fn auto_install_all() -> Vec<InstalledSkill> {
    auto_install_all_to(default_claude_skills_dir(), default_codex_skills_dir())
}

fn auto_install_all_to(claude_root: PathBuf, codex_root: PathBuf) -> Vec<InstalledSkill> {
    let mut installed = Vec::new();

    if ensure_distinct_skill_install_targets(&codex_root, &claude_root).is_err() {
        return installed;
    }

    if let Ok(path) = install_skill_folder(&claude_root, SKILL_NAME, CLAUDE_SKILL_TEMPLATE) {
        installed.push(InstalledSkill {
            agent: "claude",
            path: path.display().to_string(),
        });
    }

    if let Ok(path) = install_skill_folder(&codex_root, SKILL_NAME, CODEX_SKILL_TEMPLATE) {
        installed.push(InstalledSkill {
            agent: "codex",
            path: path.display().to_string(),
        });
    }

    installed
}

#[cfg(test)]
mod tests {
    use super::{agent_home_dir, auto_install_all_to, install_skill_folder};

    #[test]
    fn install_skill_folder_rejects_path_like_names() {
        let root = std::env::temp_dir().join(format!("sniper-skill-test-{}", uuid::Uuid::new_v4()));

        assert!(install_skill_folder(&root, "../outside", "# test\n").is_err());
        assert!(install_skill_folder(&root, "nested/skill", "# test\n").is_err());
        assert!(install_skill_folder(&root, "", "# test\n").is_err());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn install_skill_folder_cleans_temp_file_after_replace_failure() {
        let root = std::env::temp_dir().join(format!("sniper-skill-test-{}", uuid::Uuid::new_v4()));
        let skill_dir = root.join("sniper-operator");
        std::fs::create_dir_all(skill_dir.join("SKILL.md")).unwrap();

        assert!(install_skill_folder(&root, "sniper-operator", "# test\n").is_err());

        let leaked_temp = std::fs::read_dir(&skill_dir)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .any(|entry| {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                name.starts_with("SKILL.") && name.ends_with(".tmp")
            });
        assert!(!leaked_temp);

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn agent_home_dir_ignores_empty_values() {
        assert!(agent_home_dir(Some("".into())).is_none());
        assert!(agent_home_dir(Some(" \t ".into())).is_none());
        assert_eq!(
            agent_home_dir(Some("/tmp/sniper-agent-home".into())),
            Some("/tmp/sniper-agent-home".into())
        );
    }

    #[test]
    fn auto_install_all_skips_same_claude_and_codex_destination() {
        let root = std::env::temp_dir().join(format!("sniper-skill-same-{}", uuid::Uuid::new_v4()));

        let installed = auto_install_all_to(root.join("skills"), root.join("skills"));

        assert!(installed.is_empty());
        assert!(!root
            .join("skills")
            .join(super::SKILL_NAME)
            .join("SKILL.md")
            .exists());
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn auto_install_all_skips_symlinked_missing_skill_roots() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!(
            "sniper-skill-symlink-same-{}",
            uuid::Uuid::new_v4()
        ));
        let shared_home = root.join("shared-home");
        let codex_home = root.join("codex-home");
        let claude_home = root.join("claude-home");
        std::fs::create_dir_all(&shared_home).unwrap();
        symlink(&shared_home, &codex_home).unwrap();
        symlink(&shared_home, &claude_home).unwrap();

        let installed = auto_install_all_to(claude_home.join("skills"), codex_home.join("skills"));

        assert!(installed.is_empty());
        assert!(!shared_home
            .join("skills")
            .join(super::SKILL_NAME)
            .join("SKILL.md")
            .exists());
        let _ = std::fs::remove_dir_all(root);
    }
}
