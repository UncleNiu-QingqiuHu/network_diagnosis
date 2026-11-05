//! 技能（Skill）：扫描、导入、启停。
//!
//! 技能就是一份带简单 frontmatter 的 Markdown，内容会作为方法论注入系统提示词。
//! 这里刻意**只读取**其它 Agent 的目录，导入时是「复制一份到本应用」，
//! 不会改动对方的文件 —— 用户的 Claude Code / WorkBuddy 配置不该被我们动。

use crate::config::AgentStore;
use crate::AgentError;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// 单个技能最多注入多少字符，避免一篇长文把上下文吃干净。
pub const MAX_SKILL_CHARS: usize = 6000;
/// 扫描时单个文件的大小上限。
const MAX_FILE_BYTES: u64 = 200 * 1024;
/// 扫描目录深度上限。
const MAX_DEPTH: usize = 3;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Skill {
    pub slug: String,
    pub name: String,
    pub description: String,
    /// 导入来源路径，界面展示给用户判断可信度
    pub source: String,
    pub imported_at: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

/// 扫描到的候选技能（尚未导入）。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkillCandidate {
    pub name: String,
    pub description: String,
    pub path: String,
    /// 所属 Agent 目录，如「Claude Code」「WorkBuddy」
    pub origin: String,
    pub bytes: u64,
    /// 已经导入过（按来源路径判断）
    pub imported: bool,
}

/// 已知的其它 Agent 技能目录。
///
/// 只收录有明确约定的位置；不做全盘搜索 —— 全盘扫描既慢又容易把无关 Markdown
/// 当技能塞进来。
pub fn known_roots(project_root: Option<&Path>) -> Vec<(PathBuf, &'static str)> {
    let mut out: Vec<(PathBuf, &'static str)> = Vec::new();
    if let Some(home) = dirs::home_dir() {
        out.push((home.join(".claude").join("skills"), "Claude Code"));
        out.push((home.join(".workbuddy").join("skills"), "WorkBuddy"));
        out.push((home.join(".codex").join("skills"), "Codex"));
        out.push((home.join(".cursor").join("rules"), "Cursor"));
        out.push((home.join(".qoder").join("skills"), "Qoder"));
    }
    if let Some(root) = project_root {
        out.push((root.join(".claude").join("skills"), "Claude Code（项目）"));
        out.push((root.join(".workbuddy").join("skills"), "WorkBuddy（项目）"));
        out.push((root.join(".cursor").join("rules"), "Cursor（项目）"));
    }
    out
}

/// 列出实际存在、且非空的扫描根，供界面显示「从哪里找」。
pub fn existing_roots(project_root: Option<&Path>) -> Vec<(PathBuf, String)> {
    known_roots(project_root)
        .into_iter()
        .filter(|(p, _)| p.is_dir())
        .map(|(p, label)| (p, label.to_string()))
        .collect()
}

/// 扫描一个目录下的候选技能。
pub fn scan(root: &Path, origin: &str, imported_sources: &[String]) -> Vec<SkillCandidate> {
    let mut out = Vec::new();
    if !root.is_dir() {
        return out;
    }
    for entry in walk(root, 0) {
        let name = entry
            .file_name()
            .map(|n| n.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        let is_skill_file = name == "skill.md";
        let is_rule_file = entry
            .extension()
            .map(|e| e.eq_ignore_ascii_case("md") || e.eq_ignore_ascii_case("mdc"))
            .unwrap_or(false);
        // 只认 SKILL.md，或扫描根下一层的 .md/.mdc（Cursor 规则就是这样放的）
        if !is_skill_file && !(is_rule_file && depth_of(root, &entry) <= 1) {
            continue;
        }
        let Ok(meta) = std::fs::metadata(&entry) else {
            continue;
        };
        if meta.len() > MAX_FILE_BYTES {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&entry) else {
            continue;
        };
        // SKILL.md 用所在目录名当标题；散落的 .md/.mdc 用自己的文件名
        let fallback = if is_skill_file {
            entry
                .parent()
                .and_then(|p| p.file_name())
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| origin.to_string())
        } else {
            entry
                .file_stem()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| origin.to_string())
        };
        let parsed = parse(&text, &fallback);
        let path = entry.to_string_lossy().to_string();
        out.push(SkillCandidate {
            name: parsed.name,
            description: parsed.description,
            imported: imported_sources.iter().any(|s| s == &path),
            path,
            origin: origin.to_string(),
            bytes: meta.len(),
        });
        if out.len() >= 200 {
            break;
        }
    }
    out
}

/// 扫描全部已知目录。
pub fn scan_all(project_root: Option<&Path>, imported_sources: &[String]) -> Vec<SkillCandidate> {
    let mut out = Vec::new();
    for (dir, origin) in known_roots(project_root) {
        out.extend(scan(&dir, origin, imported_sources));
    }
    // 同一文件可能被多个根扫到（软链接），按路径去重
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out.dedup_by(|a, b| a.path == b.path);
    out
}

/// 深度受限的目录遍历（不跟随符号链接，避免环路）。
fn walk(dir: &Path, depth: usize) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if depth > MAX_DEPTH {
        return files;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return files;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(ft) = entry.file_type() else { continue };
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            files.extend(walk(&path, depth + 1));
        } else if ft.is_file() {
            files.push(path);
        }
    }
    files
}

fn depth_of(root: &Path, file: &Path) -> usize {
    file.strip_prefix(root)
        .map(|p| p.components().count())
        .unwrap_or(99)
}

/// 解析出的技能文本。
pub struct ParsedSkill {
    pub name: String,
    pub description: String,
    pub body: String,
}

/// 解析 frontmatter + 正文。
///
/// 不引入 YAML 依赖：技能头部只需要 `name` 与 `description` 两个字段，
/// 逐行解析足够，也避免半吊子 YAML 兼容问题。
pub fn parse(text: &str, fallback_name: &str) -> ParsedSkill {
    let mut name = fallback_name.to_string();
    let mut description = String::new();
    let mut body_start = 0usize;

    let trimmed = text.trim_start_matches('\u{feff}');
    if let Some(rest) = trimmed.strip_prefix("---") {
        if let Some(end) = rest.find("\n---") {
            let header = &rest[..end];
            read_header(header, &mut name, &mut description);
            // 跳过结束标记那一行的换行
            let consumed = 3 + end + 4;
            body_start = consumed.min(trimmed.len());
        }
    }

    let body = trimmed[body_start..].trim_start_matches('-').trim().to_string();
    if description.is_empty() {
        // 没有 description 就取正文第一段，避免列表里全是空白
        description = body
            .lines()
            .find(|l| !l.trim().is_empty())
            .map(|l| l.trim().trim_start_matches('#').trim().to_string())
            .unwrap_or_default();
        if description.chars().count() > 80 {
            description = description.chars().take(80).collect::<String>() + "…";
        }
    }
    ParsedSkill {
        name,
        description,
        body,
    }
}

/// 解析 frontmatter 头部。
///
/// 支持两种写法：单行 `description: 文本`，以及 YAML 块标量
/// `description: |` + 缩进的多行内容。后者在 Claude 系技能里非常常见，
/// 只按行取冒号右边会把 `|` 当成描述，之前就踩过。
fn read_header(header: &str, name: &mut String, description: &mut String) {
    let lines: Vec<&str> = header.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        let trimmed = line.trim_start();
        // 缩进行属于上一个 key 的块内容，单独跳过
        let Some((key, raw_value)) = trimmed.split_once(':') else {
            i += 1;
            continue;
        };
        if line.starts_with(char::is_whitespace) {
            i += 1;
            continue;
        }
        let key = key.trim().to_ascii_lowercase();
        let value = raw_value.trim();
        let is_block = matches!(value, "|" | ">" | "|-" | ">-" | "|+" | ">+");

        if is_block {
            let folded = value.starts_with('>');
            let mut collected: Vec<String> = Vec::new();
            i += 1;
            while i < lines.len() {
                let next = lines[i];
                if next.trim().is_empty() {
                    collected.push(String::new());
                    i += 1;
                    continue;
                }
                if !next.starts_with(char::is_whitespace) {
                    break;
                }
                collected.push(next.trim().to_string());
                i += 1;
            }
            let joined = if folded {
                collected.join(" ").trim().to_string()
            } else {
                collected.join("\n").trim().to_string()
            };
            match key.as_str() {
                "name" if !joined.is_empty() => *name = joined,
                "description" if !joined.is_empty() => *description = joined,
                _ => {}
            }
            continue;
        }

        let cleaned = value.trim_matches('"').trim_matches('\'');
        match key.as_str() {
            "name" if !cleaned.is_empty() => *name = cleaned.to_string(),
            "description" if !cleaned.is_empty() => *description = cleaned.to_string(),
            _ => {}
        }
        i += 1;
    }
}

/// 从磁盘导入一个技能（复制到应用目录）。
pub fn import(store: &AgentStore, path: &Path) -> Result<Skill, AgentError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| AgentError::Skill(format!("读取 {} 失败：{e}", path.display())))?;
    if text.len() as u64 > MAX_FILE_BYTES {
        return Err(AgentError::Skill("技能文件超过 200 KB，已拒绝导入。".into()));
    }
    let fallback = path
        .parent()
        .and_then(|p| p.file_name())
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "skill".to_string());
    let parsed = parse(&text, &fallback);

    let slug = unique_slug(store, &parsed.name, path);
    let dir = store.skills_dir().join(&slug);
    std::fs::create_dir_all(&dir).map_err(|e| AgentError::Skill(format!("创建目录失败：{e}")))?;

    // 原样保存，保留 frontmatter，便于以后导出/再导入
    std::fs::write(dir.join("SKILL.md"), &text)
        .map_err(|e| AgentError::Skill(format!("写入技能失败：{e}")))?;

    let skill = Skill {
        slug,
        name: parsed.name,
        description: parsed.description,
        source: path.to_string_lossy().to_string(),
        imported_at: chrono::Local::now().format("%Y-%m-%d %H:%M").to_string(),
        enabled: true,
    };
    write_meta(store, &skill)?;
    Ok(skill)
}

fn unique_slug(store: &AgentStore, name: &str, path: &Path) -> String {
    let base: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string();
    let mut base = if base.len() < 2 {
        // 纯中文名转出来的 slug 是空的，用路径哈希兜底
        format!("skill-{:x}", hash(path.to_string_lossy().as_ref()))
    } else {
        base.chars().take(40).collect::<String>()
    };

    let mut candidate = base.clone();
    let mut n = 2;
    while store.skills_dir().join(&candidate).exists() {
        candidate = format!("{base}-{n}");
        n += 1;
        if n > 99 {
            break;
        }
    }
    if candidate != base {
        base = candidate;
    }
    base
}

fn hash(s: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    s.hash(&mut h);
    h.finish() & 0xffffff
}

fn write_meta(store: &AgentStore, skill: &Skill) -> Result<(), AgentError> {
    let dir = store.skills_dir().join(&skill.slug);
    std::fs::create_dir_all(&dir).map_err(|e| AgentError::Skill(format!("创建目录失败：{e}")))?;
    let text = serde_json::to_string_pretty(skill)
        .map_err(|e| AgentError::Skill(format!("序列化技能元信息失败：{e}")))?;
    std::fs::write(dir.join("meta.json"), text)
        .map_err(|e| AgentError::Skill(format!("写入技能元信息失败：{e}")))
}

/// 列出已导入的技能。
pub fn list(store: &AgentStore) -> Vec<Skill> {
    let dir = store.skills_dir();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut out: Vec<Skill> = entries
        .flatten()
        .filter(|e| e.path().is_dir())
        .filter_map(|e| {
            let meta = std::fs::read_to_string(e.path().join("meta.json")).ok()?;
            serde_json::from_str::<Skill>(&meta).ok()
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

pub fn set_enabled(store: &AgentStore, slug: &str, enabled: bool) -> Result<Skill, AgentError> {
    let mut skill = list(store)
        .into_iter()
        .find(|s| s.slug == slug)
        .ok_or_else(|| AgentError::Skill(format!("找不到技能 {slug}")))?;
    skill.enabled = enabled;
    write_meta(store, &skill)?;
    Ok(skill)
}

pub fn delete(store: &AgentStore, slug: &str) -> Result<(), AgentError> {
    let dir = store.skills_dir().join(slug);
    if !dir.is_dir() {
        return Err(AgentError::Skill(format!("找不到技能 {slug}")));
    }
    std::fs::remove_dir_all(&dir).map_err(|e| AgentError::Skill(format!("删除失败：{e}")))
}

/// 读取已启用技能的内容，用于注入系统提示词。
///
/// 总预算按 [`MAX_SKILL_CHARS`] 均分，超出部分截断并注明 ——
/// 宁可少给一点，也不要把模型上下文挤爆导致回答质量整体下降。
pub fn enabled_contents(store: &AgentStore, budget: usize) -> Vec<(String, String)> {
    let enabled: Vec<Skill> = list(store).into_iter().filter(|s| s.enabled).collect();
    if enabled.is_empty() {
        return Vec::new();
    }
    let per = (budget / enabled.len()).max(400);
    let mut out = Vec::new();
    for skill in enabled {
        let path = store.skills_dir().join(&skill.slug).join("SKILL.md");
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        let body = parse(&text, &skill.name).body;
        let body = if body.chars().count() > per {
            let cut: String = body.chars().take(per).collect();
            format!("{cut}\n…（已截断，完整内容见技能原文）")
        } else {
            body
        };
        out.push((skill.name, body));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(path: &Path, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    #[test]
    fn parses_frontmatter() {
        let text = "---\nname: 网络排障\ndescription: 分层定位断点\n---\n\n# 步骤\n1. 先 ping";
        let p = parse(text, "fallback");
        assert_eq!(p.name, "网络排障");
        assert_eq!(p.description, "分层定位断点");
        assert!(p.body.starts_with("# 步骤"));
    }

    #[test]
    fn parses_yaml_block_scalar_description() {
        let text = "---\nname: readme-craft\ndescription: |\n  用规范写 README。\n  第二行。\n---\n\n正文";
        let p = parse(text, "x");
        assert_eq!(p.name, "readme-craft");
        assert!(p.description.contains("用规范写 README"));
        assert!(p.description.contains("第二行"));
        assert!(!p.description.starts_with('|'));
        assert!(p.body.starts_with("正文"));
    }

    #[test]
    fn parses_folded_block_scalar() {
        let text = "---\nname: a\ndescription: >-\n  第一段\n  第二段\n---\nbody";
        let p = parse(text, "x");
        assert_eq!(p.description, "第一段 第二段");
    }

    #[test]
    fn block_scalar_stops_at_next_key() {
        let text = "---\nname: n\ndescription: |\n  描述\nallowed-tools: Bash\n---\nbody";
        let p = parse(text, "x");
        assert_eq!(p.description, "描述");
        assert_eq!(p.name, "n");
    }

    #[test]
    fn parses_without_frontmatter() {
        let text = "# 标题\n正文内容";
        let p = parse(text, "目录名");
        assert_eq!(p.name, "目录名");
        assert_eq!(p.description, "标题");
        assert!(p.body.contains("正文内容"));
    }

    #[test]
    fn handles_windows_line_endings_and_quotes() {
        let text = "---\r\nname: \"Quoted Name\"\r\ndescription: 'd'\r\n---\r\nbody";
        let p = parse(text, "x");
        assert_eq!(p.name, "Quoted Name");
        assert_eq!(p.description, "d");
        assert_eq!(p.body, "body");
    }

    #[test]
    fn scans_skill_files_and_root_rules() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("skills");
        write(&root.join("a").join("SKILL.md"), "---\nname: A\n---\nbody");
        write(&root.join("b").join("SKILL.md"), "---\nname: B\n---\nbody");
        write(&root.join("rule.mdc"), "# 规则\n内容");
        // 深层目录里的普通 md 不算技能
        write(&root.join("c").join("deep").join("notes.md"), "x");

        let mut found = scan(&root, "Test", &[]);
        found.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(found.len(), 3, "实际：{:?}", found.iter().map(|c| &c.name).collect::<Vec<_>>());
        assert!(found.iter().any(|c| c.name == "rule"));
    }

    #[test]
    fn scan_marks_imported_sources() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("skills");
        let file = root.join("a").join("SKILL.md");
        write(&file, "---\nname: A\n---\nbody");
        let src = file.to_string_lossy().to_string();
        let found = scan(&root, "Test", &[src]);
        assert!(found[0].imported);
    }

    #[test]
    fn imports_lists_toggles_and_deletes() {
        let dir = tempfile::tempdir().unwrap();
        let store = AgentStore::new(dir.path().join("agent"));
        let src = dir.path().join("src").join("SKILL.md");
        write(&src, "---\nname: 排障手册\ndescription: 分层排查\n---\n## 内容");

        let skill = import(&store, &src).unwrap();
        assert!(skill.enabled);
        assert!(store
            .skills_dir()
            .join(&skill.slug)
            .join("SKILL.md")
            .exists());

        let listed = list(&store);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "排障手册");

        let off = set_enabled(&store, &skill.slug, false).unwrap();
        assert!(!off.enabled);
        assert!(enabled_contents(&store, 6000).is_empty());

        set_enabled(&store, &skill.slug, true).unwrap();
        let contents = enabled_contents(&store, 6000);
        assert_eq!(contents.len(), 1);
        assert_eq!(contents[0].0, "排障手册");
        assert!(contents[0].1.contains("## 内容"));

        delete(&store, &skill.slug).unwrap();
        assert!(list(&store).is_empty());
    }

    #[test]
    fn duplicate_names_get_distinct_slugs() {
        let dir = tempfile::tempdir().unwrap();
        let store = AgentStore::new(dir.path().join("agent"));
        let a = dir.path().join("a").join("SKILL.md");
        let b = dir.path().join("b").join("SKILL.md");
        write(&a, "---\nname: Same\n---\nx");
        write(&b, "---\nname: Same\n---\ny");
        let s1 = import(&store, &a).unwrap();
        let s2 = import(&store, &b).unwrap();
        assert_ne!(s1.slug, s2.slug);
        assert_eq!(list(&store).len(), 2);
    }

    #[test]
    fn long_skill_is_truncated_to_budget() {
        let dir = tempfile::tempdir().unwrap();
        let store = AgentStore::new(dir.path().join("agent"));
        let src = dir.path().join("big").join("SKILL.md");
        let body = "字".repeat(3000);
        write(&src, &format!("---\nname: Big\n---\n{body}"));
        import(&store, &src).unwrap();

        let contents = enabled_contents(&store, 800);
        assert!(contents[0].1.contains("已截断"));
        assert!(contents[0].1.chars().count() < 1200);
    }

    #[test]
    fn missing_source_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let store = AgentStore::new(dir.path().join("agent"));
        assert!(import(&store, &dir.path().join("nope.md")).is_err());
    }
}
