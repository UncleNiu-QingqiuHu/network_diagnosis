"""扫描用户 skills 目录，合并为系统提示约束。"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from network_diagnosis.paths import skills_root
from network_diagnosis.runtime_log import get_logger

_log = get_logger(__name__)

_MAX_SKILL_BODY = 8000
_MAX_TOTAL_SKILLS_CHARS = 28000
_FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)


@dataclass(frozen=True)
class SkillEntry:
    skill_id: str
    name: str
    description: str
    path: Path
    body: str


def _parse_simple_yaml_block(block: str) -> dict[str, str]:
    meta: dict[str, str] = {}
    for line in block.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        meta[key.strip().lower()] = val.strip().strip('"').strip("'")
    return meta


def _split_frontmatter(text: str) -> tuple[dict[str, str], str]:
    m = _FRONTMATTER_RE.match(text)
    if not m:
        return {}, text.strip()
    meta = _parse_simple_yaml_block(m.group(1))
    body = text[m.end() :].strip()
    return meta, body


def _skill_id_from_path(path: Path, root: Path) -> str:
    try:
        rel = path.relative_to(root)
    except ValueError:
        return path.stem
    parts = list(rel.parts)
    if len(parts) >= 2 and parts[-1].upper() == "SKILL.MD":
        return parts[-2]
    return path.stem


def _load_skill_file(path: Path, root: Path) -> SkillEntry | None:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as e:
        _log.warning("读取 skill 失败 path=%s: %s", path, e)
        return None
    meta, body = _split_frontmatter(raw)
    skill_id = _skill_id_from_path(path, root)
    name = meta.get("name") or skill_id
    desc = meta.get("description") or ""
    if not body.strip():
        _log.debug("跳过空 skill path=%s", path)
        return None
    if len(body) > _MAX_SKILL_BODY:
        body = body[:_MAX_SKILL_BODY] + "\n\n…（skill 正文已截断）"
    return SkillEntry(
        skill_id=skill_id,
        name=name,
        description=desc,
        path=path,
        body=body,
    )


def scan_skills() -> list[SkillEntry]:
    """扫描 skills 目录：``<skill>/SKILL.md`` 与根目录 ``*.md``（不含 README）。"""
    root = skills_root()
    if not root.is_dir():
        return []

    seen: set[Path] = set()
    entries: list[SkillEntry] = []

    for path in sorted(root.glob("**/SKILL.md")):
        if not path.is_file() or path in seen:
            continue
        seen.add(path)
        ent = _load_skill_file(path, root)
        if ent:
            entries.append(ent)

    for path in sorted(root.glob("*.md")):
        if path.name.lower() in ("readme.md", "readme.en.md"):
            continue
        if path in seen:
            continue
        seen.add(path)
        ent = _load_skill_file(path, root)
        if ent:
            entries.append(ent)

    entries.sort(key=lambda e: e.skill_id.lower())
    _log.info("已扫描 skills 目录 count=%d root=%s", len(entries), root)
    return entries


def build_skills_system_section(skills: list[SkillEntry] | None = None) -> str:
    """生成注入 system 的 skills 索引与正文约束。"""
    items = skills if skills is not None else scan_skills()
    if not items:
        return ""

    lines: list[str] = [
        "",
        "## 用户 Skills（必须遵守）",
        "",
        "以下内容由用户放在 skills 目录中；当用户请求与某 skill 的 description 相符时，"
        "你必须严格遵循对应 skill 正文中的流程、格式与限制，优先级高于一般习惯。",
        "",
        "### Skills 索引",
    ]
    for s in items:
        desc = s.description or "（无描述，请阅读正文）"
        lines.append(f"- **{s.name}** (`{s.skill_id}`)：{desc}")

    lines.append("")
    lines.append("### Skills 正文")
    total = 0
    for s in items:
        block = f"\n#### Skill: {s.name} (`{s.skill_id}`)\n\n{s.body}\n"
        if total + len(block) > _MAX_TOTAL_SKILLS_CHARS:
            lines.append("\n…（更多 skills 正文已省略，请精简单个 SKILL 或拆分多个 skill 目录）\n")
            break
        lines.append(block)
        total += len(block)

    return "\n".join(lines)
