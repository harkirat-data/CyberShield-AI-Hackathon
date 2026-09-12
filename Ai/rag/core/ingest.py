import json
import re
import yaml
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass, field, asdict

try:
    from .config import KB_ROOT, CHUNK_SIZE, CHUNK_OVERLAP
except ImportError:  # pragma: no cover - fallback for direct script execution
    from config import KB_ROOT, CHUNK_SIZE, CHUNK_OVERLAP


@dataclass
class Chunk:
    id: str
    text: str
    source: str         
    doc_id: str           
    title: str
    metadata: Dict = field(default_factory=dict)

    def to_chroma(self):
        d = asdict(self)
        meta = {k: v for k, v in d.items() if k not in ("text", "id")}
        for k, v in list(meta.items()):
            if isinstance(v, (list, dict)):
                meta[k] = json.dumps(v)
            elif v is None:
                meta[k] = ""
        return d["id"], d["text"], meta


def estimate_tokens(text: str) -> int:
    """Rough token estimate: 1 token ~ 4 chars"""
    return max(1, len(text) // 4)


def chunk_text(text: str, chunk_size: int = CHUNK_SIZE,
               overlap: int = CHUNK_OVERLAP) -> List[str]:
    """Sliding-window chunking by approximate token count."""
    if estimate_tokens(text) <= chunk_size:
        return [text.strip()] if text.strip() else []

    chunks = []
    sentences = re.split(r'(?<=[.!?\n])\s+', text)
    current = []
    current_tokens = 0

    for sent in sentences:
        sent_tokens = estimate_tokens(sent)
        if current_tokens + sent_tokens > chunk_size and current:
            chunks.append(" ".join(current))
            overlap_sents = []
            overlap_tokens = 0
            for s in reversed(current):
                t = estimate_tokens(s)
                if overlap_tokens + t > overlap:
                    break
                overlap_sents.insert(0, s)
                overlap_tokens += t
            current = overlap_sents
            current_tokens = overlap_tokens
        current.append(sent)
        current_tokens += sent_tokens

    if current:
        chunks.append(" ".join(current))

    return [c.strip() for c in chunks if c.strip()]


def load_mitre() -> List[Chunk]:
    """Load MITRE ATT&CK from local JSON bundle."""
    path = KB_ROOT / "mitre" / "enterprise-attack.json"
    if not path.exists():
        print(f"[ingest] MITRE file not found: {path}")
        return []

    print(f"[ingest] loading MITRE from {path}")
    with open(path) as f:
        bundle = json.load(f)

    chunks = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        ext_refs = obj.get("external_references", [])
        tech_id = ""
        url = ""
        for ref in ext_refs:
            if ref.get("source_name") == "mitre-attack":
                tech_id = ref.get("external_id", "")
                url = ref.get("url", "")
                break
        if not tech_id:
            continue

        parts = [
            f"MITRE ATT&CK Technique {tech_id}: {obj.get('name', '')}",
            "",
            f"Tactics: {', '.join(p.get('phase_name', '') for p in obj.get('kill_chain_phases', []))}",
            f"Platforms: {', '.join(obj.get('x_mitre_platforms', []))}",
            f"Data Sources: {', '.join(obj.get('x_mitre_data_sources', []))}",
            "",
            "Description:",
            obj.get("description", ""),
        ]
        if obj.get("x_mitre_detection"):
            parts.extend(["", "Detection:", obj["x_mitre_detection"]])
        if url:
            parts.append(f"\nReference: {url}")
        full_text = "\n".join(parts)

        # Chunk
        sub_chunks = chunk_text(full_text)
        for i, text in enumerate(sub_chunks):
            chunks.append(Chunk(
                id=f"mitre_{tech_id}_{i}",
                text=text,
                source="mitre_attack",
                doc_id=tech_id,
                title=f"{tech_id}: {obj.get('name', '')}",
                metadata={
                    "technique_id": tech_id,
                    "name": obj.get("name", ""),
                    "tactic": ", ".join(p.get("phase_name", "") for p in obj.get("kill_chain_phases", [])),
                    "platforms": ", ".join(obj.get("x_mitre_platforms", []) or []),
                    "url": url,
                }
            ))
    print(f"[ingest] MITRE: {len(chunks)} chunks")
    return chunks


def load_sigma_dir() -> List[Chunk]:
    """Recursively load Sigma rules from YAML files."""
    sigma_root = KB_ROOT / "sigma"
    if not sigma_root.exists():
        print(f"[ingest] Sigma dir not found: {sigma_root}")
        return []

    chunks = []
    count = 0
    sigma_files = list(sigma_root.rglob("*.yml")) + list(sigma_root.rglob("*.yaml"))
    for yaml_file in sigma_files:
        try:
            with open(yaml_file) as f:
                rule = yaml.safe_load(f)
            if not rule:
                continue

            doc_id = f"sigma_{yaml_file.stem}"
            title = rule.get("title", yaml_file.stem)
            desc = rule.get("description", "")
            level = rule.get("level", "informational")
            logsource = rule.get("logsource", {})
            detection = rule.get("detection", {})
            tags = rule.get("tags", []) or []

            # Build text
            det_text = json.dumps(detection, indent=2) if detection else ""
            parts = [
                f"Sigma Rule: {title}",
                f"Level: {level}",
                f"Logsource: {json.dumps(logsource)}",
                f"Tags: {', '.join(tags)}",
                "",
                "Description:",
                desc,
                "",
                "Detection Logic:",
                det_text[:2000],
            ]
            full_text = "\n".join(parts)

            for i, text in enumerate(chunk_text(full_text)):
                chunks.append(Chunk(
                    id=f"{doc_id}_{i}",
                    text=text,
                    source="sigma_rules",
                    doc_id=doc_id,
                    title=title,
                    metadata={
                        "rule_id": doc_id,
                        "level": level,
                        "product": logsource.get("product", ""),
                        "category": logsource.get("category", ""),
                        "tags": ", ".join(tags) if isinstance(tags, list) else str(tags),
                    }
                ))
            count += 1
        except Exception as e:
            print(f"[ingest] failed to parse {yaml_file}: {e}")

    print(f"[ingest] Sigma: {count} rules, {len(chunks)} chunks")
    return chunks


def load_wazuh_dir() -> List[Chunk]:
    """Load Wazuh rules from XML files."""
    wazuh_root = KB_ROOT / "wazuh"
    if not wazuh_root.exists():
        print(f"[ingest] Wazuh dir not found: {wazuh_root}")
        return []

    chunks = []
    count = 0
    for xml_file in wazuh_root.rglob("*.xml"):
        try:
            content = xml_file.read_text(encoding="utf-8", errors="ignore")
            # Naive parse - extract rule blocks
            rule_blocks = re.findall(
                r'<rule[^>]*?id="(\d+)"[^>]*?level="(\d+)"[^>]*?>(.*?)</rule>',
                content, re.DOTALL
            )
            for rule_id, level, body in rule_blocks:
                desc_match = re.search(r'<description>(.*?)</description>', body, re.DOTALL)
                desc = desc_match.group(1).strip() if desc_match else ""
                mitre_match = re.findall(r'<mitre>(.*?)</mitre>', body)
                mitre_ids = [m.strip() for m in mitre_match]

                text = f"Wazuh Rule {rule_id} (level {level}):\n{desc}"
                if mitre_ids:
                    text += f"\nMITRE: {', '.join(mitre_ids)}"

                chunks.append(Chunk(
                    id=f"wazuh_{rule_id}",
                    text=text,
                    source="wazuh_rules",
                    doc_id=f"wazuh_{rule_id}",
                    title=f"Wazuh rule {rule_id}",
                    metadata={
                        "rule_id": rule_id,
                        "level": int(level),
                        "mitre": ", ".join(mitre_ids),
                    }
                ))
            count += len(rule_blocks)
        except Exception as e:
            print(f"[ingest] failed to parse {xml_file}: {e}")

    print(f"[ingest] Wazuh: {count} rules, {len(chunks)} chunks")
    return chunks


def load_markdown_dir(subdir: str, source: str) -> List[Chunk]:
    """Load markdown/text files from a knowledge_base subdir."""
    root = KB_ROOT / subdir
    if not root.exists():
        return []

    chunks = []
    for f in list(root.rglob("*.md")) + list(root.rglob("*.txt")):
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
            title = f.stem
            for i, chunk in enumerate(chunk_text(text)):
                chunks.append(Chunk(
                    id=f"{source}_{f.stem}_{i}",
                    text=chunk,
                    source=source,
                    doc_id=f.stem,
                    title=title,
                    metadata={"file": f.name},
                ))
        except Exception as e:
            print(f"[ingest] failed {f}: {e}")

    print(f"[ingest] {source}: {len(chunks)} chunks from {root}")
    return chunks


def load_all() -> List[Chunk]:
    """Load all knowledge base sources."""
    print(f"[ingest] KB root: {KB_ROOT}")
    all_chunks = []
    all_chunks.extend(load_mitre())
    all_chunks.extend(load_sigma_dir())
    all_chunks.extend(load_wazuh_dir())
    all_chunks.extend(load_markdown_dir("linux", "linux_logs"))
    all_chunks.extend(load_markdown_dir("windows", "windows_logs"))
    all_chunks.extend(load_markdown_dir("remediation", "remediation"))
    print(f"[ingest] TOTAL: {len(all_chunks)} chunks")
    return all_chunks


if __name__ == "__main__":
    chunks = load_all()
    print(f"\nFirst chunk:\n{chunks[0].text[:300]}")
