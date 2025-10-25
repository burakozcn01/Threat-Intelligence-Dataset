from datetime import datetime
from typing import Any, Dict, List, Optional
import hashlib
import json


class DataNormalizer:
    def __init__(self):
        self.entity_cache = {}

    def normalize_malware(self, data: Dict[str, Any], source: str) -> Dict[str, Any]:
        normalized = {
            "entity_type": "malware",
            "source": source,
            "name": data.get("name", "").strip(),
            "aliases": self._extract_aliases(data),
            "description": data.get("description", "").strip(),
            "malware_types": data.get("malware_types", []),
            "is_family": data.get("is_family", True),
            "capabilities": data.get("capabilities", []),
            "first_seen": self._parse_date(data.get("first_seen")),
            "last_seen": self._parse_date(data.get("last_seen")),
            "kill_chain_phases": self._normalize_kill_chain(data.get("kill_chain_phases", [])),
            "mitre_techniques": self._extract_mitre_techniques(data),
            "external_references": data.get("external_references", []),
            "confidence": self._calculate_confidence(data, source),
        }

        normalized["id"] = self._generate_id(normalized)
        return normalized

    def normalize_threat_actor(self, data: Dict[str, Any], source: str) -> Dict[str, Any]:
        normalized = {
            "entity_type": "threat-actor",
            "source": source,
            "name": data.get("name", "").strip(),
            "aliases": self._extract_aliases(data),
            "description": data.get("description", "").strip(),
            "actor_types": data.get("threat_actor_types", []),
            "sophistication": data.get("sophistication", ""),
            "resource_level": data.get("resource_level", ""),
            "primary_motivation": data.get("primary_motivation", ""),
            "secondary_motivations": data.get("secondary_motivations", []),
            "goals": data.get("goals", []),
            "first_seen": self._parse_date(data.get("first_seen")),
            "last_seen": self._parse_date(data.get("last_seen")),
            "external_references": data.get("external_references", []),
            "confidence": self._calculate_confidence(data, source),
        }

        normalized["id"] = self._generate_id(normalized)
        return normalized

    def normalize_attack_pattern(self, data: Dict[str, Any], source: str) -> Dict[str, Any]:
        normalized = {
            "entity_type": "attack-pattern",
            "source": source,
            "name": data.get("name", "").strip(),
            "description": data.get("description", "").strip(),
            "mitre_id": data.get("mitre_id", ""),
            "kill_chain_phases": self._normalize_kill_chain(data.get("kill_chain_phases", [])),
            "platforms": data.get("x_mitre_platforms", []),
            "data_sources": data.get("x_mitre_data_sources", []),
            "detection": data.get("x_mitre_detection", ""),
            "is_subtechnique": data.get("x_mitre_is_subtechnique", False),
            "external_references": data.get("external_references", []),
            "confidence": self._calculate_confidence(data, source),
        }

        normalized["id"] = self._generate_id(normalized)
        return normalized

    def normalize_indicator(self, data: Dict[str, Any], source: str) -> Dict[str, Any]:
        ioc_data = self._extract_ioc_from_pattern(data.get("pattern", ""))

        normalized = {
            "entity_type": "indicator",
            "source": source,
            "name": data.get("name", "").strip(),
            "description": data.get("description", "").strip(),
            "pattern": data.get("pattern", ""),
            "pattern_type": data.get("pattern_type", "stix"),
            "ioc_type": ioc_data.get("type", ""),
            "ioc_value": ioc_data.get("value", ""),
            "valid_from": self._parse_date(data.get("valid_from")),
            "valid_until": self._parse_date(data.get("valid_until")),
            "labels": data.get("labels", []),
            "kill_chain_phases": self._normalize_kill_chain(data.get("kill_chain_phases", [])),
            "confidence": self._calculate_confidence(data, source),
        }

        normalized["id"] = self._generate_id(normalized)
        return normalized

    def normalize_campaign(self, data: Dict[str, Any], source: str) -> Dict[str, Any]:
        normalized = {
            "entity_type": "campaign",
            "source": source,
            "name": data.get("name", "").strip(),
            "aliases": self._extract_aliases(data),
            "description": data.get("description", "").strip(),
            "objective": data.get("objective", "").strip(),
            "first_seen": self._parse_date(data.get("first_seen")),
            "last_seen": self._parse_date(data.get("last_seen")),
            "external_references": data.get("external_references", []),
            "confidence": self._calculate_confidence(data, source),
        }

        normalized["id"] = self._generate_id(normalized)
        return normalized

    def normalize_vulnerability(self, data: Dict[str, Any], source: str) -> Dict[str, Any]:
        normalized = {
            "entity_type": "vulnerability",
            "source": source,
            "name": data.get("name", "").strip(),
            "description": data.get("description", "").strip(),
            "cve_id": data.get("cve_id", ""),
            "external_references": data.get("external_references", []),
            "confidence": self._calculate_confidence(data, source),
        }

        normalized["id"] = self._generate_id(normalized)
        return normalized

    def normalize_report(self, data: Dict[str, Any], source: str) -> Dict[str, Any]:
        normalized = {
            "entity_type": "report",
            "source": source,
            "title": data.get("title", "").strip(),
            "url": data.get("url", "").strip(),
            "published_date": self._parse_date(data.get("published_date")),
            "author": data.get("author", "").strip(),
            "description": data.get("description", "").strip(),
            "tags": [tag.lower().strip() for tag in data.get("tags", []) if tag],
            "report_type": data.get("report_type", "security_research"),
            "source_name": data.get("source_name", ""),
            "confidence": self._calculate_report_confidence(data, source),
        }

        normalized["id"] = self._generate_report_id(normalized)
        return normalized

    def normalize_blog(self, data: Dict[str, Any], source: str) -> Dict[str, Any]:
        normalized = {
            "entity_type": "blog",
            "source": source,
            "title": data.get("title", "").strip(),
            "url": data.get("url", "").strip(),
            "published_date": self._parse_date(data.get("published_date")),
            "author": data.get("author", "").strip(),
            "description": data.get("description", "").strip(),
            "tags": [tag.lower().strip() for tag in data.get("tags", []) if tag],
            "content_type": data.get("content_type", "blog_article"),
            "source_name": data.get("source_name", ""),
            "confidence": self._calculate_report_confidence(data, source),
        }

        normalized["id"] = self._generate_report_id(normalized)
        return normalized

    def _extract_aliases(self, data: Dict[str, Any]) -> List[str]:
        aliases = []

        if "aliases" in data:
            aliases.extend(data["aliases"])

        if "x_mitre_aliases" in data:
            aliases.extend(data["x_mitre_aliases"])

        return list(set(a.strip() for a in aliases if a))

    def _normalize_kill_chain(self, phases: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        normalized = []

        for phase in phases:
            normalized.append(
                {
                    "kill_chain_name": phase.get("kill_chain_name", ""),
                    "phase_name": phase.get("phase_name", ""),
                }
            )

        return normalized

    def _extract_mitre_techniques(self, data: Dict[str, Any]) -> List[str]:
        techniques = []

        for ref in data.get("external_references", []):
            if ref.get("source_name") == "mitre-attack" and "external_id" in ref:
                techniques.append(ref["external_id"])

        return techniques

    def _extract_ioc_from_pattern(self, pattern: str) -> Dict[str, str]:
        if not pattern:
            return {"type": "", "value": ""}

        pattern_lower = pattern.lower()

        if "file:hashes" in pattern_lower:
            for hash_type in ["md5", "sha-1", "sha-256", "sha-512"]:
                if f"'{hash_type}'" in pattern_lower or f'"{hash_type}"' in pattern_lower:
                    value = self._extract_value_from_pattern(pattern)
                    return {"type": hash_type, "value": value}

        elif "ipv4-addr:value" in pattern_lower:
            return {"type": "ipv4", "value": self._extract_value_from_pattern(pattern)}

        elif "ipv6-addr:value" in pattern_lower:
            return {"type": "ipv6", "value": self._extract_value_from_pattern(pattern)}

        elif "domain-name:value" in pattern_lower:
            return {"type": "domain", "value": self._extract_value_from_pattern(pattern)}

        elif "url:value" in pattern_lower:
            return {"type": "url", "value": self._extract_value_from_pattern(pattern)}

        return {"type": "unknown", "value": pattern}

    def _extract_value_from_pattern(self, pattern: str) -> str:
        try:
            start = pattern.find("=") + 1
            end = pattern.find("]", start)
            if end == -1:
                end = len(pattern)
            value = pattern[start:end].strip().strip("'\"")
            return value
        except:
            return ""

    def _parse_date(self, date_str: Optional[str]) -> Optional[str]:
        if not date_str:
            return None

        try:
            if isinstance(date_str, datetime):
                return date_str.isoformat()

            dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
            return dt.isoformat()
        except:
            return date_str

    def _calculate_confidence(self, data: Dict[str, Any], source: str) -> str:
        score = 0.5

        if source == "mitre-attack":
            score = 0.95

        elif source == "alienvault-otx":
            score = 0.7

        elif source == "abuse-ch":
            score = 0.8

        if data.get("description") and len(data.get("description", "")) > 100:
            score += 0.05

        if data.get("external_references") and len(data.get("external_references", [])) > 2:
            score += 0.05

        score = min(1.0, score)

        if score >= 0.8:
            return "high"
        elif score >= 0.5:
            return "medium"
        elif score >= 0.3:
            return "low"
        else:
            return "unknown"

    def _generate_id(self, data: Dict[str, Any]) -> str:
        content = json.dumps(
            {
                "entity_type": data.get("entity_type"),
                "name": data.get("name"),
                "source": data.get("source"),
            },
            sort_keys=True,
        )

        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def _calculate_report_confidence(self, data: Dict[str, Any], source: str) -> str:
        score = 0.6

        if source in ["kaspersky", "checkpoint", "crowdstrike", "microsoft", "paloalto_unit42", "talos"]:
            score = 0.9
        elif source in ["krebs", "bleepingcomputer", "darkreading"]:
            score = 0.8
        elif source in ["securityaffairs", "threatpost", "schneier"]:
            score = 0.75

        if data.get("description") and len(data.get("description", "")) > 200:
            score += 0.05

        if data.get("tags") and len(data.get("tags", [])) > 3:
            score += 0.05

        score = min(1.0, score)

        if score >= 0.8:
            return "high"
        elif score >= 0.6:
            return "medium"
        elif score >= 0.4:
            return "low"
        else:
            return "unknown"

    def _generate_report_id(self, data: Dict[str, Any]) -> str:
        content = json.dumps(
            {
                "entity_type": data.get("entity_type"),
                "title": data.get("title"),
                "url": data.get("url"),
                "source": data.get("source"),
            },
            sort_keys=True,
        )

        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def deduplicate(self, entities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen = set()
        unique = []

        for entity in entities:
            entity_id = entity.get("id")

            if entity_id not in seen:
                seen.add(entity_id)
                unique.append(entity)

        return unique
