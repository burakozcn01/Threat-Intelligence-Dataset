from datetime import datetime
from typing import Any, Dict, List, Optional
from stix2 import parse
from stix2.base import STIXJSONEncoder
import json


class STIXParser:
    def __init__(self):
        self.supported_types = [
            "indicator",
            "malware",
            "threat-actor",
            "attack-pattern",
            "campaign",
            "intrusion-set",
            "tool",
            "vulnerability",
            "relationship",
        ]

    def parse_bundle(self, stix_data: Dict[str, Any]) -> Dict[str, List[Any]]:
        results = {obj_type: [] for obj_type in self.supported_types}

        if stix_data.get("type") == "bundle":
            for obj in stix_data.get("objects", []):
                obj_type = obj.get("type")
                if obj_type in self.supported_types:
                    parsed = self._parse_object(obj)
                    if parsed:
                        results[obj_type].append(parsed)

        return results

    def _parse_object(self, obj: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        obj_type = obj.get("type")

        if obj_type == "indicator":
            return self._parse_indicator(obj)
        elif obj_type == "malware":
            return self._parse_malware(obj)
        elif obj_type == "threat-actor":
            return self._parse_threat_actor(obj)
        elif obj_type == "attack-pattern":
            return self._parse_attack_pattern(obj)
        elif obj_type == "campaign":
            return self._parse_campaign(obj)
        elif obj_type == "intrusion-set":
            return self._parse_intrusion_set(obj)
        elif obj_type == "tool":
            return self._parse_tool(obj)
        elif obj_type == "vulnerability":
            return self._parse_vulnerability(obj)
        elif obj_type == "relationship":
            return self._parse_relationship(obj)

        return None

    def _parse_indicator(self, obj: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": obj.get("id"),
            "type": "indicator",
            "name": obj.get("name", ""),
            "pattern": obj.get("pattern", ""),
            "pattern_type": obj.get("pattern_type", "stix"),
            "valid_from": obj.get("valid_from"),
            "valid_until": obj.get("valid_until"),
            "labels": obj.get("labels", []),
            "description": obj.get("description", ""),
            "external_references": obj.get("external_references", []),
            "kill_chain_phases": obj.get("kill_chain_phases", []),
        }

    def _parse_malware(self, obj: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": obj.get("id"),
            "type": "malware",
            "name": obj.get("name", ""),
            "is_family": obj.get("is_family", True),
            "aliases": obj.get("aliases", []),
            "description": obj.get("description", ""),
            "malware_types": obj.get("malware_types", []),
            "capabilities": obj.get("capabilities", []),
            "first_seen": obj.get("first_seen"),
            "last_seen": obj.get("last_seen"),
            "external_references": obj.get("external_references", []),
            "kill_chain_phases": obj.get("kill_chain_phases", []),
        }

    def _parse_threat_actor(self, obj: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": obj.get("id"),
            "type": "threat-actor",
            "name": obj.get("name", ""),
            "aliases": obj.get("aliases", []),
            "description": obj.get("description", ""),
            "threat_actor_types": obj.get("threat_actor_types", []),
            "sophistication": obj.get("sophistication", ""),
            "resource_level": obj.get("resource_level", ""),
            "primary_motivation": obj.get("primary_motivation", ""),
            "secondary_motivations": obj.get("secondary_motivations", []),
            "goals": obj.get("goals", []),
            "first_seen": obj.get("first_seen"),
            "last_seen": obj.get("last_seen"),
            "external_references": obj.get("external_references", []),
        }

    def _parse_attack_pattern(self, obj: Dict[str, Any]) -> Dict[str, Any]:
        external_refs = obj.get("external_references", [])
        mitre_id = ""
        for ref in external_refs:
            if ref.get("source_name") == "mitre-attack":
                mitre_id = ref.get("external_id", "")
                break

        return {
            "id": obj.get("id"),
            "type": "attack-pattern",
            "name": obj.get("name", ""),
            "description": obj.get("description", ""),
            "mitre_id": mitre_id,
            "kill_chain_phases": obj.get("kill_chain_phases", []),
            "external_references": external_refs,
            "x_mitre_platforms": obj.get("x_mitre_platforms", []),
            "x_mitre_data_sources": obj.get("x_mitre_data_sources", []),
            "x_mitre_detection": obj.get("x_mitre_detection", ""),
            "x_mitre_is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
        }

    def _parse_campaign(self, obj: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": obj.get("id"),
            "type": "campaign",
            "name": obj.get("name", ""),
            "description": obj.get("description", ""),
            "aliases": obj.get("aliases", []),
            "first_seen": obj.get("first_seen"),
            "last_seen": obj.get("last_seen"),
            "objective": obj.get("objective", ""),
            "external_references": obj.get("external_references", []),
        }

    def _parse_intrusion_set(self, obj: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": obj.get("id"),
            "type": "intrusion-set",
            "name": obj.get("name", ""),
            "description": obj.get("description", ""),
            "aliases": obj.get("aliases", []),
            "first_seen": obj.get("first_seen"),
            "last_seen": obj.get("last_seen"),
            "goals": obj.get("goals", []),
            "resource_level": obj.get("resource_level", ""),
            "primary_motivation": obj.get("primary_motivation", ""),
            "external_references": obj.get("external_references", []),
        }

    def _parse_tool(self, obj: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": obj.get("id"),
            "type": "tool",
            "name": obj.get("name", ""),
            "description": obj.get("description", ""),
            "tool_types": obj.get("tool_types", []),
            "aliases": obj.get("aliases", []),
            "kill_chain_phases": obj.get("kill_chain_phases", []),
            "external_references": obj.get("external_references", []),
        }

    def _parse_vulnerability(self, obj: Dict[str, Any]) -> Dict[str, Any]:
        external_refs = obj.get("external_references", [])
        cve_id = ""
        for ref in external_refs:
            if ref.get("source_name") == "cve":
                cve_id = ref.get("external_id", "")
                break

        return {
            "id": obj.get("id"),
            "type": "vulnerability",
            "name": obj.get("name", ""),
            "description": obj.get("description", ""),
            "cve_id": cve_id,
            "external_references": external_refs,
        }

    def _parse_relationship(self, obj: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": obj.get("id"),
            "type": "relationship",
            "relationship_type": obj.get("relationship_type", ""),
            "source_ref": obj.get("source_ref", ""),
            "target_ref": obj.get("target_ref", ""),
            "description": obj.get("description", ""),
        }

    def extract_iocs(self, pattern: str) -> List[Dict[str, str]]:
        iocs = []

        if "[file:hashes" in pattern:
            hash_types = ["MD5", "SHA-1", "SHA-256", "SHA-512"]
            for hash_type in hash_types:
                if f"'{hash_type}'" in pattern or f'"{hash_type}"' in pattern:
                    start = pattern.find("=") + 1
                    end = pattern.find("]", start)
                    value = pattern[start:end].strip().strip("'\"")
                    iocs.append({"type": hash_type.lower(), "value": value})

        elif "[ipv4-addr:value" in pattern or "[ipv6-addr:value" in pattern:
            addr_type = "ipv4" if "ipv4" in pattern else "ipv6"
            start = pattern.find("=") + 1
            end = pattern.find("]", start)
            value = pattern[start:end].strip().strip("'\"")
            iocs.append({"type": addr_type, "value": value})

        elif "[domain-name:value" in pattern:
            start = pattern.find("=") + 1
            end = pattern.find("]", start)
            value = pattern[start:end].strip().strip("'\"")
            iocs.append({"type": "domain", "value": value})

        elif "[url:value" in pattern:
            start = pattern.find("=") + 1
            end = pattern.find("]", start)
            value = pattern[start:end].strip().strip("'\"")
            iocs.append({"type": "url", "value": value})

        return iocs
