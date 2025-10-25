from datetime import datetime
from typing import Any, Dict, List, Optional
import random
import yaml
from pathlib import Path


class InstructionGenerator:
    def __init__(self, templates_path: str = "./config/instruction_templates.yaml"):
        self.templates_path = Path(templates_path)
        self.templates = self._load_templates()

    def _load_templates(self) -> Dict[str, Any]:
        with open(self.templates_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)

    def generate_from_malware(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        examples = []
        templates = self.templates["templates"]["malware_analysis"]

        if not data.get("name"):
            return examples

        template = random.choice(templates)

        input_text = template["input_template"].format(
            hash_type=data.get("hash_type", "SHA-256"),
            hash_value=data.get("hash_value", ""),
        )

        behaviors = ", ".join(data.get("capabilities", [])[:3]) if data.get("capabilities") else "Various malicious behaviors"
        techniques = ", ".join(data.get("mitre_techniques", [])[:5]) if data.get("mitre_techniques") else "Multiple techniques"

        threat_actors = data.get("threat_actors", [])
        if not threat_actors and data.get("threat_actor"):
            threat_actors = [data.get("threat_actor")]
        threat_actors_str = ", ".join(threat_actors) if threat_actors else "Unknown threat actors"

        output_text = template["output_template"].format(
            malware_name=data.get("name", "Unknown"),
            malware_type=", ".join(data.get("malware_types", ["malware"])),
            threat_actor=data.get("threat_actor", "Unknown threat actor"),
            threat_actors=threat_actors_str,
            behaviors=behaviors,
            attack_techniques=techniques,
            aliases=", ".join(data.get("aliases", [])) if data.get("aliases") else "Unknown",
            first_seen=data.get("first_seen", "Unknown"),
            capabilities=", ".join(data.get("capabilities", [])[:5]) if data.get("capabilities") else "Various capabilities",
            c2_servers=data.get("c2_servers", "Not available"),
            campaign=data.get("campaign", "Multiple campaigns"),
        )

        example = {
            "instruction": template["instruction"],
            "input": input_text,
            "output": output_text,
            "metadata": {
                "source": data.get("source", "unknown"),
                "category": "malware-analysis",
                "confidence": data.get("confidence", "medium"),
                "timestamp": datetime.utcnow().isoformat(),
                "tags": self._extract_tags(data),
                "malware_family": data.get("name"),
            },
        }

        examples.append(example)
        return examples

    def generate_from_threat_actor(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        examples = []
        templates = self.templates["templates"]["threat_actor"]

        if not data.get("name"):
            return examples

        template = random.choice(templates)

        input_text = template["input_template"].format(
            group_name=data.get("name", ""),
            actor_name=data.get("name", ""),
        )

        output_text = template["output_template"].format(
            group_name=data.get("name", ""),
            actor_name=data.get("name", ""),
            aliases=", ".join(data.get("aliases", [])) if data.get("aliases") else "None",
            group_type=", ".join(data.get("actor_types", ["APT"])),
            attribution=data.get("attribution", "Unknown"),
            first_seen=data.get("first_seen", "Unknown"),
            targeted_sectors=", ".join(data.get("targeted_sectors", ["Various sectors"])),
            targeted_regions=", ".join(data.get("targeted_regions", ["Global"])),
            ttps=", ".join(data.get("ttps", ["Various TTPs"])),
            malware_families=", ".join(data.get("malware", ["Various malware"])),
            initial_access=data.get("initial_access", "Phishing, exploit public-facing applications"),
            execution=data.get("execution", "Command and scripting interpreter"),
            persistence=data.get("persistence", "Registry run keys, scheduled tasks"),
            privilege_escalation=data.get("privilege_escalation", "Exploitation for privilege escalation"),
            defense_evasion=data.get("defense_evasion", "Obfuscated files or information"),
            credential_access=data.get("credential_access", "Credential dumping"),
            lateral_movement=data.get("lateral_movement", "Remote services"),
            exfiltration=data.get("exfiltration", "Exfiltration over C2 channel"),
            malware_list=", ".join(data.get("malware", [])) if data.get("malware") else "Custom tools",
            preferred_implants=data.get("preferred_implants", "Custom backdoors"),
            custom_tools=data.get("custom_tools", "Various custom tools"),
            public_tools=data.get("public_tools", "Mimikatz, PsExec, and other public tools"),
        )

        example = {
            "instruction": template["instruction"],
            "input": input_text,
            "output": output_text,
            "metadata": {
                "source": data.get("source", "unknown"),
                "category": "threat-actor-profiling",
                "confidence": data.get("confidence", "medium"),
                "timestamp": datetime.utcnow().isoformat(),
                "tags": self._extract_tags(data),
                "threat_actor": data.get("name"),
            },
        }

        examples.append(example)
        return examples

    def generate_from_attack_pattern(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        examples = []
        templates = self.templates["templates"]["attack_pattern"]

        if not data.get("name"):
            return examples

        template = random.choice(templates)

        tactic = ""
        if data.get("kill_chain_phases"):
            tactic = data["kill_chain_phases"][0].get("phase_name", "")

        input_text = template["input_template"].format(
            technique_id=data.get("mitre_id", ""),
            technique_name=data.get("name", ""),
            behavior_description=data.get("description", "")[:200],
        )

        output_text = template["output_template"].format(
            technique_id=data.get("mitre_id", ""),
            technique_name=data.get("name", ""),
            tactic=tactic,
            description=data.get("description", ""),
            platforms=", ".join(data.get("platforms", [])),
            data_sources=", ".join(data.get("data_sources", [])),
            detection_guidance=data.get("detection", "Monitor for suspicious activity"),
            mitigation=self._get_mitigation(data),
            detection_methods=self._get_detection_methods(data),
            log_sources=", ".join(data.get("data_sources", [])),
            indicators="Behavioral indicators specific to this technique",
            siem_rules="Custom SIEM rules based on data sources",
            sub_technique=data.get("sub_technique", "N/A"),
            threat_actors=", ".join(data.get("threat_actors", ["Multiple APT groups"])),
        )

        example = {
            "instruction": template["instruction"],
            "input": input_text,
            "output": output_text,
            "metadata": {
                "source": data.get("source", "unknown"),
                "category": "attack-pattern-recognition",
                "confidence": data.get("confidence", "medium"),
                "timestamp": datetime.utcnow().isoformat(),
                "tags": self._extract_tags(data),
                "mitre_attack_ids": [data.get("mitre_id", "")],
            },
        }

        examples.append(example)
        return examples

    def generate_from_indicator(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        examples = []
        templates = self.templates["templates"]["ioc_analysis"]

        if not data.get("ioc_value"):
            return examples

        template = self._select_template_by_ioc_type(data.get("ioc_type", ""), templates)

        input_text = self._format_indicator_input(template, data)

        output_text = self._format_indicator_output(template, data)

        example = {
            "instruction": template["instruction"],
            "input": input_text,
            "output": output_text,
            "metadata": {
                "source": data.get("source", "unknown"),
                "category": "ioc-intelligence",
                "confidence": data.get("confidence", "medium"),
                "timestamp": datetime.utcnow().isoformat(),
                "tags": self._extract_tags(data),
            },
        }

        examples.append(example)
        return examples

    def generate_from_campaign(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        examples = []
        templates = self.templates["templates"]["campaign_analysis"]

        if not data.get("name"):
            return examples

        template = random.choice(templates)

        input_text = template["input_template"].format(campaign_name=data.get("name", ""))

        output_text = template["output_template"].format(
            campaign_name=data.get("name", ""),
            campaign_description=data.get("description", ""),
            threat_actor=data.get("threat_actor", "Unknown"),
            start_date=data.get("first_seen", "Unknown"),
            end_date=data.get("last_seen", "Ongoing"),
            sectors=", ".join(data.get("targeted_sectors", ["Various sectors"])),
            countries=", ".join(data.get("targeted_countries", ["Multiple countries"])),
            attack_vectors=", ".join(data.get("attack_vectors", ["Multiple vectors"])),
            malware=", ".join(data.get("malware", ["Various malware"])),
            objectives=data.get("objective", "Information theft and espionage"),
            c2_ips=", ".join(data.get("c2_ips", [])) if data.get("c2_ips") else "Not disclosed",
            domains=", ".join(data.get("domains", [])) if data.get("domains") else "Not disclosed",
            file_hashes=", ".join(data.get("file_hashes", [])[:5]) if data.get("file_hashes") else "Not disclosed",
            email_indicators=", ".join(data.get("email_indicators", [])) if data.get("email_indicators") else "Not disclosed",
            registry_keys=", ".join(data.get("registry_keys", [])) if data.get("registry_keys") else "Not disclosed",
            mutex_names=", ".join(data.get("mutex_names", [])) if data.get("mutex_names") else "Not disclosed",
            timeline_events=self._generate_timeline(data),
            milestones=self._generate_milestones(data),
            evolution_description=data.get("evolution", "Campaign has evolved over time with new TTPs"),
        )

        example = {
            "instruction": template["instruction"],
            "input": input_text,
            "output": output_text,
            "metadata": {
                "source": data.get("source", "unknown"),
                "category": "campaign-analysis",
                "confidence": data.get("confidence", "medium"),
                "timestamp": datetime.utcnow().isoformat(),
                "tags": self._extract_tags(data),
                "campaign": data.get("name"),
            },
        }

        examples.append(example)
        return examples

    def _select_template_by_ioc_type(
        self, ioc_type: str, templates: List[Dict[str, str]]
    ) -> Dict[str, str]:
        if ioc_type in ["ipv4", "ipv6"]:
            return [t for t in templates if "IP" in t["instruction"]][0]
        elif ioc_type == "domain":
            return [t for t in templates if "domain" in t["instruction"]][0]
        elif ioc_type == "url":
            return [t for t in templates if "URL" in t["instruction"]][0]
        else:
            return [t for t in templates if "hash" in t["instruction"]][0]

    def _format_indicator_input(self, template: Dict[str, str], data: Dict[str, Any]) -> str:
        ioc_type = data.get("ioc_type", "")
        ioc_value = data.get("ioc_value", "")

        return template["input_template"].format(
            ip_address=ioc_value if ioc_type in ["ipv4", "ipv6"] else "",
            domain=ioc_value if ioc_type == "domain" else "",
            url=ioc_value if ioc_type == "url" else "",
            hash_type=ioc_type.upper() if ioc_type in ["md5", "sha-1", "sha-256"] else "SHA-256",
            hash_value=ioc_value,
        )

    def _format_indicator_output(self, template: Dict[str, str], data: Dict[str, Any]) -> str:
        return template["output_template"].format(
            reputation=self._get_reputation(data),
            associations=", ".join(data.get("associations", ["Various threat campaigns"])),
            activities=", ".join(data.get("activities", ["Malware distribution", "C2 communication"])),
            first_seen=data.get("first_seen", "Unknown"),
            last_seen=data.get("last_seen", "Recently"),
            threat_actor=data.get("threat_actor", "Multiple threat actors"),
            purpose=data.get("purpose", "Malicious infrastructure"),
            campaigns=", ".join(data.get("campaigns", ["Multiple campaigns"])),
            malware_families=", ".join(data.get("malware_families", ["Various malware"])),
            nameservers=data.get("nameservers", "Not available"),
            status=data.get("status", "Active"),
            threat_description=self._get_threat_description(data),
            malware=", ".join(data.get("malware", ["Multiple families"])),
            phishing_target=data.get("phishing_target", "N/A"),
            detection_rate=f"{data.get('detection_count', 0)}/{data.get('total_engines', 70)}",
            blocklist_date=data.get("blocklist_date", "Recently"),
            is_malicious="Malicious" if data.get("is_malicious", True) else "Clean",
            detection_count=data.get("detection_count", 0),
            total_engines=data.get("total_engines", 70),
            detection_names=", ".join(data.get("detection_names", ["Trojan", "Malware"])),
            file_type=data.get("file_type", "Unknown"),
            signature=data.get("signature", "Digital signature not verified"),
        )

    def _get_reputation(self, data: Dict[str, Any]) -> str:
        confidence = data.get("confidence", "medium")
        if confidence == "high":
            return "malicious with high confidence"
        elif confidence == "medium":
            return "suspicious"
        else:
            return "potentially malicious"

    def _get_threat_description(self, data: Dict[str, Any]) -> str:
        return data.get("description", "has been flagged for malicious activity")

    def _get_mitigation(self, data: Dict[str, Any]) -> str:
        return data.get("mitigation", "Implement proper security controls and monitoring")

    def _get_detection_methods(self, data: Dict[str, Any]) -> str:
        return data.get("detection", "Monitor relevant data sources for suspicious patterns")

    def _generate_timeline(self, data: Dict[str, Any]) -> str:
        return data.get("timeline", "Campaign timeline includes multiple phases of operation")

    def _generate_milestones(self, data: Dict[str, Any]) -> str:
        return data.get("milestones", "Key operational milestones throughout the campaign")

    def _extract_tags(self, data: Dict[str, Any]) -> List[str]:
        tags = []

        if data.get("name"):
            tags.append(data["name"].lower().replace(" ", "-"))

        if data.get("malware_types"):
            tags.extend([mt.lower() for mt in data["malware_types"]])

        if data.get("labels"):
            tags.extend([label.lower() for label in data["labels"]])

        if data.get("mitre_id"):
            tags.append(data["mitre_id"].lower())

        return list(set(tags))[:10]

    def generate_from_vulnerability(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        examples = []

        if not data.get("name"):
            return examples

        example = {
            "instruction": "Analyze this vulnerability and provide information about remediation actions.",
            "input": f"CVE ID: {data.get('name', '')}\nDescription: {data.get('description', '')}",
            "output": f"Vulnerability: {data.get('vulnerability_name', data.get('name', ''))}\n\nDescription: {data.get('description', '')}\n\nRequired Action: {data.get('required_action', 'Apply security patches')}\n\nDue Date: {data.get('due_date', 'As soon as possible')}\n\nThis vulnerability is tracked by CISA Known Exploited Vulnerabilities catalog, indicating active exploitation in the wild.",
            "metadata": {
                "source": data.get("source", "unknown"),
                "category": "vulnerability-analysis",
                "confidence": data.get("confidence", "high"),
                "timestamp": datetime.utcnow().isoformat(),
                "tags": [data.get("name", "").lower(), "vulnerability", "cve"],
                "cve_id": data.get("name"),
            },
        }

        examples.append(example)
        return examples
