import json
import jsonlines
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List
from tqdm import tqdm

from .collectors import (
    MITRECollector,
    OTXCollector,
    AbuseChCollector,
    RansomwareLiveCollector,
    PhishingCollector,
    CISAKEVCollector,
    GitHubIOCCollector,
    CERTAdvisoriesCollector,
    Unit42Collector,
    YARARulesCollector,
)
from .collectors.report_collector import ReportCollector
from .collectors.blog_collector import BlogCollector
from .processors import STIXParser
from .processors.data_normalizer import DataNormalizer
from .generators import InstructionGenerator
from .models import InstructionExample, DatasetStatistics


class CTIDatasetPipeline:
    def __init__(self, config_path: str = "./config/sources.yaml", output_dir: str = "./output"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.mitre_collector = MITRECollector()
        self.otx_collector = None
        self.abuse_collector = AbuseChCollector()
        self.ransomware_collector = RansomwareLiveCollector()
        self.phishing_collector = PhishingCollector()
        self.cisa_collector = CISAKEVCollector()
        self.github_collector = GitHubIOCCollector()
        self.cert_collector = CERTAdvisoriesCollector()
        self.unit42_collector = Unit42Collector()
        self.yara_collector = YARARulesCollector()
        self.report_collector = ReportCollector()
        self.blog_collector = BlogCollector()

        self.stix_parser = STIXParser()
        self.normalizer = DataNormalizer()
        self.generator = InstructionGenerator()

        self.examples = []
        self.stats = DatasetStatistics()

    def run_full_pipeline(self, target_count: int = 100000, skip_collection: bool = False) -> Dict[str, Any]:
        print("=" * 80)
        print("CTI Instruction-Tuning Dataset Generation Pipeline")
        print("=" * 80)

        if not skip_collection:
            print("\n[1/5] Collecting data from sources...")
            self.collect_all_sources()
        else:
            print("\n[1/5] Skipping data collection (using existing data)...")

        print("\n[2/5] Processing and normalizing data...")
        entities = self.process_all_data()

        print("\n[3/5] Generating instruction-tuning examples...")
        self.generate_instructions(entities, target_count)

        print("\n[4/5] Saving dataset...")
        self.save_dataset()

        print("\n[5/5] Generating statistics...")
        stats = self.generate_statistics()

        print("\n" + "=" * 80)
        print("Pipeline completed successfully!")
        print(f"Total examples generated: {len(self.examples)}")
        print("=" * 80)

        return stats

    def collect_all_sources(self) -> None:
        print("\nCollecting MITRE ATT&CK data from GitHub...")
        mitre_stats = self.mitre_collector.collect_from_github()
        print(f"MITRE: {sum(mitre_stats.values())} objects collected")

        print("\nCollecting Abuse.ch feeds...")
        abuse_stats = self.abuse_collector.collect_all()
        print(f"Abuse.ch: {sum(abuse_stats.values())} entries collected")

        print("\nCollecting Security Reports...")
        report_stats = self.report_collector.collect_all()
        print(f"Reports: {sum(report_stats.values())} articles collected")

        print("\nCollecting Security Blogs...")
        blog_stats = self.blog_collector.collect_all()
        print(f"Blogs: {sum(blog_stats.values())} articles collected")

    def process_all_data(self) -> List[Dict[str, Any]]:
        entities = []

        print("\nProcessing MITRE ATT&CK data...")
        mitre_entities = self.process_mitre_data()
        entities.extend(mitre_entities)
        print(f"Processed {len(mitre_entities)} MITRE entities")

        print("\nProcessing Abuse.ch data...")
        abuse_entities = self.process_abuse_data()
        entities.extend(abuse_entities)
        print(f"Processed {len(abuse_entities)} Abuse.ch entities")

        print("\nProcessing Phishing data...")
        phishing_entities = self.process_phishing_data()
        entities.extend(phishing_entities)
        print(f"Processed {len(phishing_entities)} Phishing entities")

        print("\nProcessing Ransomware data...")
        ransomware_entities = self.process_ransomware_data()
        entities.extend(ransomware_entities)
        print(f"Processed {len(ransomware_entities)} Ransomware entities")

        print("\nProcessing CISA KEV data...")
        cisa_entities = self.process_cisa_data()
        entities.extend(cisa_entities)
        print(f"Processed {len(cisa_entities)} CISA KEV entities")

        print("\nProcessing GitHub IOC data...")
        github_entities = self.process_github_data()
        entities.extend(github_entities)
        print(f"Processed {len(github_entities)} GitHub IOC entities")

        print("\nProcessing CERT advisories...")
        cert_entities = self.process_cert_data()
        entities.extend(cert_entities)
        print(f"Processed {len(cert_entities)} CERT entities")

        print("\nProcessing Unit42 data...")
        unit42_entities = self.process_unit42_data()
        entities.extend(unit42_entities)
        print(f"Processed {len(unit42_entities)} Unit42 entities")

        print("\nProcessing YARA rules...")
        yara_entities = self.process_yara_data()
        entities.extend(yara_entities)
        print(f"Processed {len(yara_entities)} YARA entities")

        print("\nProcessing OTX pulses...")
        otx_entities = self.process_otx_data()
        entities.extend(otx_entities)
        print(f"Processed {len(otx_entities)} OTX entities")

        print("\nProcessing ICS-CERT advisories...")
        ics_cert_entities = self.process_ics_cert_data()
        entities.extend(ics_cert_entities)
        print(f"Processed {len(ics_cert_entities)} ICS-CERT entities")

        print("\nProcessing Security Reports...")
        report_entities = self.process_report_data()
        entities.extend(report_entities)
        print(f"Processed {len(report_entities)} Report entities")

        print("\nProcessing Security Blogs...")
        blog_entities = self.process_blog_data()
        entities.extend(blog_entities)
        print(f"Processed {len(blog_entities)} Blog entities")

        print("\nDeduplicating entities...")
        entities = self.normalizer.deduplicate(entities)
        print(f"Total unique entities: {len(entities)}")

        return entities

    def process_mitre_data(self) -> List[Dict[str, Any]]:
        entities = []
        mitre_dir = Path("./data/raw/mitre")

        for json_file in mitre_dir.glob("*.json"):
            with open(json_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            parsed = self.stix_parser.parse_bundle(data)

            for malware in parsed.get("malware", []):
                normalized = self.normalizer.normalize_malware(malware, "mitre-attack")
                entities.append(normalized)

            for actor in parsed.get("threat-actor", []):
                normalized = self.normalizer.normalize_threat_actor(actor, "mitre-attack")
                entities.append(normalized)

            for pattern in parsed.get("attack-pattern", []):
                normalized = self.normalizer.normalize_attack_pattern(pattern, "mitre-attack")
                entities.append(normalized)

            for indicator in parsed.get("indicator", []):
                normalized = self.normalizer.normalize_indicator(indicator, "mitre-attack")
                entities.append(normalized)

            for campaign in parsed.get("campaign", []):
                normalized = self.normalizer.normalize_campaign(campaign, "mitre-attack")
                entities.append(normalized)

        return entities

    def process_abuse_data(self) -> List[Dict[str, Any]]:
        entities = []
        abuse_dir = Path("./data/raw/abuse_ch")

        for json_file in abuse_dir.glob("*.json"):
            with open(json_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            if "urlhaus" in json_file.name:
                entities.extend(self._process_urlhaus(data))
            elif "malwarebazaar" in json_file.name:
                entities.extend(self._process_malwarebazaar(data))
            elif "feodo" in json_file.name:
                entities.extend(self._process_feodo(data))
            elif "threatfox" in json_file.name:
                entities.extend(self._process_threatfox(data))

        return entities

    def _process_urlhaus(self, data: Any) -> List[Dict[str, Any]]:
        entities = []

        items = data if isinstance(data, list) else []

        for item in items[:5000]:
            if not isinstance(item, dict):
                continue

            normalized = {
                "entity_type": "indicator",
                "source": "abuse-ch",
                "ioc_type": "url",
                "ioc_value": item.get("url", ""),
                "name": f"URLhaus URL: {item.get('url_status', '')}",
                "description": f"Malware URL distributing {item.get('threat', 'malware')}",
                "confidence": "high" if item.get("url_status") == "online" else "medium",
                "malware": [item.get("threat", "")],
                "first_seen": item.get("dateadded", ""),
            }

            normalized["id"] = self.normalizer._generate_id(normalized)
            entities.append(normalized)

        return entities

    def _process_malwarebazaar(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        entities = []

        samples = data.get("data", [])

        for sample in samples[:5000]:
            normalized = {
                "entity_type": "malware",
                "source": "abuse-ch",
                "name": sample.get("signature", "Unknown"),
                "description": f"Malware sample from MalwareBazaar",
                "malware_types": [sample.get("file_type", "")],
                "hash_type": "sha256",
                "hash_value": sample.get("sha256_hash", ""),
                "first_seen": sample.get("first_seen", ""),
                "confidence": "high",
                "tags": sample.get("tags", []),
            }

            normalized["id"] = self.normalizer._generate_id(normalized)
            entities.append(normalized)

        return entities

    def _process_feodo(self, data: Any) -> List[Dict[str, Any]]:
        entities = []

        items = data if isinstance(data, list) else []

        for item in items[:5000]:
            if not isinstance(item, dict):
                continue

            normalized = {
                "entity_type": "indicator",
                "source": "abuse-ch",
                "ioc_type": "ipv4",
                "ioc_value": item.get("ip_address", ""),
                "name": f"Feodo C2: {item.get('malware', '')}",
                "description": f"Botnet C2 server for {item.get('malware', 'unknown malware')}",
                "confidence": "high",
                "malware": [item.get("malware", "")],
                "first_seen": item.get("first_seen", ""),
            }

            normalized["id"] = self.normalizer._generate_id(normalized)
            entities.append(normalized)

        return entities

    def _process_threatfox(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        entities = []

        iocs = data.get("data", [])

        for ioc in iocs[:5000]:
            ioc_type_map = {
                "ip:port": "ipv4",
                "domain": "domain",
                "url": "url",
                "md5_hash": "md5",
                "sha256_hash": "sha256",
            }

            normalized = {
                "entity_type": "indicator",
                "source": "abuse-ch",
                "ioc_type": ioc_type_map.get(ioc.get("ioc_type", ""), "unknown"),
                "ioc_value": ioc.get("ioc", ""),
                "name": f"ThreatFox IOC: {ioc.get('threat_type', '')}",
                "description": f"{ioc.get('threat_type', 'Threat')} indicator",
                "confidence": "high" if ioc.get("confidence_level", 0) >= 75 else "medium",
                "malware": [ioc.get("malware", "")],
                "first_seen": ioc.get("first_seen", ""),
            }

            normalized["id"] = self.normalizer._generate_id(normalized)
            entities.append(normalized)

        return entities

    def process_phishing_data(self) -> List[Dict[str, Any]]:
        entities = []
        phishing_dir = Path("./data/raw/phishing")

        if not phishing_dir.exists():
            return entities

        for json_file in phishing_dir.glob("*.json"):
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                items = data if isinstance(data, list) else []

                for item in items[:50000]:
                    if not isinstance(item, dict):
                        continue

                    ioc_value = item.get("url") or item.get("value") or item.get("domain", "")
                    if not ioc_value:
                        continue

                    normalized = {
                        "entity_type": "indicator",
                        "source": item.get("source", "phishing-feeds"),
                        "ioc_type": "url" if "http" in ioc_value.lower() else "domain",
                        "ioc_value": ioc_value,
                        "name": f"Phishing: {ioc_value[:50]}",
                        "description": f"Phishing {'URL' if 'http' in ioc_value.lower() else 'domain'} reported by {item.get('source', 'phishing feed')}",
                        "confidence": "high",
                        "first_seen": item.get("collected_at", ""),
                        "tags": ["phishing"],
                    }

                    normalized["id"] = self.normalizer._generate_id(normalized)
                    entities.append(normalized)

            except Exception as e:
                print(f"Error processing {json_file.name}: {e}")
                continue

        return entities

    def process_ransomware_data(self) -> List[Dict[str, Any]]:
        entities = []
        ransomware_dir = Path("./data/raw/ransomware_live")

        if not ransomware_dir.exists():
            return entities

        for json_file in ransomware_dir.glob("*.json"):
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                items = data if isinstance(data, list) else []

                for item in items:
                    if "group" in json_file.name:
                        normalized = {
                            "entity_type": "threat-actor",
                            "source": "ransomware-live",
                            "name": item.get("name", "Unknown"),
                            "description": f"Ransomware group tracked by ransomware.live",
                            "confidence": "high",
                            "malware": [item.get("name", "")],
                            "first_seen": item.get("discovered", ""),
                        }
                    else:
                        victim = item.get("post_title") or item.get("victim", "Unknown")
                        group = item.get("group_name") or item.get("group", "unknown group")
                        normalized = {
                            "entity_type": "campaign",
                            "source": "ransomware-live",
                            "name": f"Ransomware attack: {victim}",
                            "description": f"Attack by {group} targeting {victim}. {item.get('description', '')}",
                            "confidence": "high",
                            "first_seen": item.get("published") or item.get("discovered", ""),
                            "threat_actors": [group],
                        }

                    normalized["id"] = self.normalizer._generate_id(normalized)
                    entities.append(normalized)

            except Exception as e:
                print(f"Error processing {json_file.name}: {e}")
                continue

        return entities

    def process_cisa_data(self) -> List[Dict[str, Any]]:
        entities = []
        cisa_dir = Path("./data/raw/cisa_kev")

        if not cisa_dir.exists():
            return entities

        for json_file in cisa_dir.glob("*.json"):
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                vulns = data.get("vulnerabilities", [])

                for vuln in vulns:
                    normalized = {
                        "entity_type": "vulnerability",
                        "source": "cisa-kev",
                        "name": vuln.get("cveID", ""),
                        "description": vuln.get("shortDescription", ""),
                        "vulnerability_name": vuln.get("vulnerabilityName", ""),
                        "required_action": vuln.get("requiredAction", ""),
                        "due_date": vuln.get("dueDate", ""),
                        "confidence": "high",
                        "first_seen": vuln.get("dateAdded", ""),
                    }

                    normalized["id"] = self.normalizer._generate_id(normalized)
                    entities.append(normalized)

            except Exception as e:
                print(f"Error processing {json_file.name}: {e}")
                continue

        return entities

    def process_github_data(self) -> List[Dict[str, Any]]:
        entities = []
        github_dir = Path("./data/raw/github_ioc")

        if not github_dir.exists():
            return entities

        for json_file in github_dir.glob("*.json"):
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                items = data if isinstance(data, list) else []

                for item in items:
                    if "apt_campaign" in json_file.name or ("filename" in item and "url" in item):
                        normalized = {
                            "entity_type": "report",
                            "source": "github-apt-campaigns",
                            "name": item.get("filename", "Unknown Campaign"),
                            "description": f"APT Campaign report: {item.get('filename', '')}",
                            "url": item.get("url", ""),
                            "published": item.get("published", ""),
                            "sha1": item.get("sha1", ""),
                            "confidence": "high",
                            "first_seen": item.get("published", ""),
                            "tags": ["apt", "campaign"],
                        }
                        normalized["id"] = self.normalizer._generate_id(normalized)
                        entities.append(normalized)

                    elif "hashes" in item and "campaign" in item:
                        hashes = item.get("hashes", [])
                        campaign = item.get("campaign", "Unknown")
                        hash_type = item.get("hash_type", "unknown")

                        for hash_value in hashes[:50]:
                            if not hash_value or hash_value.startswith("#"):
                                continue

                            normalized = {
                                "entity_type": "indicator",
                                "source": "github-eset-iocs",
                                "ioc_type": hash_type,
                                "ioc_value": hash_value,
                                "name": f"ESET Malware: {campaign}",
                                "description": f"{hash_type.upper()} hash from ESET {campaign} malware campaign",
                                "confidence": "high",
                                "first_seen": item.get("collected_at", ""),
                                "tags": ["malware", "eset", campaign.lower()],
                            }

                            normalized["id"] = self.normalizer._generate_id(normalized)
                            entities.append(normalized)

            except Exception as e:
                print(f"Error processing {json_file.name}: {e}")
                continue

        return entities

    def process_cert_data(self) -> List[Dict[str, Any]]:
        entities = []
        cert_dir = Path("./data/raw/cert_advisories")

        if not cert_dir.exists():
            return entities

        for json_file in cert_dir.glob("*.json"):
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                items = data if isinstance(data, list) else []

                for item in items:
                    normalized = {
                        "entity_type": "report",
                        "source": item.get("source", "cert-advisories"),
                        "name": item.get("title", ""),
                        "description": item.get("summary", ""),
                        "url": item.get("link", ""),
                        "confidence": "high",
                        "first_seen": item.get("published", ""),
                        "tags": ["advisory", "cert"],
                    }

                    normalized["id"] = self.normalizer._generate_id(normalized)
                    entities.append(normalized)

            except Exception as e:
                print(f"Error processing {json_file.name}: {e}")
                continue

        return entities

    def process_unit42_data(self) -> List[Dict[str, Any]]:
        entities = []
        unit42_dir = Path("./data/raw/unit42")

        if not unit42_dir.exists():
            return entities

        for json_file in unit42_dir.glob("*.json"):
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                items = data if isinstance(data, list) else []

                for item in items:
                    iocs = item.get("content", "").split("\n")[:100]

                    for ioc in iocs:
                        ioc = ioc.strip()
                        if not ioc or ioc.startswith("#"):
                            continue

                        normalized = {
                            "entity_type": "indicator",
                            "source": item.get("source", "unit42"),
                            "ioc_type": "hash" if len(ioc) in [32, 40, 64] else "domain",
                            "ioc_value": ioc,
                            "name": f"Unit42 IOC: {item.get('filename', '')}",
                            "description": f"IOC from Palo Alto Unit42 threat intelligence",
                            "confidence": "high",
                            "first_seen": item.get("collected_at", ""),
                        }

                        normalized["id"] = self.normalizer._generate_id(normalized)
                        entities.append(normalized)

            except Exception as e:
                print(f"Error processing {json_file.name}: {e}")
                continue

        return entities

    def process_yara_data(self) -> List[Dict[str, Any]]:
        entities = []
        yara_dir = Path("./data/raw/yara_rules")

        if not yara_dir.exists():
            return entities

        for json_file in yara_dir.glob("*.json"):
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                items = data if isinstance(data, list) else []

                for item in items:
                    normalized = {
                        "entity_type": "detection-rule",
                        "source": item.get("source", "yara-rules"),
                        "name": item.get("filename", ""),
                        "description": f"YARA rule from Neo23x0 signature-base",
                        "rule_content": item.get("content", "")[:500],
                        "confidence": "high",
                        "first_seen": item.get("collected_at", ""),
                        "tags": ["yara", "apt"],
                    }

                    normalized["id"] = self.normalizer._generate_id(normalized)
                    entities.append(normalized)

            except Exception as e:
                print(f"Error processing {json_file.name}: {e}")
                continue

        return entities

    def process_otx_data(self) -> List[Dict[str, Any]]:
        entities = []
        otx_dir = Path("./data/raw/otx")

        if not otx_dir.exists():
            return entities

        for json_file in otx_dir.glob("*.json"):
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                pulses = data.get("pulses", [])

                for pulse in pulses:
                    normalized = {
                        "entity_type": "threat-intelligence",
                        "source": "otx",
                        "name": pulse.get("name", ""),
                        "description": pulse.get("description", ""),
                        "tags": pulse.get("tags", []),
                        "confidence": "high",
                        "first_seen": pulse.get("created", ""),
                    }

                    normalized["id"] = self.normalizer._generate_id(normalized)
                    entities.append(normalized)

                    for indicator in pulse.get("indicators", [])[:50]:
                        ind_normalized = {
                            "entity_type": "indicator",
                            "source": "otx",
                            "ioc_type": indicator.get("type", ""),
                            "ioc_value": indicator.get("indicator", ""),
                            "name": f"OTX Indicator: {pulse.get('name', '')[:30]}",
                            "description": pulse.get("description", "")[:200],
                            "confidence": "high",
                            "first_seen": pulse.get("created", ""),
                            "tags": pulse.get("tags", []),
                        }

                        ind_normalized["id"] = self.normalizer._generate_id(ind_normalized)
                        entities.append(ind_normalized)

            except Exception as e:
                print(f"Error processing {json_file.name}: {e}")
                continue

        return entities

    def process_dshield_data(self) -> List[Dict[str, Any]]:
        entities = []
        dshield_dir = Path("./data/raw/dshield")

        if not dshield_dir.exists():
            return entities

        for json_file in dshield_dir.glob("*.json"):
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                items = data if isinstance(data, list) else []

                for item in items[:1000]:
                    if isinstance(item, str):
                        normalized = {
                            "entity_type": "indicator",
                            "source": "dshield",
                            "ioc_type": "username" if "username" in json_file.name else "password",
                            "ioc_value": item,
                            "name": f"DShield {json_file.name}: {item[:30]}",
                            "description": f"Commonly observed {'username' if 'username' in json_file.name else 'password'} from SANS ISC DShield",
                            "confidence": "medium",
                            "first_seen": "",
                            "tags": ["dshield", "brute-force"],
                        }

                        normalized["id"] = self.normalizer._generate_id(normalized)
                        entities.append(normalized)

            except Exception as e:
                print(f"Error processing {json_file.name}: {e}")
                continue

        return entities

    def process_ics_cert_data(self) -> List[Dict[str, Any]]:
        entities = []
        ics_cert_dir = Path("./data/raw/ics_cert")

        if not ics_cert_dir.exists():
            return entities

        for json_file in ics_cert_dir.glob("*.json"):
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                items = data if isinstance(data, list) else []

                for item in items:
                    normalized = {
                        "entity_type": "report",
                        "source": "ics-cert",
                        "name": item.get("title", ""),
                        "description": item.get("summary", ""),
                        "url": item.get("link", ""),
                        "confidence": "high",
                        "first_seen": item.get("published", ""),
                        "tags": ["ics", "scada", "critical-infrastructure"],
                    }

                    normalized["id"] = self.normalizer._generate_id(normalized)
                    entities.append(normalized)

            except Exception as e:
                print(f"Error processing {json_file.name}: {e}")
                continue

        return entities

    def process_report_data(self) -> List[Dict[str, Any]]:
        entities = []
        reports_dir = Path("./data/raw/reports")

        if not reports_dir.exists():
            return entities

        for json_file in reports_dir.glob("*.json"):
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                reports = data if isinstance(data, list) else []

                for report in reports:
                    normalized = self.normalizer.normalize_report(report, json_file.stem)
                    entities.append(normalized)

            except Exception as e:
                print(f"Error processing {json_file.name}: {e}")
                continue

        return entities

    def process_blog_data(self) -> List[Dict[str, Any]]:
        entities = []
        blogs_dir = Path("./data/raw/blogs")

        if not blogs_dir.exists():
            return entities

        for json_file in blogs_dir.glob("*.json"):
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                articles = data if isinstance(data, list) else []

                for article in articles:
                    normalized = self.normalizer.normalize_blog(article, json_file.stem)
                    entities.append(normalized)

            except Exception as e:
                print(f"Error processing {json_file.name}: {e}")
                continue

        return entities

    def generate_instructions(self, entities: List[Dict[str, Any]], target_count: int) -> None:
        self.examples = []

        for entity in tqdm(entities, desc="Generating instructions"):
            entity_type = entity.get("entity_type", "")

            try:
                if entity_type == "malware":
                    examples = self.generator.generate_from_malware(entity)
                elif entity_type == "threat-actor":
                    examples = self.generator.generate_from_threat_actor(entity)
                elif entity_type == "attack-pattern":
                    examples = self.generator.generate_from_attack_pattern(entity)
                elif entity_type == "indicator":
                    examples = self.generator.generate_from_indicator(entity)
                elif entity_type == "campaign":
                    examples = self.generator.generate_from_campaign(entity)
                elif entity_type == "vulnerability":
                    examples = self.generator.generate_from_vulnerability(entity)
                elif entity_type == "report":
                    examples = [self._generate_report_example(entity)]
                elif entity_type == "blog":
                    examples = [self._generate_blog_example(entity)]
                elif entity_type == "detection-rule":
                    examples = [self._generate_detection_rule_example(entity)]
                elif entity_type == "threat-intelligence":
                    examples = [self._generate_threat_intelligence_example(entity)]
                else:
                    continue

                self.examples.extend(examples)

                if len(self.examples) >= target_count:
                    break

            except Exception as e:
                continue

        print(f"\nGenerated {len(self.examples)} instruction examples")

    def _generate_report_example(self, entity: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "instruction": "Summarize this security research report.",
            "input": f"Report Title: {entity.get('title', '')}\nSource: {entity.get('source_name', '')}\nPublished: {entity.get('published_date', '')}",
            "output": f"Summary of '{entity.get('title', '')}' by {entity.get('source_name', '')}:\n{entity.get('description', '')}\n\nRelevant Tags: {', '.join(entity.get('tags', []))}",
            "metadata": {
                "category": "report-analysis",
                "source": entity.get("source", "unknown"),
                "confidence": entity.get("confidence", "medium"),
                "tags": entity.get("tags", []),
            }
        }

    def _generate_blog_example(self, entity: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "instruction": "Summarize this cybersecurity blog post.",
            "input": f"Title: {entity.get('title', '')}\nAuthor: {entity.get('author', '')}\nSource: {entity.get('source_name', '')}",
            "output": f"Summary of '{entity.get('title', '')}' by {entity.get('author', '')}:\n{entity.get('description', '')}\n\nTags: {', '.join(entity.get('tags', []))}\nPublished: {entity.get('published_date', '')}",
            "metadata": {
                "category": "blog-analysis",
                "source": entity.get("source", "unknown"),
                "confidence": entity.get("confidence", "medium"),
                "tags": entity.get("tags", []),
            }
        }

    def _generate_detection_rule_example(self, entity: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "instruction": "Explain this YARA detection rule and what threats it identifies.",
            "input": f"Rule: {entity.get('name', '')}\n{entity.get('rule_content', '')[:300]}",
            "output": f"This YARA rule from Neo23x0's signature-base is designed to detect APT-related threats. {entity.get('description', '')}",
            "metadata": {
                "category": "malware-analysis",
                "source": entity.get("source", "unknown"),
                "confidence": entity.get("confidence", "high"),
                "tags": entity.get("tags", []),
            }
        }

    def _generate_threat_intelligence_example(self, entity: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "instruction": "Analyze this threat intelligence report and extract key indicators.",
            "input": f"Threat: {entity.get('name', '')}\nDescription: {entity.get('description', '')}",
            "output": f"Threat Analysis: {entity.get('name', '')}\n\n{entity.get('description', '')}\n\nThis intelligence was collected from {entity.get('source', 'open sources')} and is considered {entity.get('confidence', 'medium')} confidence.",
            "metadata": {
                "category": "threat-intelligence",
                "source": entity.get("source", "unknown"),
                "confidence": entity.get("confidence", "medium"),
                "tags": entity.get("tags", []),
            }
        }

    def save_dataset(self) -> None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        jsonl_path = self.output_dir / f"cti_dataset_{timestamp}.jsonl"
        with jsonlines.open(jsonl_path, mode="w") as writer:
            for example in tqdm(self.examples, desc="Saving JSONL"):
                writer.write(example)

        print(f"\nDataset saved to: {jsonl_path}")

        json_path = self.output_dir / f"cti_dataset_{timestamp}.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(self.examples, f, indent=2, ensure_ascii=False)

        print(f"Dataset saved to: {json_path}")

    def generate_statistics(self) -> Dict[str, Any]:
        stats = {
            "total_examples": len(self.examples),
            "by_category": {},
            "by_source": {},
            "by_confidence": {},
            "timestamp": datetime.now().isoformat(),
        }

        for example in self.examples:
            metadata = example.get("metadata", {})

            category = metadata.get("category", "unknown")
            stats["by_category"][category] = stats["by_category"].get(category, 0) + 1

            source = metadata.get("source", "unknown")
            stats["by_source"][source] = stats["by_source"].get(source, 0) + 1

            confidence = metadata.get("confidence", "unknown")
            stats["by_confidence"][confidence] = stats["by_confidence"].get(confidence, 0) + 1

        stats_path = self.output_dir / "dataset_statistics.json"
        with open(stats_path, "w", encoding="utf-8") as f:
            json.dump(stats, f, indent=2, ensure_ascii=False)

        print(f"\nStatistics saved to: {stats_path}")
        print(f"\nDataset Statistics:")
        print(f"  Total examples: {stats['total_examples']}")
        print(f"  By category: {stats['by_category']}")
        print(f"  By source: {stats['by_source']}")
        print(f"  By confidence: {stats['by_confidence']}")

        return stats
