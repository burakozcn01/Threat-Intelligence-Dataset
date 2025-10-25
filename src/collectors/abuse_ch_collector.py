import json
import time
from pathlib import Path
from typing import Any, Dict, List
import requests
from tqdm import tqdm


class AbuseChCollector:
    def __init__(self, output_dir: str = "./data/raw/abuse_ch"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.feeds = {
            "urlhaus": {
                "url": "https://urlhaus.abuse.ch/downloads/json/",
                "format": "json",
            },
            "urlhaus_recent": {
                "url": "https://urlhaus.abuse.ch/downloads/json_recent/",
                "format": "json",
            },
            "malwarebazaar_recent": {
                "url": "https://mb-api.abuse.ch/api/v1/",
                "format": "api",
            },
            "feodo_ipblocklist": {
                "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
                "format": "json",
            },
            "threatfox": {
                "url": "https://threatfox-api.abuse.ch/api/v1/",
                "format": "api",
            },
        }

    def collect_all(self) -> Dict[str, int]:
        stats = {}

        print("Collecting URLhaus data...")
        stats["urlhaus"] = self.collect_urlhaus()
        time.sleep(2)

        print("Collecting MalwareBazaar data...")
        stats["malwarebazaar"] = self.collect_malwarebazaar()
        time.sleep(2)

        print("Collecting Feodo Tracker data...")
        stats["feodo"] = self.collect_feodo()
        time.sleep(2)

        print("Collecting ThreatFox data...")
        stats["threatfox"] = self.collect_threatfox()

        return stats

    def collect_urlhaus(self) -> int:
        try:
            csv_url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
            response = requests.get(csv_url, timeout=60)

            if response.status_code == 200:
                lines = response.text.strip().split('\n')
                data = []

                for line in lines:
                    if line.startswith('#') or not line.strip():
                        continue

                    parts = line.strip().split('","')
                    if len(parts) >= 9:
                        parts = [p.strip('"') for p in parts]
                        data.append({
                            "id": parts[0],
                            "dateadded": parts[1],
                            "url": parts[2],
                            "url_status": parts[3],
                            "threat": parts[5] if len(parts) > 5 else "",
                            "tags": parts[6] if len(parts) > 6 else "",
                        })

                if data:
                    output_file = self.output_dir / "urlhaus_recent.json"
                    with open(output_file, "w", encoding="utf-8") as f:
                        json.dump(data[:1000], f, indent=2, ensure_ascii=False)

                    print(f"Saved {len(data[:1000])} URLhaus entries")
                    return len(data[:1000])

        except Exception as e:
            print(f"Error collecting URLhaus: {e}")

        return 0

    def collect_urlhaus_recent(self) -> int:
        try:
            response = requests.get(self.feeds["urlhaus_recent"]["url"], timeout=60)

            if response.status_code == 200:
                data = response.json()

                output_file = self.output_dir / "urlhaus_recent.json"
                with open(output_file, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)

                count = len(data) if isinstance(data, list) else 1
                print(f"Saved {count} recent URLhaus entries")
                return count

        except Exception as e:
            print(f"Error collecting URLhaus recent: {e}")

        return 0

    def collect_malwarebazaar(self) -> int:
        try:
            data = {"query": "get_recent", "selector": 100}

            response = requests.post(
                self.feeds["malwarebazaar_recent"]["url"],
                json=data,
                headers={"Content-Type": "application/json"},
                timeout=30,
            )

            if response.status_code == 200:
                result = response.json()

                output_file = self.output_dir / "malwarebazaar_recent.json"
                with open(output_file, "w", encoding="utf-8") as f:
                    json.dump(result, f, indent=2, ensure_ascii=False)

                samples = result.get("data", [])
                print(f"Saved {len(samples)} MalwareBazaar samples")
                return len(samples)

        except Exception as e:
            print(f"Error collecting MalwareBazaar: {e}")

        return 0

    def collect_malwarebazaar_by_tag(self, tag: str) -> int:
        try:
            data = {"query": "get_taginfo", "tag": tag, "limit": 100}

            response = requests.post(
                self.feeds["malwarebazaar_recent"]["url"],
                json=data,
                headers={"Content-Type": "application/json"},
                timeout=30,
            )

            if response.status_code == 200:
                result = response.json()

                output_file = self.output_dir / f"malwarebazaar_tag_{tag}.json"
                with open(output_file, "w", encoding="utf-8") as f:
                    json.dump(result, f, indent=2, ensure_ascii=False)

                samples = result.get("data", [])
                return len(samples)

        except Exception as e:
            print(f"Error collecting tag {tag}: {e}")

        return 0

    def collect_feodo(self) -> int:
        try:
            response = requests.get(self.feeds["feodo_ipblocklist"]["url"], timeout=30)

            if response.status_code == 200:
                data = response.json()

                output_file = self.output_dir / "feodo_tracker.json"
                with open(output_file, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)

                count = len(data) if isinstance(data, list) else 1
                print(f"Saved {count} Feodo Tracker entries")
                return count

        except Exception as e:
            print(f"Error collecting Feodo: {e}")

        return 0

    def collect_threatfox(self) -> int:
        try:
            data = {"query": "get_iocs", "days": 7}

            response = requests.post(
                self.feeds["threatfox"]["url"],
                json=data,
                headers={"Content-Type": "application/json"},
                timeout=30,
            )

            if response.status_code == 200:
                result = response.json()

                output_file = self.output_dir / "threatfox_recent.json"
                with open(output_file, "w", encoding="utf-8") as f:
                    json.dump(result, f, indent=2, ensure_ascii=False)

                iocs = result.get("data", [])
                print(f"Saved {len(iocs)} ThreatFox IOCs")
                return len(iocs)

        except Exception as e:
            print(f"Error collecting ThreatFox: {e}")

        return 0

    def collect_malware_tags(self, tags: List[str]) -> Dict[str, int]:
        stats = {}

        for tag in tqdm(tags, desc="Collecting malware tags"):
            count = self.collect_malwarebazaar_by_tag(tag)
            stats[tag] = count
            time.sleep(2)

        return stats

    def get_statistics(self) -> Dict[str, Any]:
        stats = {"total_files": 0, "total_entries": 0, "files": {}}

        for json_file in self.output_dir.glob("*.json"):
            with open(json_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            if isinstance(data, list):
                count = len(data)
            elif isinstance(data, dict):
                count = len(data.get("data", []))
            else:
                count = 1

            stats["files"][json_file.name] = count
            stats["total_entries"] += count
            stats["total_files"] += 1

        return stats
