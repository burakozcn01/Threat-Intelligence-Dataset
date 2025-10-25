import json
from pathlib import Path
from typing import Any, Dict
import requests


class CISAKEVCollector:
    def __init__(self, output_dir: str = "./data/raw/cisa_kev"):
        self.kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def collect_all(self) -> Dict[str, int]:
        stats = {}

        print("Collecting CISA Known Exploited Vulnerabilities...")
        stats["kev"] = self.collect_kev()

        return stats

    def collect_kev(self) -> int:
        try:
            response = requests.get(self.kev_url, timeout=60)

            if response.status_code == 200:
                data = response.json()

                output_file = self.output_dir / "known_exploited_vulnerabilities.json"
                with open(output_file, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)

                vulnerabilities = data.get("vulnerabilities", [])
                print(f"Saved {len(vulnerabilities)} CISA KEV entries")
                return len(vulnerabilities)

        except Exception as e:
            print(f"Error collecting CISA KEV: {e}")

        return 0

    def get_statistics(self) -> Dict[str, Any]:
        stats = {"total_files": 0, "total_entries": 0, "files": {}}

        for json_file in self.output_dir.glob("*.json"):
            with open(json_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            if isinstance(data, dict) and "vulnerabilities" in data:
                count = len(data["vulnerabilities"])
            elif isinstance(data, list):
                count = len(data)
            else:
                count = 1

            stats["files"][json_file.name] = count
            stats["total_entries"] += count
            stats["total_files"] += 1

        return stats
