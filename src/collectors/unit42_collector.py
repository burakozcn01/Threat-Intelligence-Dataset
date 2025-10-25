import json
import time
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict
import requests


class Unit42Collector:
    def __init__(self, api_key: str = None, output_dir: str = "./data/raw/unit42"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.api_key = api_key or os.getenv("GITHUB_API_KEY")
        self.headers = {}
        if self.api_key:
            self.headers["Authorization"] = f"token {self.api_key}"

        self.repos = {
            "threat_intel": "https://api.github.com/repos/PaloAltoNetworks/Unit42-Threat-Intelligence-Article-Information/contents",
            "timely_intel": "https://api.github.com/repos/PaloAltoNetworks/Unit42-timely-threat-intel/contents",
        }

    def collect_all(self) -> Dict[str, int]:
        stats = {}

        print("Collecting Unit42 threat intelligence IOCs...")
        stats["threat_intel"] = self.collect_threat_intel()
        time.sleep(3)

        print("Collecting Unit42 timely threat intel...")
        stats["timely_intel"] = self.collect_timely_intel()

        return stats

    def collect_threat_intel(self) -> int:
        try:
            response = requests.get(self.repos["threat_intel"], headers=self.headers, timeout=30)

            if response.status_code == 200:
                contents = response.json()

                all_iocs = []

                for item in contents[:20]:
                    if item["type"] == "file" and item["name"].endswith(".txt"):
                        time.sleep(1)

                        file_response = requests.get(item["download_url"], headers=self.headers, timeout=30)

                        if file_response.status_code == 200:
                            all_iocs.append({
                                "filename": item["name"],
                                "source": "unit42-threat-intel",
                                "url": item["download_url"],
                                "content": file_response.text[:5000],
                                "collected_at": datetime.utcnow().isoformat(),
                            })

                if all_iocs:
                    output_file = self.output_dir / "unit42_threat_intel.json"
                    with open(output_file, "w", encoding="utf-8") as f:
                        json.dump(all_iocs, f, indent=2, ensure_ascii=False)

                    print(f"Saved {len(all_iocs)} Unit42 threat intel files")
                    return len(all_iocs)

        except Exception as e:
            print(f"Error collecting Unit42 threat intel: {e}")

        return 0

    def collect_timely_intel(self) -> int:
        try:
            response = requests.get(self.repos["timely_intel"], headers=self.headers, timeout=30)

            if response.status_code == 200:
                contents = response.json()

                all_iocs = []

                for item in contents[:20]:
                    if item["type"] == "file" and item["name"].endswith(".txt"):
                        time.sleep(1)

                        file_response = requests.get(item["download_url"], headers=self.headers, timeout=30)

                        if file_response.status_code == 200:
                            all_iocs.append({
                                "filename": item["name"],
                                "source": "unit42-timely-intel",
                                "url": item["download_url"],
                                "content": file_response.text[:5000],
                                "collected_at": datetime.utcnow().isoformat(),
                            })

                if all_iocs:
                    output_file = self.output_dir / "unit42_timely_intel.json"
                    with open(output_file, "w", encoding="utf-8") as f:
                        json.dump(all_iocs, f, indent=2, ensure_ascii=False)

                    print(f"Saved {len(all_iocs)} Unit42 timely intel files")
                    return len(all_iocs)

        except Exception as e:
            print(f"Error collecting Unit42 timely intel: {e}")

        return 0

    def get_statistics(self) -> Dict[str, Any]:
        stats = {"total_files": 0, "total_entries": 0, "files": {}}

        for json_file in self.output_dir.glob("*.json"):
            with open(json_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            count = len(data) if isinstance(data, list) else 1
            stats["files"][json_file.name] = count
            stats["total_entries"] += count
            stats["total_files"] += 1

        return stats
