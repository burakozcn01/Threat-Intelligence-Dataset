import json
import time
from pathlib import Path
from typing import Any, Dict
import requests


class RansomwareLiveCollector:
    def __init__(self, output_dir: str = "./data/raw/ransomware_live"):
        self.base_url = "https://data.ransomware.live"
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def collect_all(self) -> Dict[str, int]:
        stats = {}

        print("Collecting all ransomware victims...")
        stats["victims"] = self.collect_all_victims()
        time.sleep(2)

        print("Collecting ransomware groups...")
        stats["groups"] = self.collect_all_groups()
        time.sleep(2)

        print("Collecting recent attacks...")
        stats["recent_attacks"] = self.collect_recent_attacks()

        return stats

    def collect_all_victims(self) -> int:
        try:
            response = requests.get(f"{self.base_url}/victims.json", timeout=60)

            if response.status_code == 200:
                data = response.json()

                if isinstance(data, list):
                    data = data[:500]

                output_file = self.output_dir / "all_victims.json"
                with open(output_file, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)

                count = len(data) if isinstance(data, list) else 0
                print(f"Saved {count} ransomware victims")
                return count

        except Exception as e:
            print(f"Error collecting victims: {e}")

        return 0

    def collect_all_groups(self) -> int:
        try:
            response = requests.get(f"{self.base_url}/groups.json", timeout=30)

            if response.status_code == 200:
                data = response.json()

                output_file = self.output_dir / "all_groups.json"
                with open(output_file, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)

                count = len(data) if isinstance(data, list) else 0
                print(f"Saved {count} ransomware groups")
                return count

        except Exception as e:
            print(f"Error collecting groups: {e}")

        return 0

    def collect_recent_attacks(self, days: int = 30) -> int:
        try:
            response = requests.get(f"{self.base_url}/victims.json", timeout=30)

            if response.status_code == 200:
                data = response.json()

                if isinstance(data, list):
                    data = data[:100]

                output_file = self.output_dir / "recent_attacks.json"
                with open(output_file, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)

                count = len(data) if isinstance(data, list) else 0
                print(f"Saved {count} recent attacks")
                return count

        except Exception as e:
            print(f"Error collecting recent attacks: {e}")

        return 0

    def collect_group_details(self, group_name: str) -> Dict[str, Any]:
        try:
            response = requests.get(f"{self.base_url}/group/{group_name}", timeout=30)

            if response.status_code == 200:
                return response.json()

        except Exception as e:
            print(f"Error collecting group {group_name}: {e}")

        return {}

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
