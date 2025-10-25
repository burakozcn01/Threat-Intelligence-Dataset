import json
import time
from pathlib import Path
from typing import Any, Dict
import requests


class DShieldCollector:
    def __init__(self, output_dir: str = "./data/raw/dshield"):
        self.base_url = "https://isc.sans.edu"
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.feeds = {
            "top_ips": f"{self.base_url}/api/sources/attacks/10000/2023-01-01",
            "ssh_usernames": f"{self.base_url}/sshallusernames.json",
            "webhoneypot": f"{self.base_url}/api/webhoneypot/",
        }

    def collect_all(self) -> Dict[str, int]:
        stats = {}

        print("Collecting DShield SSH usernames...")
        stats["ssh_usernames"] = self.collect_ssh_usernames()
        time.sleep(2)

        print("Collecting DShield top IPs...")
        stats["top_ips"] = self.collect_top_ips()

        return stats

    def collect_ssh_usernames(self) -> int:
        try:
            response = requests.get(self.feeds["ssh_usernames"], timeout=30)

            if response.status_code == 200:
                data = response.json()

                output_file = self.output_dir / "ssh_usernames.json"
                with open(output_file, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)

                usernames = data.get("data", [])
                print(f"Saved {len(usernames)} SSH usernames")
                return len(usernames)

        except Exception as e:
            print(f"Error collecting SSH usernames: {e}")

        return 0

    def collect_top_ips(self) -> int:
        try:
            response = requests.get(f"{self.base_url}/api/topips/records/100", timeout=30)

            if response.status_code == 200:
                data = response.json()

                output_file = self.output_dir / "top_ips.json"
                with open(output_file, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)

                ips = data if isinstance(data, list) else []
                print(f"Saved {len(ips)} top attacking IPs")
                return len(ips)

        except Exception as e:
            print(f"Error collecting top IPs: {e}")

        return 0

    def get_statistics(self) -> Dict[str, Any]:
        stats = {"total_files": 0, "total_entries": 0, "files": {}}

        for json_file in self.output_dir.glob("*.json"):
            with open(json_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            if isinstance(data, dict):
                count = len(data.get("data", []))
            elif isinstance(data, list):
                count = len(data)
            else:
                count = 1

            stats["files"][json_file.name] = count
            stats["total_entries"] += count
            stats["total_files"] += 1

        return stats
