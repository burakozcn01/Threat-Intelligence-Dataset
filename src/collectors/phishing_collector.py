import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict
import requests


class PhishingCollector:
    def __init__(self, api_key: str = None, output_dir: str = "./data/raw/phishing"):
        self.phishtank_api_key = api_key
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.feeds = {
            "openphish": "https://openphish.com/feed.txt",
            "phishtank": "http://data.phishtank.com/data/online-valid.csv",
            "phishing_army": "https://phishing.army/download/phishing_army_blocklist.txt",
        }

    def collect_all(self) -> Dict[str, int]:
        stats = {}

        print("Collecting OpenPhish feed...")
        stats["openphish"] = self.collect_openphish()
        time.sleep(2)

        print("Collecting PhishTank feed...")
        stats["phishtank"] = self.collect_phishtank()
        time.sleep(2)

        print("Collecting Phishing Army blocklist...")
        stats["phishing_army"] = self.collect_phishing_army()

        return stats

    def collect_openphish(self) -> int:
        try:
            response = requests.get(self.feeds["openphish"], timeout=60)

            if response.status_code == 200:
                urls = response.text.strip().split("\n")
                urls = [url.strip() for url in urls if url.strip()]

                data = [{"url": url, "source": "openphish", "collected_at": datetime.utcnow().isoformat()} for url in urls]

                output_file = self.output_dir / "openphish.json"
                with open(output_file, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)

                print(f"Saved {len(data)} OpenPhish URLs")
                return len(data)

        except Exception as e:
            print(f"Error collecting OpenPhish: {e}")

        return 0

    def collect_phishtank(self) -> int:
        try:
            response = requests.get(self.feeds["phishtank"], timeout=60)

            if response.status_code == 200:
                lines = response.text.strip().split("\n")

                if len(lines) > 1:
                    header = lines[0].split(",")
                    data = []

                    for line in lines[1:]:
                        if not line.strip():
                            continue

                        values = line.split(",")
                        if len(values) >= len(header):
                            entry = {header[i]: values[i].strip('"') for i in range(len(header))}
                            entry["source"] = "phishtank"
                            entry["collected_at"] = datetime.utcnow().isoformat()
                            data.append(entry)

                    output_file = self.output_dir / "phishtank.json"
                    with open(output_file, "w", encoding="utf-8") as f:
                        json.dump(data, f, indent=2, ensure_ascii=False)

                    print(f"Saved {len(data)} PhishTank entries")
                    return len(data)

        except Exception as e:
            print(f"Error collecting PhishTank: {e}")

        return 0

    def collect_phishing_army(self) -> int:
        try:
            response = requests.get(self.feeds["phishing_army"], timeout=60)

            if response.status_code == 200:
                domains = []

                for line in response.text.strip().split("\n"):
                    line = line.strip()
                    if line and not line.startswith("#"):
                        domains.append(line)

                data = [{"domain": domain, "source": "phishing_army", "collected_at": datetime.utcnow().isoformat()} for domain in domains]

                output_file = self.output_dir / "phishing_army.json"
                with open(output_file, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)

                print(f"Saved {len(data)} Phishing Army domains")
                return len(data)

        except Exception as e:
            print(f"Error collecting Phishing Army: {e}")

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
