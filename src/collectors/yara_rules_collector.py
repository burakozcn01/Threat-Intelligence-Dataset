import json
import time
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict
import requests


class YARARulesCollector:
    def __init__(self, api_key: str = None, output_dir: str = "./data/raw/yara_rules"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.api_key = api_key or os.getenv("GITHUB_API_KEY")
        self.headers = {}
        if self.api_key:
            self.headers["Authorization"] = f"token {self.api_key}"

        self.repos = {
            "neo23x0": "https://api.github.com/repos/Neo23x0/signature-base/contents/yara",
        }

    def collect_all(self) -> Dict[str, int]:
        stats = {}

        print("Collecting Neo23x0 YARA rules...")
        stats["yara_rules"] = self.collect_yara_rules()

        return stats

    def collect_yara_rules(self) -> int:
        try:
            response = requests.get(self.repos["neo23x0"], headers=self.headers, timeout=30)

            if response.status_code == 200:
                contents = response.json()

                yara_rules = []

                apt_files = [f for f in contents if "apt" in f["name"].lower() and f["name"].endswith(".yar")][:15]

                for item in apt_files:
                    time.sleep(1)

                    file_response = requests.get(item["download_url"], headers=self.headers, timeout=30)

                    if file_response.status_code == 200:
                        yara_rules.append({
                            "filename": item["name"],
                            "source": "neo23x0-signature-base",
                            "url": item["download_url"],
                            "content": file_response.text[:10000],
                            "collected_at": datetime.utcnow().isoformat(),
                        })

                if yara_rules:
                    output_file = self.output_dir / "neo23x0_yara_rules.json"
                    with open(output_file, "w", encoding="utf-8") as f:
                        json.dump(yara_rules, f, indent=2, ensure_ascii=False)

                    print(f"Saved {len(yara_rules)} YARA rule files")
                    return len(yara_rules)

        except Exception as e:
            print(f"Error collecting YARA rules: {e}")

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
