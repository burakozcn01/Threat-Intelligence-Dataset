import json
import time
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict
import requests
from .utils import retry_on_failure


class GitHubIOCCollector:
    def __init__(self, api_key: str = None, output_dir: str = "./data/raw/github_ioc"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.api_key = api_key or os.getenv("GITHUB_API_KEY")
        self.headers = {}
        if self.api_key:
            self.headers["Authorization"] = f"token {self.api_key}"
            self.headers["Accept"] = "application/vnd.github.v3+json"

        self.repos = {
            "eset_malware": {
                "base": "https://api.github.com/repos/eset/malware-ioc/contents",
                "type": "github_api",
            },
            "apt_campaigns": {
                "base": "https://raw.githubusercontent.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/master",
                "type": "raw",
            },
        }

    def collect_all(self) -> Dict[str, int]:
        stats = {}

        print("Collecting APT Campaign reports from CyberMonitor...")
        stats["apt_campaigns"] = self.collect_apt_campaigns()
        time.sleep(3)

        print("Collecting ESET malware IOCs...")
        stats["eset_iocs"] = self.collect_eset_iocs()
        time.sleep(3)

        return stats

    @retry_on_failure(max_retries=3, delay=3)
    def collect_apt_campaigns(self) -> int:
        try:
            csv_url = "https://raw.githubusercontent.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections/master/index.csv"
            response = requests.get(csv_url, headers=self.headers, timeout=30)

            if response.status_code == 200:
                lines = response.text.strip().split('\n')
                campaigns = []

                for i, line in enumerate(lines):
                    if i == 0:
                        continue

                    parts = line.split(',')
                    if len(parts) >= 4:
                        campaigns.append({
                            "published": parts[0].strip(),
                            "sha1": parts[1].strip(),
                            "filename": parts[2].strip(),
                            "url": parts[3].strip(),
                            "source": "cybermonitor-apt",
                            "collected_at": datetime.utcnow().isoformat(),
                        })

                if campaigns:
                    output_file = self.output_dir / "apt_campaigns.json"
                    with open(output_file, "w", encoding="utf-8") as f:
                        json.dump(campaigns, f, indent=2, ensure_ascii=False)

                    print(f"Saved {len(campaigns)} APT campaign reports")
                    return len(campaigns)

        except Exception as e:
            print(f"Error collecting APT campaigns: {e}")
            raise

        return 0

    @retry_on_failure(max_retries=3, delay=3)
    def collect_eset_iocs(self) -> int:
        try:
            response = requests.get(self.repos["eset_malware"]["base"], headers=self.headers, timeout=30)

            if response.status_code == 200:
                contents = response.json()

                all_iocs = []

                dir_folders = [item for item in contents if item["type"] == "dir"]

                for item in dir_folders[:10]:
                    time.sleep(2)
                    dir_response = requests.get(item["url"], headers=self.headers, timeout=30)

                    if dir_response.status_code == 200:
                        dir_contents = dir_response.json()
                        hash_files = [f for f in dir_contents if f["name"].endswith((".md5", ".sha1", ".sha256"))]

                        for file_item in hash_files[:3]:
                            time.sleep(1)
                            file_response = requests.get(file_item["download_url"], headers=self.headers, timeout=30)

                            if file_response.status_code == 200:
                                hashes = file_response.text.strip().split('\n')

                                all_iocs.append({
                                    "source": "eset",
                                    "campaign": item["name"],
                                    "filename": file_item["name"],
                                    "hash_type": file_item["name"].split('.')[-1],
                                    "hashes": [h.strip() for h in hashes if h.strip() and not h.startswith('#')][:50],
                                    "collected_at": datetime.utcnow().isoformat(),
                                })

                if all_iocs:
                    output_file = self.output_dir / "eset_malware_iocs.json"
                    with open(output_file, "w", encoding="utf-8") as f:
                        json.dump(all_iocs, f, indent=2, ensure_ascii=False)

                    total_hashes = sum(len(ioc.get("hashes", [])) for ioc in all_iocs)
                    print(f"Saved {len(all_iocs)} ESET malware campaigns with {total_hashes} IOC hashes")
                    return len(all_iocs)
                else:
                    print("No ESET IOCs collected")
                    return 0

        except Exception as e:
            print(f"Error collecting ESET IOCs: {e}")

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
