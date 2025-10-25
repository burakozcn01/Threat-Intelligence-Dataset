import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict
import feedparser
from .utils import retry_on_failure


class ICSCERTCollector:
    def __init__(self, output_dir: str = "./data/raw/ics_cert"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.feeds = {
            "cisa_ics": "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml",
        }

    def collect_all(self) -> Dict[str, int]:
        stats = {}

        print("Collecting ICS-CERT advisories from RSS feed...")
        stats["ics_advisories"] = self.collect_ics_advisories()

        return stats

    @retry_on_failure(max_retries=3, delay=3)
    def collect_ics_advisories(self) -> int:
        try:
            feed = feedparser.parse(self.feeds["cisa_ics"])

            if not feed.entries:
                print("No entries found in ICS-CERT feed")
                return 0

            entries = []
            for entry in feed.entries[:100]:
                entries.append({
                    "title": entry.get("title", ""),
                    "link": entry.get("link", ""),
                    "published": entry.get("published", ""),
                    "summary": entry.get("summary", ""),
                    "source": "cisa-ics",
                    "collected_at": datetime.utcnow().isoformat(),
                })

            if entries:
                output_file = self.output_dir / "ics_advisories.json"
                with open(output_file, "w", encoding="utf-8") as f:
                    json.dump(entries, f, indent=2, ensure_ascii=False)

                print(f"Saved {len(entries)} ICS advisories from RSS feed")
                return len(entries)

        except Exception as e:
            print(f"Error collecting ICS advisories: {e}")
            raise

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
