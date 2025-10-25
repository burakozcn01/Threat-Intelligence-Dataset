import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict
import feedparser


class CERTAdvisoriesCollector:
    def __init__(self, output_dir: str = "./data/raw/cert_advisories"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.feeds = {
            "jpcert_alerts": "https://www.jpcert.or.jp/rss/jpcert.rdf",
            "jpcert_weekly": "https://www.jpcert.or.jp/english/rss/jpcert_e.rdf",
            "jvn": "http://jvn.jp/en/rss/jvn.rdf",
            "jvndb": "http://jvndb.jvn.jp/en/rss/jvndb_new.rdf",
        }

    def collect_all(self) -> Dict[str, int]:
        stats = {}

        print("Collecting JPCERT alerts...")
        stats["jpcert_alerts"] = self.collect_jpcert_alerts()
        time.sleep(2)

        print("Collecting JPCERT weekly reports...")
        stats["jpcert_weekly"] = self.collect_jpcert_weekly()
        time.sleep(2)

        print("Collecting JVN advisories...")
        stats["jvn"] = self.collect_jvn()
        time.sleep(2)

        print("Collecting JVNDB vulnerabilities...")
        stats["jvndb"] = self.collect_jvndb()

        return stats

    def collect_jpcert_alerts(self) -> int:
        try:
            feed = feedparser.parse(self.feeds["jpcert_alerts"])

            entries = []
            for entry in feed.entries:
                entries.append({
                    "title": entry.get("title", ""),
                    "link": entry.get("link", ""),
                    "published": entry.get("published", ""),
                    "summary": entry.get("summary", ""),
                    "source": "jpcert-alerts",
                    "collected_at": datetime.utcnow().isoformat(),
                })

            if entries:
                output_file = self.output_dir / "jpcert_alerts.json"
                with open(output_file, "w", encoding="utf-8") as f:
                    json.dump(entries, f, indent=2, ensure_ascii=False)

                print(f"Saved {len(entries)} JPCERT alerts")
                return len(entries)

        except Exception as e:
            print(f"Error collecting JPCERT alerts: {e}")

        return 0

    def collect_jpcert_weekly(self) -> int:
        try:
            feed = feedparser.parse(self.feeds["jpcert_weekly"])

            entries = []
            for entry in feed.entries:
                entries.append({
                    "title": entry.get("title", ""),
                    "link": entry.get("link", ""),
                    "published": entry.get("published", ""),
                    "summary": entry.get("summary", ""),
                    "source": "jpcert-weekly",
                    "collected_at": datetime.utcnow().isoformat(),
                })

            if entries:
                output_file = self.output_dir / "jpcert_weekly.json"
                with open(output_file, "w", encoding="utf-8") as f:
                    json.dump(entries, f, indent=2, ensure_ascii=False)

                print(f"Saved {len(entries)} JPCERT weekly reports")
                return len(entries)

        except Exception as e:
            print(f"Error collecting JPCERT weekly: {e}")

        return 0

    def collect_jvn(self) -> int:
        try:
            feed = feedparser.parse(self.feeds["jvn"])

            entries = []
            for entry in feed.entries:
                entries.append({
                    "title": entry.get("title", ""),
                    "link": entry.get("link", ""),
                    "published": entry.get("published", ""),
                    "summary": entry.get("summary", ""),
                    "source": "jvn",
                    "collected_at": datetime.utcnow().isoformat(),
                })

            if entries:
                output_file = self.output_dir / "jvn_advisories.json"
                with open(output_file, "w", encoding="utf-8") as f:
                    json.dump(entries, f, indent=2, ensure_ascii=False)

                print(f"Saved {len(entries)} JVN advisories")
                return len(entries)

        except Exception as e:
            print(f"Error collecting JVN: {e}")

        return 0

    def collect_jvndb(self) -> int:
        try:
            feed = feedparser.parse(self.feeds["jvndb"])

            entries = []
            for entry in feed.entries:
                entries.append({
                    "title": entry.get("title", ""),
                    "link": entry.get("link", ""),
                    "published": entry.get("published", ""),
                    "summary": entry.get("summary", ""),
                    "source": "jvndb",
                    "collected_at": datetime.utcnow().isoformat(),
                })

            if entries:
                output_file = self.output_dir / "jvndb_vulns.json"
                with open(output_file, "w", encoding="utf-8") as f:
                    json.dump(entries, f, indent=2, ensure_ascii=False)

                print(f"Saved {len(entries)} JVNDB vulnerabilities")
                return len(entries)

        except Exception as e:
            print(f"Error collecting JVNDB: {e}")

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
