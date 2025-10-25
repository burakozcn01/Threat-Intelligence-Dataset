import json
import hashlib
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional
import feedparser
from bs4 import BeautifulSoup
from tqdm import tqdm


class ReportCollector:
    def __init__(self, output_dir: str = "./data/raw/reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.sources = {
            "kaspersky": {
                "name": "Kaspersky SecureList",
                "feed_url": "https://securelist.com/feed/",
                "type": "rss"
            },
            "checkpoint": {
                "name": "Check Point Research",
                "feed_url": "https://research.checkpoint.com/feed/",
                "type": "rss"
            },
            "crowdstrike": {
                "name": "CrowdStrike Threat Intel",
                "feed_url": "https://www.crowdstrike.com/blog/category/threat-intel-research/feed/",
                "type": "rss"
            },
            "microsoft": {
                "name": "Microsoft Security",
                "feed_url": "https://www.microsoft.com/security/blog/feed/",
                "type": "rss"
            },
            "paloalto_unit42": {
                "name": "Palo Alto Unit 42",
                "feed_url": "https://researchcenter.paloaltonetworks.com/unit42/feed/",
                "type": "rss"
            },
            "talos": {
                "name": "Cisco Talos Intelligence",
                "feed_url": "https://feeds.feedburner.com/feedburner/Talos",
                "type": "rss"
            },
            "sentinelone": {
                "name": "SentinelOne Labs",
                "feed_url": "https://www.sentinelone.com/labs/feed/",
                "type": "rss"
            },
            "eset": {
                "name": "ESET WeLiveSecurity",
                "feed_url": "https://www.welivesecurity.com/en/rss/feed/",
                "type": "rss"
            },
            "dfir_report": {
                "name": "The DFIR Report",
                "feed_url": "https://thedfirreport.com/feed/",
                "type": "rss"
            },
            "malwarebytes": {
                "name": "Malwarebytes Labs",
                "feed_url": "https://www.malwarebytes.com/blog/feed",
                "type": "rss"
            }
        }

        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }

    def collect_all(self) -> Dict[str, int]:
        stats = {}

        for source_id, source_config in tqdm(self.sources.items(), desc="Collecting reports"):
            try:
                print(f"\nCollecting from {source_config['name']}...")
                count = self.collect_source(source_id, source_config)
                stats[source_id] = count
                time.sleep(2)
            except Exception as e:
                print(f"Error collecting {source_id}: {e}")
                stats[source_id] = 0

        return stats

    def collect_source(self, source_id: str, config: Dict[str, Any]) -> int:
        try:
            feed = feedparser.parse(config["feed_url"])

            if not feed.entries:
                print(f"No entries found for {source_id}")
                return 0

            reports = []

            for entry in feed.entries[:50]:
                try:
                    report = self.parse_feed_entry(entry, source_id, config["name"])
                    if report:
                        reports.append(report)
                except Exception as e:
                    print(f"Error parsing entry: {e}")
                    continue

            if reports:
                output_file = self.output_dir / f"{source_id}.json"
                with open(output_file, "w", encoding="utf-8") as f:
                    json.dump(reports, f, indent=2, ensure_ascii=False)

                print(f"Saved {len(reports)} reports to {output_file}")
                return len(reports)

            return 0

        except Exception as e:
            print(f"Error collecting source {source_id}: {e}")
            return 0

    def parse_feed_entry(self, entry: Any, source_id: str, source_name: str) -> Optional[Dict[str, Any]]:
        try:
            title = entry.get("title", "").strip()
            link = entry.get("link", "").strip()

            if not title or not link:
                return None

            published = entry.get("published_parsed") or entry.get("updated_parsed")
            pub_date = None
            if published:
                pub_date = datetime(*published[:6]).isoformat()

            summary = entry.get("summary", "")
            content = entry.get("content", [{}])[0].get("value", "") if entry.get("content") else summary

            description = self.clean_html(content if content else summary)

            tags = []
            if hasattr(entry, "tags"):
                tags = [tag.term for tag in entry.tags if hasattr(tag, "term")]

            categories = entry.get("categories", [])
            if categories:
                tags.extend([cat[0] if isinstance(cat, tuple) else cat for cat in categories])

            tags = list(set([tag.lower().strip() for tag in tags if tag]))

            report_id = hashlib.sha256(f"{source_id}:{link}".encode()).hexdigest()

            author = entry.get("author", "")
            if not author and hasattr(entry, "authors"):
                author = ", ".join([a.get("name", "") for a in entry.authors if a.get("name")])

            return {
                "id": report_id,
                "source": source_id,
                "source_name": source_name,
                "title": title,
                "url": link,
                "published_date": pub_date,
                "author": author,
                "description": description[:5000] if description else "",
                "tags": tags,
                "collected_at": datetime.utcnow().isoformat(),
                "report_type": "security_research"
            }

        except Exception as e:
            print(f"Error parsing entry: {e}")
            return None

    def clean_html(self, html_content: str) -> str:
        if not html_content:
            return ""

        try:
            soup = BeautifulSoup(html_content, "html.parser")

            for tag in soup(["script", "style", "img", "iframe"]):
                tag.decompose()

            text = soup.get_text(separator=" ", strip=True)

            text = " ".join(text.split())

            return text
        except Exception as e:
            return html_content

    def get_statistics(self) -> Dict[str, Any]:
        stats = {
            "total_reports": 0,
            "by_source": {},
            "by_month": {},
            "total_tags": set()
        }

        for report_file in self.output_dir.glob("*.json"):
            try:
                with open(report_file, "r", encoding="utf-8") as f:
                    reports = json.load(f)

                source_name = report_file.stem
                count = len(reports)

                stats["by_source"][source_name] = count
                stats["total_reports"] += count

                for report in reports:
                    if report.get("published_date"):
                        month = report["published_date"][:7]
                        stats["by_month"][month] = stats["by_month"].get(month, 0) + 1

                    if report.get("tags"):
                        stats["total_tags"].update(report["tags"])

            except Exception as e:
                print(f"Error reading {report_file}: {e}")

        stats["total_tags"] = len(stats["total_tags"])

        return stats
