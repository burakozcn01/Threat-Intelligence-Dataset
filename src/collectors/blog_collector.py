import json
import hashlib
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional
import feedparser
from bs4 import BeautifulSoup
from tqdm import tqdm


class BlogCollector:
    def __init__(self, output_dir: str = "./data/raw/blogs"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.sources = {
            "krebs": {
                "name": "Krebs on Security",
                "feed_url": "https://krebsonsecurity.com/feed/",
                "type": "rss"
            },
            "bleepingcomputer": {
                "name": "BleepingComputer",
                "feed_url": "https://www.bleepingcomputer.com/feed/",
                "type": "rss"
            },
            "darkreading": {
                "name": "Dark Reading",
                "feed_url": "https://www.darkreading.com/rss.xml",
                "type": "rss"
            },
            "securityaffairs": {
                "name": "Security Affairs",
                "feed_url": "https://securityaffairs.com/wordpress/feed",
                "type": "rss"
            },
            "threatpost": {
                "name": "Threatpost",
                "feed_url": "https://threatpost.com/feed/",
                "type": "rss"
            },
            "schneier": {
                "name": "Schneier on Security",
                "feed_url": "https://www.schneier.com/blog/atom.xml",
                "type": "atom"
            },
            "troyhunt": {
                "name": "Troy Hunt",
                "feed_url": "https://www.troyhunt.com/rss/",
                "type": "rss"
            },
            "grahamcluley": {
                "name": "Graham Cluley",
                "feed_url": "https://www.grahamcluley.com/feed/",
                "type": "rss"
            },
            "hackread": {
                "name": "HackRead",
                "feed_url": "https://www.hackread.com/feed/",
                "type": "rss"
            },
            "infosecurity": {
                "name": "Infosecurity Magazine",
                "feed_url": "http://www.infosecurity-magazine.com/rss/news/",
                "type": "rss"
            },
            "sans_isc": {
                "name": "SANS Internet Storm Center",
                "feed_url": "https://isc.sans.edu/rssfeed_full.xml",
                "type": "rss"
            },
            "nakedsecurity": {
                "name": "Sophos Naked Security",
                "feed_url": "https://nakedsecurity.sophos.com/feed/",
                "type": "rss"
            },
            "wired_security": {
                "name": "WIRED Security",
                "feed_url": "https://www.wired.com/feed/category/security/latest/rss",
                "type": "rss"
            },
            "zdnet_security": {
                "name": "ZDNet Security",
                "feed_url": "https://www.zdnet.com/topic/security/rss.xml",
                "type": "rss"
            },
            "arstechnica": {
                "name": "Ars Technica Security",
                "feed_url": "https://arstechnica.com/tag/security/feed/",
                "type": "rss"
            }
        }

        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }

    def collect_all(self) -> Dict[str, int]:
        stats = {}

        for source_id, source_config in tqdm(self.sources.items(), desc="Collecting blogs"):
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

            articles = []

            for entry in feed.entries[:50]:
                try:
                    article = self.parse_feed_entry(entry, source_id, config["name"])
                    if article:
                        articles.append(article)
                except Exception as e:
                    print(f"Error parsing entry: {e}")
                    continue

            if articles:
                output_file = self.output_dir / f"{source_id}.json"
                with open(output_file, "w", encoding="utf-8") as f:
                    json.dump(articles, f, indent=2, ensure_ascii=False)

                print(f"Saved {len(articles)} articles to {output_file}")
                return len(articles)

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

            article_id = hashlib.sha256(f"{source_id}:{link}".encode()).hexdigest()

            author = entry.get("author", "")
            if not author and hasattr(entry, "authors"):
                author = ", ".join([a.get("name", "") for a in entry.authors if a.get("name")])

            return {
                "id": article_id,
                "source": source_id,
                "source_name": source_name,
                "title": title,
                "url": link,
                "published_date": pub_date,
                "author": author,
                "description": description[:5000] if description else "",
                "tags": tags,
                "collected_at": datetime.utcnow().isoformat(),
                "content_type": "blog_article"
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
            "total_articles": 0,
            "by_source": {},
            "by_month": {},
            "total_tags": set()
        }

        for article_file in self.output_dir.glob("*.json"):
            try:
                with open(article_file, "r", encoding="utf-8") as f:
                    articles = json.load(f)

                source_name = article_file.stem
                count = len(articles)

                stats["by_source"][source_name] = count
                stats["total_articles"] += count

                for article in articles:
                    if article.get("published_date"):
                        month = article["published_date"][:7]
                        stats["by_month"][month] = stats["by_month"].get(month, 0) + 1

                    if article.get("tags"):
                        stats["total_tags"].update(article["tags"])

            except Exception as e:
                print(f"Error reading {article_file}: {e}")

        stats["total_tags"] = len(stats["total_tags"])

        return stats
