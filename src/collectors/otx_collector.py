import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
import requests
from tqdm import tqdm


class OTXCollector:
    def __init__(self, api_key: Optional[str] = None, output_dir: str = "./data/raw/otx"):
        self.api_key = api_key
        self.base_url = "https://otx.alienvault.com/api/v1"
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.session = requests.Session()

        if self.api_key:
            self.session.headers.update({"X-OTX-API-KEY": self.api_key})

    def collect_pulses(
        self, limit: int = 1000, modified_since: Optional[str] = None
    ) -> Dict[str, int]:
        pulses = []
        page = 1
        total_collected = 0

        print(f"Collecting OTX pulses (limit: {limit})...")

        params = {"limit": 50, "page": page}
        if modified_since:
            params["modified_since"] = modified_since

        while total_collected < limit:
            try:
                response = self.session.get(
                    f"{self.base_url}/pulses/subscribed", params=params, timeout=30
                )

                if response.status_code != 200:
                    print(f"Error: Status code {response.status_code}")
                    break

                data = response.json()
                results = data.get("results", [])

                if not results:
                    break

                pulses.extend(results)
                total_collected += len(results)

                print(f"Collected {total_collected} pulses...")

                if not data.get("next"):
                    break

                page += 1
                params["page"] = page
                time.sleep(0.6)

            except Exception as e:
                print(f"Error collecting pulses: {e}")
                break

        output_file = self.output_dir / f"pulses_{datetime.now().strftime('%Y%m%d')}.json"
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(pulses, f, indent=2, ensure_ascii=False)

        print(f"Saved {len(pulses)} pulses to {output_file}")
        return {"pulses": len(pulses)}

    def collect_pulse_details(self, pulse_id: str) -> Optional[Dict[str, Any]]:
        try:
            response = self.session.get(f"{self.base_url}/pulses/{pulse_id}", timeout=30)

            if response.status_code == 200:
                return response.json()

        except Exception as e:
            print(f"Error fetching pulse {pulse_id}: {e}")

        return None

    def collect_indicators(self, indicator_type: str = "domain", limit: int = 1000) -> int:
        indicators = []
        page = 1
        total_collected = 0

        print(f"Collecting {indicator_type} indicators...")

        while total_collected < limit:
            try:
                params = {"limit": 50, "page": page}
                response = self.session.get(
                    f"{self.base_url}/indicators/{indicator_type}", params=params, timeout=30
                )

                if response.status_code != 200:
                    break

                data = response.json()
                results = data.get("results", [])

                if not results:
                    break

                indicators.extend(results)
                total_collected += len(results)

                if not data.get("next"):
                    break

                page += 1
                time.sleep(0.6)

            except Exception as e:
                print(f"Error: {e}")
                break

        if indicators:
            output_file = (
                self.output_dir / f"indicators_{indicator_type}_{datetime.now().strftime('%Y%m%d')}.json"
            )
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(indicators, f, indent=2, ensure_ascii=False)

            print(f"Saved {len(indicators)} {indicator_type} indicators")

        return len(indicators)

    def search_pulses(self, query: str, limit: int = 100) -> List[Dict[str, Any]]:
        results = []
        page = 1

        while len(results) < limit:
            try:
                params = {"q": query, "page": page, "limit": 20}
                response = self.session.get(f"{self.base_url}/search/pulses", params=params, timeout=30)

                if response.status_code != 200:
                    break

                data = response.json()
                page_results = data.get("results", [])

                if not page_results:
                    break

                results.extend(page_results)

                if not data.get("next"):
                    break

                page += 1
                time.sleep(0.6)

            except Exception as e:
                print(f"Error searching: {e}")
                break

        return results[:limit]

    def collect_malware_families(self, families: List[str]) -> Dict[str, int]:
        stats = {}

        for family in tqdm(families, desc="Collecting malware families"):
            pulses = self.search_pulses(family, limit=100)

            if pulses:
                output_file = self.output_dir / f"malware_{family.lower().replace(' ', '_')}.json"
                with open(output_file, "w", encoding="utf-8") as f:
                    json.dump(pulses, f, indent=2, ensure_ascii=False)

                stats[family] = len(pulses)
            else:
                stats[family] = 0

            time.sleep(1)

        return stats

    def get_statistics(self) -> Dict[str, Any]:
        stats = {"total_files": 0, "total_pulses": 0, "files": {}}

        for json_file in self.output_dir.glob("*.json"):
            with open(json_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            count = len(data) if isinstance(data, list) else 1
            stats["files"][json_file.name] = count
            stats["total_pulses"] += count
            stats["total_files"] += 1

        return stats
