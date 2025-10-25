import json
from pathlib import Path
from typing import Any, Dict
import requests


class MITRECollector:
    def __init__(self, output_dir: str = "./data/raw/mitre"):
        self.server_url = "https://cti-taxii.mitre.org/taxii/"
        self.api_root = "https://cti-taxii.mitre.org/stix/collections/"
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.collections = {
            "enterprise-attack": "95ecc380-afe9-11e4-9b6c-751b66dd541e",
            "mobile-attack": "2f669986-b40b-4423-b720-4396ca6a462b",
            "ics-attack": "02c3ef24-9cd4-48f3-a99f-b74ce24f1d34",
        }

    def collect_all(self) -> Dict[str, int]:
        stats = {}

        for collection_name, collection_id in self.collections.items():
            print(f"Collecting {collection_name}...")
            count = self.collect_collection(collection_name, collection_id)
            stats[collection_name] = count

        return stats

    def collect_collection(self, name: str, collection_id: str) -> int:
        try:
            url = f"{self.api_root}{collection_id}/"
            response = requests.get(url, headers={"Accept": "application/taxii+json;version=2.1"})

            if response.status_code != 200:
                print(f"Error: Status code {response.status_code}")
                return 0

            data = response.json()

            output_file = self.output_dir / f"{name}.json"
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

            if data.get("type") == "bundle":
                object_count = len(data.get("objects", []))
                print(f"Saved {object_count} objects to {output_file}")
                return object_count

            return 0

        except Exception as e:
            print(f"Error collecting {name}: {e}")
            return 0

    def collect_from_github(self) -> Dict[str, int]:
        base_url = "https://raw.githubusercontent.com/mitre/cti/master"
        collections = {
            "enterprise-attack": f"{base_url}/enterprise-attack/enterprise-attack.json",
            "mobile-attack": f"{base_url}/mobile-attack/mobile-attack.json",
            "ics-attack": f"{base_url}/ics-attack/ics-attack.json",
        }

        stats = {}

        for name, url in collections.items():
            try:
                print(f"Downloading {name} from GitHub...")
                response = requests.get(url, timeout=60)

                if response.status_code == 200:
                    data = response.json()

                    output_file = self.output_dir / f"{name}.json"
                    with open(output_file, "w", encoding="utf-8") as f:
                        json.dump(data, f, indent=2, ensure_ascii=False)

                    object_count = len(data.get("objects", []))
                    print(f"Saved {object_count} objects to {output_file}")
                    stats[name] = object_count
                else:
                    print(f"Error: Status code {response.status_code} for {name}")
                    stats[name] = 0

            except Exception as e:
                print(f"Error downloading {name}: {e}")
                stats[name] = 0

        return stats

    def get_statistics(self) -> Dict[str, Any]:
        stats = {
            "total_objects": 0,
            "by_type": {},
            "by_collection": {},
        }

        for collection_file in self.output_dir.glob("*.json"):
            with open(collection_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            collection_name = collection_file.stem
            objects = data.get("objects", [])

            stats["by_collection"][collection_name] = len(objects)
            stats["total_objects"] += len(objects)

            for obj in objects:
                obj_type = obj.get("type", "unknown")
                stats["by_type"][obj_type] = stats["by_type"].get(obj_type, 0) + 1

        return stats
