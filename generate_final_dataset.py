#!/usr/bin/env python3

import os
import time
from src.pipeline import CTIDatasetPipeline
from src.collectors import (
    MITRECollector,
    OTXCollector,
    AbuseChCollector,
    RansomwareLiveCollector,
    PhishingCollector,
    CISAKEVCollector,
    GitHubIOCCollector,
    CERTAdvisoriesCollector,
    Unit42Collector,
    YARARulesCollector,
    ICSCERTCollector,
)

def collect_all_data():
    print("=" * 80)
    print("STEP 1: COLLECTING DATA FROM ALL 11 SOURCES")
    print("=" * 80)

    total_stats = {}

    print("\n[1/11] MITRE ATT&CK...")
    mitre = MITRECollector()
    total_stats["mitre"] = mitre.collect_from_github()
    print(f"MITRE: {sum(total_stats['mitre'].values())} collected")
    time.sleep(2)

    print("\n[2/11] AlienVault OTX...")
    otx = OTXCollector(api_key=os.getenv("OTX_API_KEY"))
    total_stats["otx"] = otx.collect_pulses(limit=1000)
    print(f"OTX: {total_stats['otx'].get('pulses', 0)} collected")
    time.sleep(2)

    print("\n[3/11] Abuse.ch...")
    abuse = AbuseChCollector()
    total_stats["abuse_ch"] = abuse.collect_all()
    print(f"Abuse.ch: {sum(total_stats['abuse_ch'].values())} collected")
    time.sleep(2)

    print("\n[4/11] Ransomware.live...")
    ransomware = RansomwareLiveCollector()
    total_stats["ransomware"] = ransomware.collect_all()
    print(f"Ransomware.live: {sum(total_stats['ransomware'].values())} collected")
    time.sleep(2)

    print("\n[5/11] Phishing Feeds...")
    phishing = PhishingCollector()
    total_stats["phishing"] = phishing.collect_all()
    print(f"Phishing: {sum(total_stats['phishing'].values())} collected")
    time.sleep(2)

    print("\n[6/11] CISA KEV...")
    cisa = CISAKEVCollector()
    total_stats["cisa_kev"] = cisa.collect_all()
    print(f"CISA KEV: {sum(total_stats['cisa_kev'].values())} collected")
    time.sleep(2)

    print("\n[7/11] GitHub IOCs (APT Campaigns)...")
    github = GitHubIOCCollector(api_key=os.getenv("GITHUB_API_KEY"))
    total_stats["github_ioc"] = github.collect_all()
    print(f"GitHub IOCs: {sum(total_stats['github_ioc'].values())} collected")
    time.sleep(2)

    print("\n[8/11] CERT Advisories (JPCERT)...")
    cert = CERTAdvisoriesCollector()
    total_stats["cert"] = cert.collect_all()
    print(f"CERT: {sum(total_stats['cert'].values())} collected")
    time.sleep(2)

    print("\n[9/11] Unit42 IOCs...")
    unit42 = Unit42Collector()
    total_stats["unit42"] = unit42.collect_all()
    print(f"Unit42: {sum(total_stats['unit42'].values())} collected")
    time.sleep(2)

    print("\n[10/11] YARA Rules (Neo23x0)...")
    yara = YARARulesCollector()
    total_stats["yara"] = yara.collect_all()
    print(f"YARA: {sum(total_stats['yara'].values())} collected")
    time.sleep(2)

    print("\n[11/11] ICS-CERT Advisories...")
    ics_cert = ICSCERTCollector()
    total_stats["ics_cert"] = ics_cert.collect_all()
    print(f"ICS-CERT: {sum(total_stats['ics_cert'].values())} collected")

    grand_total = sum(sum(v.values()) if isinstance(v, dict) else v for v in total_stats.values())
    print(f"\n✓ Data Collection Complete: {grand_total:,} entries from 11 sources")

    return total_stats

def main():
    print("=" * 80)
    print("COMPLETE CTI DATASET GENERATION PIPELINE")
    print("TARGET: 300K HIGH-QUALITY INSTRUCTION-TUNING EXAMPLES")
    print("=" * 80)

    collection_stats = collect_all_data()

    print("\n" + "=" * 80)
    print("STEP 2: PROCESSING AND GENERATING DATASET")
    print("=" * 80)

    pipeline = CTIDatasetPipeline(output_dir="./output/final")
    stats = pipeline.run_full_pipeline(target_count=300000, skip_collection=True)

    print("\n" + "=" * 80)
    print("PIPELINE COMPLETED SUCCESSFULLY!")
    print("=" * 80)
    print(f"\nCollection Statistics:")
    for source, count in collection_stats.items():
        total = sum(count.values()) if isinstance(count, dict) else count
        print(f"  {source}: {total:,} entries")

    print(f"\nDataset Statistics:")
    print(f"  Total examples: {stats['total_examples']:,}")
    print(f"  By category: {stats['by_category']}")
    print(f"  By source: {stats['by_source']}")
    print(f"  By confidence: {stats['by_confidence']}")


if __name__ == "__main__":
    main()
