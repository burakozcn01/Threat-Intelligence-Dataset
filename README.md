# CTI Instruction-Tuning Dataset Generator

Siber Tehdit İstihbaratı (CTI) verilerinden yüksek kaliteli instruction-tuning dataset'i üreten otomatik pipeline.

## Veri Kaynakları

| Kaynak | Tip | Örnek Veri |
|--------|-----|------------|
| MITRE ATT&CK | Taktik/Teknik/Malware | ~26,000 entity |
| AlienVault OTX | Threat Pulse/IOC | ~1,000 pulse |
| Abuse.ch | Malware/URL/C2 | ~1,000 URLhaus |
| Ransomware.live | Ransomware Grupları/Attacks | ~600 entry |
| Phishing Feeds | Phishing URL/Domain | ~200,000 URL |
| CISA KEV | Zafiyetler | ~1,500 CVE |
| GitHub APT Campaigns | APT Raporları | ~1,500 campaign |
| CERT Advisories | Güvenlik Bültenleri | ~500 advisory |
| Unit42 | Threat Intel | ~30 rapor |
| YARA Rules | Detection Rules | ~15 rule seti |
| ICS-CERT | ICS Güvenlik | ~30 advisory |

## Kurulum

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## API Anahtarları

API anahtarlarını `.env` dosyasına ekleyin:

```env
OTX_API_KEY=your_otx_api_key
GITHUB_API_KEY=your_github_token
VIRUSTOTAL_API_KEY=your_virustotal_key
```

## Kullanım

Tek komutla tüm pipeline'ı çalıştırın:

```bash
python generate_final_dataset.py
```

Bu komut:
1. 12 kaynaktan veri toplar
2. Verileri normalize eder ve deduplicate eder
3. Instruction-tuning formatına dönüştürür
4. 300K hedef ile dataset oluşturur
5. `./output/final/` klasörüne kaydeder

## Çıktı Formatı

### Instruction-Tuning Format

```json
{
  "instruction": "Analyze this malware hash and provide threat intelligence.",
  "input": "SHA-256: abc123...",
  "output": "The hash corresponds to TrickBot malware...",
  "metadata": {
    "source": "mitre-attack",
    "category": "malware-analysis",
    "confidence": "high",
    "timestamp": "2025-10-25T...",
    "tags": ["banking-trojan", "apt"]
  }
}
```

## Dataset Kategorileri

- **malware-analysis**: Malware analizi ve sınıflandırma
- **ioc-intelligence**: IOC (Indicator of Compromise) analizi
- **threat-actor-profiling**: APT grupları ve threat actor profilleme
- **attack-pattern-recognition**: MITRE ATT&CK teknik tanıma
- **vulnerability-analysis**: Zafiyet analizi ve remediation
- **campaign-analysis**: Threat kampanya analizi
- **threat-intelligence**: Genel tehdit istihbaratı

## Lisans

Bu proje CTI araştırma amaçlı geliştirilmiştir.
