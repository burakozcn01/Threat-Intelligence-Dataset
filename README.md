# AI-Powered CTI Instruction-Tuning Dataset

Yapay zeka ile üretilmiş 50,000 yüksek kaliteli Siber Tehdit İstihbaratı (CTI) instruction-tuning dataset'i.

## 🎯 Özellikler

- **50,000 örnek**: Gerçekçi ve çeşitli CTI senaryoları
- **AI-powered**: Yapay zeka tarafından üretilmiş yüksek kaliteli içerik
- **7 kategori**: Malware analizi, IOC intelligence, threat actor profiling, ve daha fazlası
- **Gerçekçi veriler**: Gerçek dünya threat intelligence verilerine dayalı
- **Instruction-tuning formatı**: LLM fine-tuning için hazır format

## 📊 Dataset İçeriği

| Kategori | Örnek Sayısı | Oran |
|----------|--------------|------|
| Malware Analysis | 12,500 | 25% |
| IOC Intelligence | 10,000 | 20% |
| Threat Actor Profiling | 7,500 | 15% |
| Attack Pattern Recognition | 7,500 | 15% |
| Vulnerability Analysis | 5,000 | 10% |
| Campaign Analysis | 5,000 | 10% |
| Threat Intelligence | 2,500 | 5% |

## 🚀 Kurulum

```bash
# Repository'yi klonlayın
git clone https://github.com/burakozcn01/ThreatIntel-JSON-Dataset-150k.git
cd ThreatIntel-JSON-Dataset-150k

# Gereksinimleri yükleyin
pip install -r requirements.txt
```

## 💻 Kullanım

### Yeni Dataset Üretme

Yeni bir 50K dataset üretmek için:

```bash
python generate_ai_dataset.py
```

Bu komut:
1. 50,000 yüksek kaliteli CTI örneği üretir
2. Instruction-tuning formatına dönüştürür
3. `./output/final/` klasörüne kaydeder
4. İstatistikleri oluşturur

## 📋 Çıktı Formatı

Her örnek instruction-tuning formatında:

```json
{
  "instruction": "Analyze this malware sample and provide threat intelligence.",
  "input": "SHA256: 3f5a2b9c8d1e0f4a...",
  "output": "This SHA256 hash corresponds to Emotet malware. Emotet is a banking trojan known for targeting Financial Services sector. The malware typically spreads via phishing emails and establishes persistence through registry modifications...",
  "metadata": {
    "category": "malware-analysis",
    "source": "ai-generated",
    "confidence": "high",
    "timestamp": "2025-11-04T23:46:14.765507",
    "tags": ["emotet", "malware", "trojan"]
  }
}
```

## 🎓 Dataset Kategorileri

- **malware-analysis** (25%): Malware analizi, hash analizi, dosya analizi
- **ioc-intelligence** (20%): IOC (Indicator of Compromise) analizi, IP/domain/hash kontrol
- **threat-actor-profiling** (15%): APT grupları, threat actor TTPs, profilleme
- **attack-pattern-recognition** (15%): MITRE ATT&CK teknikleri, detection yöntemleri
- **vulnerability-analysis** (10%): CVE analizi, zafiyet değerlendirme, remediation
- **campaign-analysis** (10%): Threat kampanya analizi, APT operasyonları
- **threat-intelligence** (5%): Genel tehdit istihbaratı, durum raporları

## 📦 Örnek Kullanım

```python
import json

# Dataset'i yükle
with open('output/final/cti_dataset_ai_generated_20251104_234615.json', 'r') as f:
    dataset = json.load(f)

# İlk örneği görüntüle
print(json.dumps(dataset[0], indent=2))

# Kategoriye göre filtrele
malware_examples = [ex for ex in dataset if ex['metadata']['category'] == 'malware-analysis']
print(f"Malware analysis örnekleri: {len(malware_examples)}")
```

## 🔧 Dataset İstatistikleri

- **Toplam örnek**: 50,000
- **Dosya boyutu**: ~51 MB (JSON)
- **Ortalama örnek uzunluğu**: ~1 KB
- **High confidence**: 70%
- **Medium confidence**: 30%

## 🎯 Kullanım Alanları

- LLM fine-tuning için CTI domain adaptation
- Security analyst eğitim dataları
- Threat intelligence chatbot geliştirme
- SOC analyst eğitim simülasyonları
- CTI araştırma ve geliştirme

## 📝 Lisans

Bu proje CTI araştırma ve eğitim amaçlı geliştirilmiştir. Ticari kullanım için lisans gereklidir.
