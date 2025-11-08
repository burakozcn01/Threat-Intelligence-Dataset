# CTI Instruction-Tuning Veri Seti (Toplam 50.174 Örnek)

Bu veri seti, Siber Tehdit İstihbaratı (CTI) alanında kullanılmak üzere hazırlanmış **50.174 adet instruction-tuning örneğinden** oluşmaktadır.

Veri seti CTI araştırmaları, SOC analizi, tehdit avcılığı ve yapay zeka model eğitimi ihtiyaçlarını karşılayacak şekilde oluşturulmuştur .

## Genel Özellikler

| Özellik | Değer |
|--------|-------|
| Toplam veri | **50.174 örnek** |
| Dosya formatı | **JSONL** (her satır tek bir JSON nesnesi) |
| Kategori sayısı | 27 kategori |
| Kullanım amaçları | CTI analizi, SOC eğitimi, Veri sınıflandırma, LLM fine-tuning, Threat Hunting |

## Kategori Dağılımı (27 kategori)

| Kategori Adı | Açıklama |
|--------------|---------|
| network-based-threats | Ağ tabanlı saldırı davranışları ve trafik analizi |
| malware | Zararlı yazılım davranış analizi ve IOC’ler |
| malicious-campaigns | Bilinen saldırı kampanyalarının yapı ve yöntemleri |
| vulnerabilities-cves | Zafiyet değerlendirmesi ve teknik etki analizi |
| cyber-espionage-apt | APT grupları ve casusluk operasyonlarının bağlamı |
| threat-actors | Tehdit aktörlerinin motivasyon, hedef ve TTP profilleri |
| threat-intelligence-feeds | IOC beslemeleri ve bağlamsal değerlendirme |
| social-engineering-fraud | Sosyal mühendislik ve kimlik avı örüntüleri |
| ttps-mitre-attack | MITRE ATT&CK tekniği eşleştirme ve açıklama |
| threat-intelligence-operations | CTI iş akışları ve raporlama süreçleri |
| supply-chain-attacks | Tedarik zinciri istismar yöntemleri |
| incident-response-forensics | Olay müdahale ve dijital adli analiz |
| security-monitoring-detection | SIEM, log analizi ve tespit kuralı tasarımı |
| digital-risk-management | Dijital varlık güvenliği ve risk yüzeyi değerlendirmesi |
| dark-web-cybercrime | Dark Web platformlarında gözlemlenen faaliyetler |
| ics-ot-security | Endüstriyel sistemler ve OT ortamlarının tehditleri |
| cloud-saas-security | Bulut ortamı zafiyetleri ve saldırı yüzeyleri |
| mobile-iot-threats | Mobil / IoT tehdit modellemeleri |
| ai-ml-threats | Yapay zeka modellerine karşı geliştirilen saldırı yöntemleri |
| data-exfiltration | Veri sızdırma teknikleri ve karşı tespit yaklaşımları |

## Veri Formatı

Veri seti **JSONL** formatındadır; yani her satır tek bir analiz örneğini temsil eder:

```json
{
  "instruction": "<kullanıcı isteği>",
  "input": "<analiz edilecek IOC / CVE / IP / domain / log vb.>",
  "output": "<profesyonel CTI analizi>",
  "metadata": {
    "category": "<kategori>",
    "source": "ai-generated",
    "confidence": "high/medium/low",
    "timestamp": "YYYY-MM-DDTHH:MM:SSZ",
    "tags": ["ilgili", "anahtar", "terimler"]
  }
}
```
## Python ile Örnek Kullanım

```python
import json

with open("dataset.jsonl", "r", encoding="utf-8") as f:
    for line in f:
        entry = json.loads(line)
        print(entry["metadata"]["category"], entry["instruction"])
```

---

Bu veri seti CTI analiz süreçleri, tehdit avcılığı, SOC seviyelendirme eğitimleri ve yapay zeka tabanlı güvenlik modellerinin eğitimi için kullanılmaya hazırdır.
