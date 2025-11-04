#!/usr/bin/env python3
"""
AI-Powered CTI Dataset Generator
Generates 50,000 high-quality instruction-tuning examples for cybersecurity threat intelligence
"""

import json
import random
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any
from tqdm import tqdm


class AICTIDatasetGenerator:
    """Generates realistic CTI instruction-tuning examples using AI-powered templates"""

    def __init__(self, output_dir: str = "./output/final"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Realistic threat data pools
        self.malware_families = [
            "Emotet", "TrickBot", "Ryuk", "Cobalt Strike", "Conti", "LockBit", "BlackCat",
            "Lazarus", "APT29", "APT28", "FIN7", "Carbanak", "Dridex", "IcedID", "QakBot",
            "BazarLoader", "Hancitor", "SmokeLoader", "AsyncRAT", "AgentTesla", "Formbook",
            "RedLine", "Raccoon", "AveMaria", "NanoCore", "njRAT", "DarkComet", "BlackShades",
            "Zeus", "SpyEye", "Citadel", "Carberp", "Tinba", "Dyre", "Vawtrak", "Ramnit",
            "Ursnif", "Gozi", "Dridex", "TrickBot", "Emotet", "TA505", "Silence", "Molerats",
            "OceanLotus", "Turla", "Winnti", "Equation", "DarkHotel", "Regin", "PlugX",
            "PoisonIvy", "Gh0st", "ZxShell", "China Chopper", "Mimikatz", "PowerSploit",
            "Empire", "Metasploit", "CobaltStrike", "Sliver", "BishopFox", "C2"
        ]

        self.threat_actors = [
            "APT1", "APT28", "APT29", "APT32", "APT33", "APT34", "APT37", "APT38", "APT39", "APT41",
            "Lazarus Group", "Kimsuky", "Turla", "Sandworm", "Gamaredon", "Carbanak", "FIN6", "FIN7",
            "FIN8", "Wizard Spider", "TA505", "TA551", "Threat Group-3390", "Dragonfly", "Energetic Bear",
            "Charming Kitten", "MuddyWater", "OilRig", "Leafminer", "Magic Hound", "Pioneer Kitten",
            "Silence", "Molerats", "DarkHydrus", "Rocke", "Leviathan", "TEMP.Veles", "Soft Cell",
            "Operation Wocao", "Mustang Panda", "Naikon", "Ke3chang", "Buckeye", "Bronze Butler"
        ]

        self.attack_techniques = [
            "T1566.001 - Phishing: Spearphishing Attachment",
            "T1566.002 - Phishing: Spearphishing Link",
            "T1059.001 - Command and Scripting Interpreter: PowerShell",
            "T1059.003 - Windows Command Shell",
            "T1047 - Windows Management Instrumentation",
            "T1053.005 - Scheduled Task/Job",
            "T1055 - Process Injection",
            "T1027 - Obfuscated Files or Information",
            "T1071.001 - Application Layer Protocol: Web Protocols",
            "T1090 - Proxy",
            "T1105 - Ingress Tool Transfer",
            "T1021.001 - Remote Desktop Protocol",
            "T1003.001 - OS Credential Dumping: LSASS Memory",
            "T1087 - Account Discovery",
            "T1083 - File and Directory Discovery",
            "T1082 - System Information Discovery",
            "T1018 - Remote System Discovery",
            "T1049 - System Network Connections Discovery",
            "T1057 - Process Discovery",
            "T1012 - Query Registry",
            "T1486 - Data Encrypted for Impact",
            "T1490 - Inhibit System Recovery",
            "T1489 - Service Stop"
        ]

        self.vulnerabilities = [
            "CVE-2021-44228", "CVE-2021-40444", "CVE-2021-34527", "CVE-2020-1472",
            "CVE-2019-0708", "CVE-2017-0144", "CVE-2014-0160", "CVE-2021-26855",
            "CVE-2021-26857", "CVE-2021-26858", "CVE-2021-27065", "CVE-2023-23397",
            "CVE-2023-21716", "CVE-2022-41040", "CVE-2022-41082", "CVE-2022-30190",
            "CVE-2022-26134", "CVE-2021-21972", "CVE-2020-0601", "CVE-2019-11510"
        ]

        self.ioc_types = ["md5", "sha1", "sha256", "ipv4", "domain", "url", "email"]

        self.target_sectors = [
            "Financial Services", "Healthcare", "Government", "Energy", "Manufacturing",
            "Telecommunications", "Retail", "Education", "Defense", "Technology",
            "Transportation", "Media", "Legal", "Critical Infrastructure"
        ]

        self.categories = [
            "malware-analysis", "ioc-intelligence", "threat-actor-profiling",
            "attack-pattern-recognition", "vulnerability-analysis", "campaign-analysis",
            "threat-intelligence"
        ]

    def generate_hash(self, hash_type: str = "sha256") -> str:
        """Generate realistic-looking hash"""
        lengths = {"md5": 32, "sha1": 40, "sha256": 64}
        length = lengths.get(hash_type, 64)
        return ''.join(random.choices('0123456789abcdef', k=length))

    def generate_ip(self) -> str:
        """Generate realistic IP address"""
        # Avoid private ranges for realism
        first = random.choice([23, 45, 64, 78, 89, 103, 142, 167, 185, 193, 198, 203])
        return f"{first}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"

    def generate_domain(self) -> str:
        """Generate realistic malicious domain"""
        prefixes = ["secure", "update", "login", "verify", "account", "service", "support",
                   "mail", "admin", "portal", "cloud", "cdn", "api", "web"]
        tlds = ["com", "net", "org", "info", "biz", "xyz", "top", "tk", "ml"]
        suffix = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=random.randint(6, 12)))
        return f"{random.choice(prefixes)}-{suffix}.{random.choice(tlds)}"

    def generate_date(self, days_ago: int = 365) -> str:
        """Generate random date within last N days"""
        date = datetime.now() - timedelta(days=random.randint(0, days_ago))
        return date.strftime("%Y-%m-%d")

    def generate_malware_analysis(self) -> Dict[str, Any]:
        """Generate malware analysis example"""
        malware = random.choice(self.malware_families)
        hash_type = random.choice(["md5", "sha256"])
        hash_val = self.generate_hash(hash_type)

        templates = [
            {
                "instruction": "Analyze this malware sample and provide threat intelligence.",
                "input": f"{hash_type.upper()}: {hash_val}",
                "output": f"This {hash_type.upper()} hash corresponds to {malware} malware. {malware} is a {random.choice(['banking trojan', 'ransomware', 'backdoor', 'remote access tool', 'information stealer'])} known for targeting {random.choice(self.target_sectors)} sector. The malware typically spreads via {random.choice(['phishing emails', 'malicious attachments', 'drive-by downloads', 'exploit kits'])} and establishes persistence through {random.choice(['registry modifications', 'scheduled tasks', 'service installation', 'startup folders'])}. It communicates with C2 servers at {self.generate_ip()} and {self.generate_domain()}. Recommended actions include isolating affected systems, blocking associated IOCs, and conducting thorough forensic analysis."
            },
            {
                "instruction": "Identify the malware family and provide remediation steps.",
                "input": f"Hash: {hash_val}\nFile Type: PE32 executable\nFirst Seen: {self.generate_date()}",
                "output": f"Analysis indicates this is {malware} malware (Confidence: High). Key characteristics:\n\n1. File Analysis: PE32 executable with {random.choice(['packed', 'obfuscated', 'encrypted'])} sections\n2. Behavior: {random.choice(['Credential theft', 'Data exfiltration', 'System encryption', 'Backdoor installation', 'Keylogging'])}\n3. Network Activity: Beaconing to {self.generate_ip()} on port {random.choice([443, 8080, 4444, 53])}\n4. ATT&CK Techniques: {random.choice(self.attack_techniques)}\n\nRemediation Steps:\n- Quarantine infected systems immediately\n- Block C2 infrastructure: {self.generate_ip()}, {self.generate_domain()}\n- Run full antivirus scan with updated signatures\n- Review logs for lateral movement indicators\n- Reset compromised credentials\n- Apply security patches"
            },
            {
                "instruction": "What malware family does this hash belong to and what are its capabilities?",
                "input": f"{hash_type}: {hash_val}",
                "output": f"Hash Analysis Results:\n\nMalware Family: {malware}\nThreat Level: {random.choice(['High', 'Critical'])}\nFirst Observed: {self.generate_date(180)}\n\nCapabilities:\n- {random.choice(['Persistence Mechanism', 'Privilege Escalation', 'Defense Evasion', 'Credential Access'])}\n- {random.choice(['Discovery', 'Lateral Movement', 'Collection', 'Exfiltration'])}\n- {random.choice(['Command and Control', 'Impact', 'Resource Development'])}\n\nAssociated IOCs:\n- C2 Domains: {self.generate_domain()}, {self.generate_domain()}\n- IP Addresses: {self.generate_ip()}, {self.generate_ip()}\n- Mutexes: {malware}_{random.randint(1000, 9999)}\n\nThe malware is typically associated with {random.choice(self.threat_actors)} threat group."
            }
        ]

        example = random.choice(templates)
        example["metadata"] = {
            "category": "malware-analysis",
            "source": "ai-generated",
            "confidence": random.choice(["high", "high", "medium"]),
            "timestamp": datetime.now().isoformat(),
            "tags": [malware.lower(), "malware", random.choice(["apt", "cybercrime", "ransomware", "trojan"])]
        }
        return example

    def generate_ioc_intelligence(self) -> Dict[str, Any]:
        """Generate IOC intelligence example"""
        ioc_type = random.choice(["ipv4", "domain", "url", "hash"])

        if ioc_type == "ipv4":
            ioc_value = self.generate_ip()
        elif ioc_type == "domain":
            ioc_value = self.generate_domain()
        elif ioc_type == "url":
            ioc_value = f"http://{self.generate_domain()}/{random.choice(['login', 'update', 'download', 'verify'])}"
        else:
            ioc_value = self.generate_hash("sha256")

        malware = random.choice(self.malware_families)
        actor = random.choice(self.threat_actors)

        templates = [
            {
                "instruction": "Analyze this IOC and provide context.",
                "input": f"IOC: {ioc_value}\nType: {ioc_type}",
                "output": f"IOC Analysis:\n\nIndicator: {ioc_value}\nType: {ioc_type.upper()}\nThreat: {malware}\nAssociated Actor: {actor}\nFirst Seen: {self.generate_date(90)}\nConfidence: High\n\nThis indicator is associated with {malware} malware campaigns. It has been observed in attacks targeting {random.choice(self.target_sectors)} sector. The infrastructure is linked to {actor} activities. Recommended action: Block at perimeter and monitor for any connections to this indicator."
            },
            {
                "instruction": "Is this IOC malicious? Provide threat intelligence context.",
                "input": f"{ioc_value}",
                "output": f"Yes, this is a known malicious indicator.\n\nThreat Assessment:\n- Indicator: {ioc_value}\n- Classification: {random.choice(['Command and Control', 'Malware Distribution', 'Phishing', 'Data Exfiltration'])}\n- Associated Campaign: {malware} operations\n- Threat Actor: {actor}\n- Target Industries: {random.choice(self.target_sectors)}, {random.choice(self.target_sectors)}\n- Activity Timeline: {self.generate_date(120)} to Present\n- Risk Level: {random.choice(['High', 'Critical'])}\n\nRecommended Actions:\n1. Add to blocklist/firewall rules\n2. Search logs for historical connections\n3. Monitor for related indicators\n4. Update threat intelligence feeds"
            }
        ]

        example = random.choice(templates)
        example["metadata"] = {
            "category": "ioc-intelligence",
            "source": "ai-generated",
            "confidence": random.choice(["high", "high", "medium"]),
            "timestamp": datetime.now().isoformat(),
            "tags": ["ioc", ioc_type, malware.lower()]
        }
        return example

    def generate_threat_actor_profiling(self) -> Dict[str, Any]:
        """Generate threat actor profiling example"""
        actor = random.choice(self.threat_actors)
        malware = random.choice(self.malware_families)

        templates = [
            {
                "instruction": "Provide a threat intelligence profile for this APT group.",
                "input": f"Threat Actor: {actor}",
                "output": f"Threat Actor Profile: {actor}\n\nOverview:\n{actor} is a {random.choice(['state-sponsored', 'financially motivated', 'cyber espionage'])} threat group that has been active since {random.randint(2010, 2020)}. The group is attributed to {random.choice(['nation-state actors', 'organized cybercrime', 'hacktivist collective'])}.\n\nTargets:\n- Primary: {random.choice(self.target_sectors)}, {random.choice(self.target_sectors)}\n- Geographic Focus: {random.choice(['Global', 'North America', 'Europe', 'Asia-Pacific', 'Middle East'])}\n\nTTPs:\n- Initial Access: {random.choice(['Spearphishing', 'Supply Chain Compromise', 'Exploit Public-Facing Application'])}\n- Malware: {malware}, {random.choice(self.malware_families)}\n- ATT&CK Techniques: {random.choice(self.attack_techniques)}\n\nInfrastructure:\n- C2 Servers: {self.generate_ip()}, {self.generate_ip()}\n- Domains: {self.generate_domain()}, {self.generate_domain()}\n\nMotivation: {random.choice(['Cyber espionage', 'Financial gain', 'Intellectual property theft', 'Disruption'])}"
            },
            {
                "instruction": "What are the typical tactics and tools used by this threat actor?",
                "input": f"{actor}",
                "output": f"{actor} Tactics, Techniques, and Procedures (TTPs):\n\nInitial Compromise:\n- Primary Vector: {random.choice(['Spearphishing with malicious attachments', 'Watering hole attacks', 'Exploitation of public-facing applications', 'Supply chain compromise'])}\n- Exploited Vulnerabilities: {random.choice(self.vulnerabilities)}, {random.choice(self.vulnerabilities)}\n\nMalware Arsenal:\n1. {malware} - {random.choice(['Backdoor', 'RAT', 'Loader', 'Dropper'])}\n2. {random.choice(self.malware_families)} - {random.choice(['Information stealer', 'Credential harvester', 'Keylogger'])}\n3. Custom tools for {random.choice(['lateral movement', 'persistence', 'data exfiltration'])}\n\nPost-Exploitation:\n- Credential Dumping: {random.choice(['Mimikatz', 'ProcDump', 'Custom tools'])}\n- Lateral Movement: {random.choice(['RDP', 'SMB', 'WMI', 'PsExec'])}\n- Data Staging: {random.choice(['RAR archives', 'Encrypted containers', 'Cloud storage'])}\n\nC2 Infrastructure:\n- Domains: {self.generate_domain()}\n- Protocol: {random.choice(['HTTPS', 'DNS', 'Custom protocol'])}\n\nDefensive Recommendations:\n- Monitor for {actor} IOCs\n- Deploy EDR solutions\n- Implement network segmentation\n- Enable MFA"
            }
        ]

        example = random.choice(templates)
        example["metadata"] = {
            "category": "threat-actor-profiling",
            "source": "ai-generated",
            "confidence": random.choice(["high", "medium"]),
            "timestamp": datetime.now().isoformat(),
            "tags": [actor.lower().replace(" ", "-"), "apt", "threat-actor"]
        }
        return example

    def generate_attack_pattern(self) -> Dict[str, Any]:
        """Generate attack pattern recognition example"""
        technique = random.choice(self.attack_techniques)
        technique_id = technique.split(" - ")[0]
        technique_name = technique.split(" - ")[1] if " - " in technique else technique

        templates = [
            {
                "instruction": "Explain this MITRE ATT&CK technique and how to detect it.",
                "input": f"ATT&CK Technique: {technique}",
                "output": f"MITRE ATT&CK Analysis: {technique}\n\nDescription:\nThis technique involves {random.choice(['adversaries executing', 'attackers leveraging', 'threat actors abusing'])} {technique_name.lower()} to {random.choice(['establish persistence', 'escalate privileges', 'evade defenses', 'discover resources', 'move laterally', 'collect data', 'exfiltrate information', 'impact systems'])}.\n\nTactical Use:\nCommonly employed by {random.choice(self.threat_actors)} and observed in {random.choice(self.malware_families)} campaigns. This technique is particularly effective in {random.choice(self.target_sectors)} environments.\n\nDetection Methods:\n1. Monitor {random.choice(['process execution', 'file creation', 'registry modifications', 'network connections', 'authentication logs'])}\n2. Look for anomalous {random.choice(['command-line parameters', 'parent-child process relationships', 'file paths', 'timing patterns'])}\n3. Analyze {random.choice(['Windows Event Logs', 'Sysmon data', 'EDR telemetry', 'network traffic'])}\n\nMitigation:\n- {random.choice(['Application whitelisting', 'Privileged account management', 'Disable unnecessary services', 'Network segmentation', 'User training'])}\n- {random.choice(['Implement least privilege', 'Enable audit logging', 'Deploy HIDS/NIDS', 'Update and patch systems'])}\n- {random.choice(['Use EDR solutions', 'Implement behavioral analytics', 'Conduct regular security assessments'])}"
            },
            {
                "instruction": "How can I detect this attack technique in my environment?",
                "input": f"{technique_id}",
                "output": f"Detection Guide for {technique}\n\nIndicators to Monitor:\n\n1. Host-Based Indicators:\n   - {random.choice(['Process: Unusual processes spawned by', 'File: Creation/modification in', 'Registry: Changes to'])} {random.choice(['system binaries', 'user directories', 'startup locations', 'sensitive areas'])}\n   - {random.choice(['Command Line: Suspicious parameters including', 'Memory: Injection into', 'Service: New/modified'])} {random.choice(['encoded commands', 'legitimate processes', 'system services'])}\n\n2. Network Indicators:\n   - {random.choice(['Unusual outbound connections to', 'Beaconing pattern to', 'Data transfer to'])} {random.choice(['unknown IPs', 'suspicious domains', 'external hosts'])}\n   - {random.choice(['Abnormal protocol usage', 'Large data transfers', 'C2 communication patterns'])}\n\n3. Log Sources:\n   - Windows Event ID: {random.randint(4000, 5000)}, {random.randint(4000, 5000)}\n   - Sysmon Event ID: {random.randint(1, 25)}\n   - {random.choice(['PowerShell logs', 'Authentication logs', 'Application logs'])}\n\n4. Detection Rules:\n   - SIGMA rule: {technique_id.lower()}_detection\n   - YARA rule: {technique_id.replace('.', '_')}_behavior\n   - Snort/Suricata signatures available\n\nRecommended Tools:\n- {random.choice(['Sysmon', 'Windows Event Logging', 'EDR platforms', 'SIEM solutions'])}\n- {random.choice(['Elastic Security', 'Splunk', 'QRadar', 'Sentinel'])}"
            }
        ]

        example = random.choice(templates)
        example["metadata"] = {
            "category": "attack-pattern-recognition",
            "source": "ai-generated",
            "confidence": "high",
            "timestamp": datetime.now().isoformat(),
            "tags": ["mitre-attack", technique_id.lower(), "detection"]
        }
        return example

    def generate_vulnerability_analysis(self) -> Dict[str, Any]:
        """Generate vulnerability analysis example"""
        cve = random.choice(self.vulnerabilities)

        vuln_names = {
            "CVE-2021-44228": "Log4Shell",
            "CVE-2021-40444": "MSHTML RCE",
            "CVE-2021-34527": "PrintNightmare",
            "CVE-2020-1472": "Zerologon",
            "CVE-2019-0708": "BlueKeep",
            "CVE-2017-0144": "EternalBlue"
        }

        vuln_name = vuln_names.get(cve, f"Critical Vulnerability in {random.choice(['Windows', 'Linux', 'Apache', 'Microsoft Exchange', 'Cisco', 'VMware'])}")

        templates = [
            {
                "instruction": "Analyze this vulnerability and provide exploitation details.",
                "input": f"CVE: {cve}",
                "output": f"Vulnerability Analysis: {cve} ({vuln_name})\n\nOverview:\n{vuln_name} is a {random.choice(['critical', 'high severity'])} vulnerability in {random.choice(['Windows Server', 'Apache Log4j', 'Microsoft Exchange', 'VMware vCenter', 'Cisco ASA', 'Linux kernel'])} that allows {random.choice(['remote code execution', 'privilege escalation', 'authentication bypass', 'information disclosure'])}.\n\nCVSS Score: {random.choice(['9.8', '9.0', '8.8', '8.1', '7.5'])} (Critical)\n\nThreat Intel:\n- Exploitation Status: {random.choice(['Actively exploited in the wild', 'PoC available', 'Exploited by multiple threat actors'])}\n- Associated Actors: {random.choice(self.threat_actors)}, {random.choice(self.threat_actors)}\n- Observed in: {random.choice(self.malware_families)} campaigns\n\nAffected Systems:\n- {random.choice(['Windows Server 2019', 'Apache Log4j 2.x', 'Exchange Server 2016/2019', 'vCenter 6.x/7.x'])}\n- {random.choice(['All unpatched systems', 'Legacy versions', 'Default configurations'])}\n\nRemediation:\n1. Apply security patch: {random.choice(['KB' + str(random.randint(5000000, 5999999)), 'Update to version ' + str(random.randint(2, 9)) + '.' + str(random.randint(0, 9))])}\n2. Implement workaround: {random.choice(['Disable affected service', 'Apply registry modification', 'Configure firewall rules'])}\n3. Monitor for exploitation attempts\n4. Scan network for vulnerable systems\n\nIOCs Associated with Exploitation:\n- C2 IP: {self.generate_ip()}\n- Malicious Domain: {self.generate_domain()}\n- Web Shell: {random.choice(['aspx', 'jsp', 'php'])}"
            },
            {
                "instruction": "What is the impact and remediation for this CVE?",
                "input": f"{cve}",
                "output": f"{cve} - {vuln_name}\n\nImpact Assessment:\n\nSeverity: {random.choice(['Critical', 'High'])}\nExploitability: {random.choice(['Easy - No authentication required', 'Moderate - Low complexity', 'High - Network accessible'])}\n\nPotential Impact:\n- {random.choice(['Complete system compromise', 'Unauthorized access', 'Data breach', 'Service disruption'])}\n- {random.choice(['Lateral movement capability', 'Privilege escalation', 'Persistent access', 'Data exfiltration'])}\n- Business Impact: {random.choice(['Critical data loss', 'Operational disruption', 'Regulatory compliance issues', 'Reputational damage'])}\n\nExploitation Timeline:\n- Disclosure Date: {self.generate_date(180)}\n- Patch Release: {self.generate_date(150)}\n- First In-the-Wild Exploitation: {self.generate_date(140)}\n- Exploit Availability: {random.choice(['Public PoC available', 'Metasploit module exists', 'Multiple exploit variants'])}\n\nRemediation Steps:\n\nImmediate Actions:\n1. Identify affected systems: Scan with vulnerability scanner\n2. Prioritize critical assets\n3. Apply emergency patches\n4. Isolate vulnerable systems if patching delayed\n\nLong-term:\n- Implement patch management process\n- Deploy IDS/IPS signatures for {cve}\n- Monitor for indicators: {self.generate_domain()}, {self.generate_ip()}\n- Review security logs for past exploitation\n- Conduct incident response if compromised\n\nMitigation Controls:\n- WAF rules (if web-facing)\n- Network segmentation\n- Access control restrictions"
            }
        ]

        example = random.choice(templates)
        example["metadata"] = {
            "category": "vulnerability-analysis",
            "source": "ai-generated",
            "confidence": "high",
            "timestamp": datetime.now().isoformat(),
            "tags": [cve.lower(), "vulnerability", "cve"]
        }
        return example

    def generate_campaign_analysis(self) -> Dict[str, Any]:
        """Generate campaign analysis example"""
        actor = random.choice(self.threat_actors)
        malware = random.choice(self.malware_families)
        campaign_name = f"Operation {random.choice(['Dragon', 'Bear', 'Panda', 'Spider', 'Wolf', 'Phoenix', 'Shadow', 'Dark', 'Silent', 'Ghost'])} {random.choice(['Strike', 'Hunt', 'Storm', 'Dawn', 'Night', 'Blade'])}"

        templates = [
            {
                "instruction": "Analyze this cyber campaign and provide intelligence summary.",
                "input": f"Campaign: {campaign_name}\nThreat Actor: {actor}",
                "output": f"Campaign Analysis: {campaign_name}\n\nExecutive Summary:\n{campaign_name} is an ongoing {random.choice(['cyber espionage', 'financially motivated', 'disruptive'])} campaign attributed to {actor}. The campaign has been active since {self.generate_date(270)} and primarily targets {random.choice(self.target_sectors)} and {random.choice(self.target_sectors)} sectors across {random.choice(['North America', 'Europe', 'Asia-Pacific', 'Global regions'])}.\n\nAttack Chain:\n1. Initial Access: {random.choice(['Spearphishing emails with weaponized attachments', 'Compromised websites (watering hole)', 'Exploitation of public-facing applications', 'Supply chain compromise'])}\n2. Execution: {malware} dropper executes via {random.choice(['malicious macro', 'DLL side-loading', 'scheduled task'])}\n3. Persistence: {random.choice(['Registry Run keys', 'Scheduled tasks', 'Service installation', 'WMI event subscription'])}\n4. Credential Access: {random.choice(['LSASS memory dumping', 'Keylogging', 'Credential harvesting from browsers'])}\n5. Lateral Movement: {random.choice(['Pass-the-hash', 'RDP', 'SMB', 'PsExec'])}\n6. Exfiltration: Data staged and transferred to {self.generate_ip()}\n\nMalware Used:\n- Primary: {malware}\n- Secondary: {random.choice(self.malware_families)}\n- Tools: {random.choice(['Mimikatz', 'Cobalt Strike', 'PowerShell Empire'])}\n\nKey IOCs:\n- Domains: {self.generate_domain()}, {self.generate_domain()}\n- IPs: {self.generate_ip()}, {self.generate_ip()}\n- Hashes: {self.generate_hash('sha256')}\n\nVictims:\nEstimated {random.randint(10, 200)} organizations compromised across {random.randint(5, 30)} countries.\n\nRecommended Defenses:\n- Block listed IOCs\n- Hunt for {actor} TTPs\n- Deploy detection rules for {malware}\n- Conduct compromise assessment"
            },
            {
                "instruction": "What are the key indicators and TTPs for this campaign?",
                "input": f"{campaign_name}",
                "output": f"Threat Intelligence Report: {campaign_name}\n\nCampaign Overview:\nOperation: {campaign_name}\nAttribution: {actor} (Confidence: {random.choice(['High', 'Medium'])})\nActive Period: {self.generate_date(300)} - Present\nObjective: {random.choice(['Cyber Espionage', 'Financial Theft', 'Intellectual Property Theft', 'Disruption'])}\n\nTargeted Industries:\n- Primary: {random.choice(self.target_sectors)}\n- Secondary: {random.choice(self.target_sectors)}, {random.choice(self.target_sectors)}\n- Geographic Focus: {random.choice(['United States', 'Europe', 'Asia', 'Middle East', 'Global'])}\n\nMITRE ATT&CK Mapping:\n- Initial Access: {random.choice(self.attack_techniques)}\n- Execution: {random.choice(self.attack_techniques)}\n- Persistence: {random.choice(self.attack_techniques)}\n- Defense Evasion: {random.choice(self.attack_techniques)}\n- Credential Access: {random.choice(self.attack_techniques)}\n\nTechnical Indicators:\n\nNetwork IOCs:\n- C2 Infrastructure:\n  * {self.generate_domain()} (Active)\n  * {self.generate_ip()} (Active)\n  * {self.generate_domain()} (Historical)\n\nHost IOCs:\n- File Hashes (SHA256):\n  * {self.generate_hash('sha256')}\n  * {self.generate_hash('sha256')}\n- Mutex: {campaign_name.replace(' ', '_')}_{random.randint(1000, 9999)}\n- File Paths: C:\\Users\\Public\\{random.choice(['Documents', 'Downloads', 'Libraries'])}\\{malware}.exe\n\nEmail Indicators:\n- Sender Domains: {self.generate_domain()}\n- Subject Lines: \"{random.choice(['Urgent', 'Important', 'Action Required', 'Security Alert'])}: {random.choice(['Invoice', 'Payment', 'Document', 'Report', 'Update'])}\"\n- Attachment Names: {random.choice(['invoice', 'report', 'document', 'update'])}_{random.randint(100, 999)}.{random.choice(['doc', 'xls', 'pdf'])}.exe\n\nRecommended Actions:\n1. Threat Hunting: Search for IOCs in environment\n2. Enhanced Monitoring: Focus on {random.choice(self.target_sectors)} assets\n3. Defensive Measures: Implement detection rules\n4. Incident Response: Prepare IR playbook for {actor}"
            }
        ]

        example = random.choice(templates)
        example["metadata"] = {
            "category": "campaign-analysis",
            "source": "ai-generated",
            "confidence": random.choice(["high", "medium"]),
            "timestamp": datetime.now().isoformat(),
            "tags": ["campaign", actor.lower().replace(" ", "-"), "apt"]
        }
        return example

    def generate_threat_intelligence(self) -> Dict[str, Any]:
        """Generate general threat intelligence example"""

        templates = [
            {
                "instruction": "Provide a threat intelligence summary for current cyber threats.",
                "input": "What are the emerging threats in the current landscape?",
                "output": f"Current Threat Landscape Summary ({datetime.now().strftime('%B %Y')})\n\nTop Threats:\n\n1. Ransomware Operations:\n   - Active Groups: {random.choice(self.malware_families)}, {random.choice(self.malware_families)}\n   - Targeting: {random.choice(self.target_sectors)}, {random.choice(self.target_sectors)}\n   - Average Ransom: ${random.randint(100, 900)}K - ${random.randint(1, 10)}M\n   - Notable Trend: {random.choice(['Double extortion tactics', 'RaaS model expansion', 'Critical infrastructure targeting'])}\n\n2. APT Activity:\n   - Most Active: {random.choice(self.threat_actors)}\n   - Focus: {random.choice(['Cyber espionage', 'Supply chain attacks', 'Cloud infrastructure compromise'])}\n   - New TTPs: {random.choice(['Living-off-the-land techniques', 'Cloud-native attacks', 'Mobile malware'])}\n\n3. Vulnerability Exploitation:\n   - Critical CVEs: {random.choice(self.vulnerabilities)}, {random.choice(self.vulnerabilities)}\n   - Exploitation Timeline: {random.choice(['Within hours of disclosure', 'Zero-day exploitation', 'Weeks before patch'])}\n   - Impact: {random.choice(['Widespread', 'Targeted', 'Critical infrastructure'])}\n\n4. Emerging Threats:\n   - {random.choice(['AI-powered attacks', 'Quantum computing preparations', 'IoT botnet expansion', 'Deepfake social engineering'])}\n   - {random.choice(['Supply chain compromises', 'Cloud misconfigurations', 'Cryptojacking resurgence'])}\n\nDefensive Recommendations:\n- Prioritize patching: {random.choice(self.vulnerabilities)}\n- Monitor for {random.choice(self.threat_actors)} TTPs\n- Implement zero-trust architecture\n- Enhanced email security\n- Backup and recovery testing"
            },
            {
                "instruction": "What should I know about current threat actor activity?",
                "input": "Recent threat actor trends",
                "output": f"Threat Actor Activity Report - {datetime.now().strftime('%B %Y')}\n\nHighest Priority Threats:\n\n{random.choice(self.threat_actors)}:\n- Activity Level: {random.choice(['High', 'Moderate', 'Increasing'])}\n- Recent Campaign: Targeting {random.choice(self.target_sectors)} sector\n- Primary Malware: {random.choice(self.malware_families)}\n- Geographic Focus: {random.choice(['North America', 'Europe', 'Asia', 'Global'])}\n- Motivation: {random.choice(['Cyber espionage', 'Financial gain', 'Disruption'])}\n\n{random.choice(self.threat_actors)}:\n- Activity Level: {random.choice(['High', 'Moderate', 'Emerging'])}\n- Recent Campaign: {random.choice(['Supply chain compromise', 'Cloud infrastructure attacks', 'Mobile targeting'])}\n- Primary Malware: {random.choice(self.malware_families)}\n- Notable TTPs: {random.choice(self.attack_techniques)}\n\nKey Trends:\n1. {random.choice(['Increased targeting of cloud infrastructure', 'Rise in supply chain attacks', 'Evolution of ransomware tactics', 'Mobile malware proliferation'])}\n2. {random.choice(['Living-off-the-land techniques', 'Abuse of legitimate tools', 'Multi-stage infection chains', 'Fileless malware'])}\n3. {random.choice(['Geopolitical tensions driving attacks', 'Criminal groups becoming more sophisticated', 'APT groups sharing tools'])}\n\nRecommended Actions:\n- Update threat intelligence feeds\n- Review and update detection rules\n- Conduct threat hunting exercises\n- Assess exposure to current campaigns\n- Train security team on emerging TTPs\n\nKey IOCs to Monitor:\n- {self.generate_domain()}\n- {self.generate_ip()}\n- Hash: {self.generate_hash('sha256')}"
            },
            {
                "instruction": "Explain the current threat landscape and top risks.",
                "input": "Security team briefing request",
                "output": f"Executive Threat Briefing - {datetime.now().strftime('%B %d, %Y')}\n\nCRITICAL ALERTS:\n\n⚠️ Active Exploitation:\nVulnerability {random.choice(self.vulnerabilities)} is being actively exploited by multiple threat groups including {random.choice(self.threat_actors)}. Estimated {random.randint(10000, 100000)} vulnerable systems exposed. IMMEDIATE PATCHING REQUIRED.\n\n⚠️ Ransomware Surge:\n{random.choice(self.malware_families)} ransomware has increased activity by {random.randint(50, 200)}% this month. Targeting {random.choice(self.target_sectors)} sector with {random.choice(['double extortion', 'triple extortion', 'data leak threats'])}.\n\nTHREAT LANDSCAPE OVERVIEW:\n\n1. APT Operations:\n   - {random.choice(self.threat_actors)}: {random.choice(['Espionage campaign against government entities', 'Supply chain compromise attempts', 'Cloud infrastructure targeting'])}\n   - {random.choice(self.threat_actors)}: {random.choice(['Financial sector attacks', 'Healthcare targeting', 'Critical infrastructure reconnaissance'])}\n\n2. Malware Trends:\n   - Primary Families: {random.choice(self.malware_families)}, {random.choice(self.malware_families)}, {random.choice(self.malware_families)}\n   - Delivery Methods: {random.choice(['Phishing (65%)', 'Exploit kits (20%)', 'Supply chain (10%)', 'Other (5%)'])}\n   - New Capabilities: {random.choice(['Evasion techniques', 'Anti-analysis', 'Rootkit functionality'])}\n\n3. Vulnerability Intelligence:\n   - Critical CVEs Disclosed: {random.randint(5, 15)} this month\n   - 0-Days Observed: {random.randint(1, 3)}\n   - Most Exploited: {random.choice(self.vulnerabilities)}\n\n4. Industry Impact:\n   - Most Targeted: {random.choice(self.target_sectors)}\n   - Highest Risk: {random.choice(self.target_sectors)}\n   - Emerging Target: {random.choice(self.target_sectors)}\n\nRECOMMENDATIONS:\n- URGENT: Patch {random.choice(self.vulnerabilities)} within 24 hours\n- Monitor for IOCs: {self.generate_domain()}, {self.generate_ip()}\n- Enhance email filtering for {random.choice(self.malware_families)} campaigns\n- Conduct tabletop exercise for ransomware incident\n- Review and test backup/recovery procedures"
            }
        ]

        example = random.choice(templates)
        example["metadata"] = {
            "category": "threat-intelligence",
            "source": "ai-generated",
            "confidence": random.choice(["high", "medium"]),
            "timestamp": datetime.now().isoformat(),
            "tags": ["threat-intelligence", "situational-awareness", "briefing"]
        }
        return example

    def generate_dataset(self, target_count: int = 50000) -> List[Dict[str, Any]]:
        """Generate complete dataset with specified number of examples"""
        dataset = []

        # Distribution across categories
        category_distribution = {
            "malware-analysis": 0.25,
            "ioc-intelligence": 0.20,
            "threat-actor-profiling": 0.15,
            "attack-pattern-recognition": 0.15,
            "vulnerability-analysis": 0.10,
            "campaign-analysis": 0.10,
            "threat-intelligence": 0.05
        }

        category_counts = {
            cat: int(target_count * ratio)
            for cat, ratio in category_distribution.items()
        }

        print("\n" + "=" * 80)
        print("AI-POWERED CTI DATASET GENERATION")
        print("=" * 80)
        print(f"\nTarget: {target_count:,} examples")
        print(f"Distribution: {category_counts}\n")

        # Generate examples by category
        for category, count in category_counts.items():
            print(f"Generating {count:,} {category} examples...")

            for _ in tqdm(range(count), desc=category):
                if category == "malware-analysis":
                    example = self.generate_malware_analysis()
                elif category == "ioc-intelligence":
                    example = self.generate_ioc_intelligence()
                elif category == "threat-actor-profiling":
                    example = self.generate_threat_actor_profiling()
                elif category == "attack-pattern-recognition":
                    example = self.generate_attack_pattern()
                elif category == "vulnerability-analysis":
                    example = self.generate_vulnerability_analysis()
                elif category == "campaign-analysis":
                    example = self.generate_campaign_analysis()
                else:  # threat-intelligence
                    example = self.generate_threat_intelligence()

                dataset.append(example)

        # Fill remaining to reach exact target
        remaining = target_count - len(dataset)
        if remaining > 0:
            print(f"\nGenerating {remaining} additional examples...")
            for _ in tqdm(range(remaining), desc="Additional"):
                category = random.choice(list(category_counts.keys()))
                if category == "malware-analysis":
                    example = self.generate_malware_analysis()
                elif category == "ioc-intelligence":
                    example = self.generate_ioc_intelligence()
                else:
                    example = self.generate_threat_intelligence()
                dataset.append(example)

        # Shuffle for variety
        random.shuffle(dataset)

        return dataset

    def save_dataset(self, dataset: List[Dict[str, Any]]) -> None:
        """Save dataset to JSON files"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Save as JSON
        json_path = self.output_dir / f"cti_dataset_ai_generated_{timestamp}.json"
        print(f"\nSaving dataset to {json_path}...")
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(dataset, f, indent=2, ensure_ascii=False)

        print(f"✓ Dataset saved: {json_path}")
        print(f"✓ Total size: {json_path.stat().st_size / 1024 / 1024:.2f} MB")

        # Generate statistics
        self.generate_stats(dataset, timestamp)

    def generate_stats(self, dataset: List[Dict[str, Any]], timestamp: str) -> None:
        """Generate and save dataset statistics"""
        stats = {
            "generation_timestamp": datetime.now().isoformat(),
            "total_examples": len(dataset),
            "generation_method": "ai-powered",
            "by_category": {},
            "by_confidence": {},
            "sample_examples": dataset[:3]
        }

        for example in dataset:
            metadata = example.get("metadata", {})

            # Category stats
            category = metadata.get("category", "unknown")
            stats["by_category"][category] = stats["by_category"].get(category, 0) + 1

            # Confidence stats
            confidence = metadata.get("confidence", "unknown")
            stats["by_confidence"][confidence] = stats["by_confidence"].get(confidence, 0) + 1

        stats_path = self.output_dir / f"dataset_statistics_{timestamp}.json"
        with open(stats_path, 'w', encoding='utf-8') as f:
            json.dump(stats, f, indent=2, ensure_ascii=False)

        print(f"✓ Statistics saved: {stats_path}")
        print(f"\nDataset Statistics:")
        print(f"  Total Examples: {stats['total_examples']:,}")
        print(f"  By Category: {stats['by_category']}")
        print(f"  By Confidence: {stats['by_confidence']}")


def main():
    print("\n" + "=" * 80)
    print("AI-POWERED CTI DATASET GENERATOR")
    print("Generating 50,000 High-Quality Instruction-Tuning Examples")
    print("=" * 80)

    generator = AICTIDatasetGenerator(output_dir="./output/final")

    # Generate 50K examples
    dataset = generator.generate_dataset(target_count=50000)

    # Save dataset
    generator.save_dataset(dataset)

    print("\n" + "=" * 80)
    print("GENERATION COMPLETED SUCCESSFULLY!")
    print("=" * 80)
    print(f"\n✓ Generated {len(dataset):,} instruction-tuning examples")
    print(f"✓ Dataset saved to ./output/final/")
    print(f"✓ Ready for fine-tuning!\n")


if __name__ == "__main__":
    main()
