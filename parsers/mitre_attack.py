"""
MITRE ATT&CK Framework Integration for Log Analysis

Maps log patterns and behaviors to MITRE ATT&CK tactics and techniques.
This module provides comprehensive coverage of the Enterprise ATT&CK Matrix.
"""

import re
from collections import defaultdict


class MitreAttackMapper:
    """Maps suspicious activities to MITRE ATT&CK framework tactics and techniques"""

    def __init__(self):
        """Initialize MITRE ATT&CK technique mappings"""

        # Pattern-to-Technique mappings
        # Each entry: {pattern: [(tactic, technique_id, technique_name, description)]}
        self.attack_patterns = self._initialize_attack_patterns()

        # Tactic metadata
        self.tactics = self._initialize_tactics()

    def _initialize_tactics(self):
        """Initialize MITRE ATT&CK tactics with descriptions"""
        return {
            'reconnaissance': {
                'id': 'TA0043',
                'name': 'Reconnaissance',
                'description': 'Adversaries gather information about targets'
            },
            'resource_development': {
                'id': 'TA0042',
                'name': 'Resource Development',
                'description': 'Adversaries establish resources for operations'
            },
            'initial_access': {
                'id': 'TA0001',
                'name': 'Initial Access',
                'description': 'Adversaries try to get into the network'
            },
            'execution': {
                'id': 'TA0002',
                'name': 'Execution',
                'description': 'Adversaries try to run malicious code'
            },
            'persistence': {
                'id': 'TA0003',
                'name': 'Persistence',
                'description': 'Adversaries maintain their foothold'
            },
            'privilege_escalation': {
                'id': 'TA0004',
                'name': 'Privilege Escalation',
                'description': 'Adversaries gain higher-level permissions'
            },
            'defense_evasion': {
                'id': 'TA0005',
                'name': 'Defense Evasion',
                'description': 'Adversaries avoid detection'
            },
            'credential_access': {
                'id': 'TA0006',
                'name': 'Credential Access',
                'description': 'Adversaries steal account credentials'
            },
            'discovery': {
                'id': 'TA0007',
                'name': 'Discovery',
                'description': 'Adversaries explore the environment'
            },
            'lateral_movement': {
                'id': 'TA0008',
                'name': 'Lateral Movement',
                'description': 'Adversaries move through the network'
            },
            'collection': {
                'id': 'TA0009',
                'name': 'Collection',
                'description': 'Adversaries gather target data'
            },
            'command_and_control': {
                'id': 'TA0011',
                'name': 'Command and Control',
                'description': 'Adversaries communicate with compromised systems'
            },
            'exfiltration': {
                'id': 'TA0010',
                'name': 'Exfiltration',
                'description': 'Adversaries steal data'
            },
            'impact': {
                'id': 'TA0040',
                'name': 'Impact',
                'description': 'Adversaries manipulate, disrupt, or destroy systems'
            }
        }

    def _initialize_attack_patterns(self):
        """
        Initialize mappings between log patterns and ATT&CK techniques.
        Each pattern maps to: (tactic, technique_id, technique_name, severity)
        """
        patterns = {}

        # ===== RECONNAISSANCE (TA0043) =====
        patterns.update({
            r'(?:nmap|masscan|zmap)': [
                ('reconnaissance', 'T1595.001', 'Active Scanning: Scanning IP Blocks', 'high')
            ],
            r'(?:nikto|dirb|gobuster|dirbuster)': [
                ('reconnaissance', 'T1595.002', 'Active Scanning: Vulnerability Scanning', 'high')
            ],
            r'(?:whois|nslookup|dig)\s': [
                ('reconnaissance', 'T1590.002', 'Gather Victim Network Information: DNS', 'medium')
            ],
            r'(?:scan|probe|enumerate)': [
                ('reconnaissance', 'T1595', 'Active Scanning', 'medium'),
                ('discovery', 'T1046', 'Network Service Discovery', 'medium')
            ],
            r'/\.git|/\.svn|/\.env': [
                ('reconnaissance', 'T1593.003', 'Search Open Websites/Domains: Code Repositories', 'high')
            ],
            r'robots\.txt|sitemap\.xml': [
                ('reconnaissance', 'T1594', 'Search Victim-Owned Websites', 'low')
            ]
        })

        # ===== INITIAL ACCESS (TA0001) =====
        patterns.update({
            r'(?:phish|spoof)': [
                ('initial_access', 'T1566', 'Phishing', 'high')
            ],
            r'/wp-admin|/wp-login|/administrator': [
                ('initial_access', 'T1190', 'Exploit Public-Facing Application', 'high')
            ],
            r'(?:exploit|vulnerability|cve-)': [
                ('initial_access', 'T1190', 'Exploit Public-Facing Application', 'critical')
            ],
            r'(?:brute.?force|dictionary.?attack)': [
                ('initial_access', 'T1110', 'Brute Force', 'high'),
                ('credential_access', 'T1110', 'Brute Force', 'high')
            ],
            r'default.?(?:password|credential)': [
                ('initial_access', 'T1078', 'Valid Accounts', 'high')
            ]
        })

        # ===== EXECUTION (TA0002) =====
        patterns.update({
            r'(?:cmd\.exe|command\.com)': [
                ('execution', 'T1059.003', 'Command and Scripting Interpreter: Windows Command Shell', 'high')
            ],
            r'powershell(?:\.exe)?': [
                ('execution', 'T1059.001', 'Command and Scripting Interpreter: PowerShell', 'high')
            ],
            r'(?:bash|sh|zsh)': [
                ('execution', 'T1059.004', 'Command and Scripting Interpreter: Unix Shell', 'high')
            ],
            r'python(?:\d)?(?:\.exe)?': [
                ('execution', 'T1059.006', 'Command and Scripting Interpreter: Python', 'medium')
            ],
            r'(?:javascript|vbscript|jscript)': [
                ('execution', 'T1059.007', 'Command and Scripting Interpreter: JavaScript', 'medium')
            ],
            r'wmic(?:\.exe)?': [
                ('execution', 'T1047', 'Windows Management Instrumentation', 'high')
            ],
            r'(?:cron|at|schtasks)': [
                ('execution', 'T1053', 'Scheduled Task/Job', 'high'),
                ('persistence', 'T1053', 'Scheduled Task/Job', 'high')
            ],
            r'(?:eval|exec|system)\(': [
                ('execution', 'T1059', 'Command and Scripting Interpreter', 'critical')
            ]
        })

        # ===== PERSISTENCE (TA0003) =====
        patterns.update({
            r'(?:registry|reg\.exe|regedit)': [
                ('persistence', 'T1547.001', 'Boot or Logon Autostart: Registry Run Keys', 'high')
            ],
            r'(?:startup|autostart|autorun)': [
                ('persistence', 'T1547', 'Boot or Logon Autostart Execution', 'high')
            ],
            r'(?:service|systemctl|sc\.exe)': [
                ('persistence', 'T1543', 'Create or Modify System Process', 'high')
            ],
            r'(?:cron|crontab)': [
                ('persistence', 'T1053.003', 'Scheduled Task/Job: Cron', 'high')
            ],
            r'\.bashrc|\.bash_profile|\.profile': [
                ('persistence', 'T1546.004', 'Event Triggered Execution: Unix Shell Configuration', 'medium')
            ],
            r'authorized_keys|\.ssh': [
                ('persistence', 'T1098.004', 'Account Manipulation: SSH Authorized Keys', 'critical')
            ]
        })

        # ===== PRIVILEGE ESCALATION (TA0004) =====
        patterns.update({
            r'(?:sudo|su\s|runas)': [
                ('privilege_escalation', 'T1548.003', 'Abuse Elevation Control: Sudo and Sudo Caching', 'high')
            ],
            r'(?:admin|administrator|root|system)': [
                ('privilege_escalation', 'T1078.003', 'Valid Accounts: Local Accounts', 'high')
            ],
            r'(?:setuid|suid|sgid)': [
                ('privilege_escalation', 'T1548.001', 'Abuse Elevation Control: Setuid and Setgid', 'high')
            ],
            r'(?:uac|bypass)': [
                ('privilege_escalation', 'T1548.002', 'Abuse Elevation Control: Bypass UAC', 'critical')
            ],
            r'privilege.*(?:escalat|elevat)': [
                ('privilege_escalation', 'T1068', 'Exploitation for Privilege Escalation', 'critical')
            ]
        })

        # ===== DEFENSE EVASION (TA0005) =====
        patterns.update({
            r'(?:obfuscat|encod|decode|base64)': [
                ('defense_evasion', 'T1027', 'Obfuscated Files or Information', 'high')
            ],
            r'(?:disable|stop|kill).*(?:antivirus|defender|firewall|av)': [
                ('defense_evasion', 'T1562.001', 'Impair Defenses: Disable or Modify Tools', 'critical')
            ],
            r'(?:clear|delete|wipe).*(?:log|event|audit)': [
                ('defense_evasion', 'T1070.001', 'Indicator Removal: Clear Windows Event Logs', 'critical')
            ],
            r'(?:masquerad|spoof|impersonat)': [
                ('defense_evasion', 'T1036', 'Masquerading', 'high')
            ],
            r'(?:proxy|vpn|tor|tunnel)': [
                ('defense_evasion', 'T1090', 'Proxy', 'medium'),
                ('command_and_control', 'T1090', 'Proxy', 'medium')
            ],
            r'\.\.[\\/]|directory.*travers': [
                ('defense_evasion', 'T1083', 'File and Directory Discovery', 'high')
            ],
            r'timestomp|touch\s.*-t': [
                ('defense_evasion', 'T1070.006', 'Indicator Removal: Timestomp', 'high')
            ]
        })

        # ===== CREDENTIAL ACCESS (TA0006) =====
        patterns.update({
            r'(?:mimikatz|gsecdump|pwdump)': [
                ('credential_access', 'T1003.001', 'OS Credential Dumping: LSASS Memory', 'critical')
            ],
            r'/etc/passwd|/etc/shadow': [
                ('credential_access', 'T1003.008', 'OS Credential Dumping: /etc/passwd and /etc/shadow', 'critical')
            ],
            r'sam|system|security.*hive': [
                ('credential_access', 'T1003.002', 'OS Credential Dumping: Security Account Manager', 'critical')
            ],
            r'(?:keylog|keystroke)': [
                ('credential_access', 'T1056.001', 'Input Capture: Keylogging', 'critical')
            ],
            r'(?:password|credential).*(?:dump|extract|harvest)': [
                ('credential_access', 'T1003', 'OS Credential Dumping', 'critical')
            ],
            r'(?:brute.?force|hydra|medusa)': [
                ('credential_access', 'T1110', 'Brute Force', 'high')
            ],
            r'(?:hash|ntlm|kerberos).*(?:crack|break)': [
                ('credential_access', 'T1110.002', 'Brute Force: Password Cracking', 'high')
            ],
            r'\.kdbx|keepass|lastpass|1password': [
                ('credential_access', 'T1555.005', 'Credentials from Password Stores', 'high')
            ]
        })

        # ===== DISCOVERY (TA0007) =====
        patterns.update({
            r'(?:ipconfig|ifconfig|ip\s+addr)': [
                ('discovery', 'T1016', 'System Network Configuration Discovery', 'low')
            ],
            r'(?:netstat|ss\s|lsof)': [
                ('discovery', 'T1049', 'System Network Connections Discovery', 'medium')
            ],
            r'(?:ps\s|tasklist|get-process)': [
                ('discovery', 'T1057', 'Process Discovery', 'low')
            ],
            r'(?:whoami|id\s|get-localuser)': [
                ('discovery', 'T1033', 'System Owner/User Discovery', 'medium')
            ],
            r'(?:net\s+user|net\s+group|net\s+localgroup)': [
                ('discovery', 'T1087', 'Account Discovery', 'medium')
            ],
            r'(?:hostname|uname)': [
                ('discovery', 'T1082', 'System Information Discovery', 'low')
            ],
            r'(?:dir|ls|find|tree)\s': [
                ('discovery', 'T1083', 'File and Directory Discovery', 'low')
            ],
            r'(?:arp|route|traceroute)': [
                ('discovery', 'T1018', 'Remote System Discovery', 'medium')
            ]
        })

        # ===== LATERAL MOVEMENT (TA0008) =====
        patterns.update({
            r'(?:psexec|paexec|remcom)': [
                ('lateral_movement', 'T1021.002', 'Remote Services: SMB/Windows Admin Shares', 'critical')
            ],
            r'(?:rdp|remote.*desktop|mstsc)': [
                ('lateral_movement', 'T1021.001', 'Remote Services: Remote Desktop Protocol', 'high')
            ],
            r'(?:ssh|scp|sftp)': [
                ('lateral_movement', 'T1021.004', 'Remote Services: SSH', 'medium')
            ],
            r'(?:winrm|powershell.*remoting)': [
                ('lateral_movement', 'T1021.006', 'Remote Services: Windows Remote Management', 'high')
            ],
            r'net\s+use|mount.*\\\\': [
                ('lateral_movement', 'T1021.002', 'Remote Services: SMB/Windows Admin Shares', 'high')
            ],
            r'pass.?the.?hash': [
                ('lateral_movement', 'T1550.002', 'Use Alternate Authentication: Pass the Hash', 'critical')
            ]
        })

        # ===== COLLECTION (TA0009) =====
        patterns.update({
            r'(?:screenshot|screencap|printscreen)': [
                ('collection', 'T1113', 'Screen Capture', 'medium')
            ],
            r'(?:keylog|input.*capture)': [
                ('collection', 'T1056', 'Input Capture', 'high')
            ],
            r'(?:clipboard|copy.*buffer)': [
                ('collection', 'T1115', 'Clipboard Data', 'medium')
            ],
            r'(?:archive|compress|zip|rar|tar\.gz)': [
                ('collection', 'T1560', 'Archive Collected Data', 'medium')
            ],
            r'(?:email|inbox|mail).*(?:harvest|collect|scrape)': [
                ('collection', 'T1114', 'Email Collection', 'high')
            ],
            r'(?:audio|microphone|record)': [
                ('collection', 'T1123', 'Audio Capture', 'high')
            ],
            r'(?:video|camera|webcam)': [
                ('collection', 'T1125', 'Video Capture', 'high')
            ]
        })

        # ===== COMMAND AND CONTROL (TA0011) =====
        patterns.update({
            r'(?:c2|c&c|command.*control)': [
                ('command_and_control', 'T1071', 'Application Layer Protocol', 'high')
            ],
            r'(?:beacon|callback|heartbeat)': [
                ('command_and_control', 'T1095', 'Non-Application Layer Protocol', 'high')
            ],
            r'(?:dns.*tunnel|icmp.*tunnel)': [
                ('command_and_control', 'T1071.004', 'Application Layer Protocol: DNS', 'high')
            ],
            r'(?:http|https).*(?:tunnel|covert)': [
                ('command_and_control', 'T1071.001', 'Application Layer Protocol: Web Protocols', 'medium')
            ],
            r'(?:reverse.*shell|bind.*shell)': [
                ('command_and_control', 'T1059', 'Command and Scripting Interpreter', 'critical')
            ],
            r'(?:irc|discord|telegram|slack).*bot': [
                ('command_and_control', 'T1102', 'Web Service', 'high')
            ],
            r'(?:encrypt|aes|rsa|chacha).*(?:traffic|communication)': [
                ('command_and_control', 'T1573', 'Encrypted Channel', 'medium')
            ]
        })

        # ===== EXFILTRATION (TA0010) =====
        patterns.update({
            r'(?:exfil|extract|steal).*data': [
                ('exfiltration', 'T1041', 'Exfiltration Over C2 Channel', 'critical')
            ],
            r'(?:ftp|sftp).*(?:upload|put)': [
                ('exfiltration', 'T1048.002', 'Exfiltration Over Alternative Protocol: FTP', 'high')
            ],
            r'(?:s3|dropbox|drive|onedrive).*upload': [
                ('exfiltration', 'T1567.002', 'Exfiltration Over Web Service: Cloud Storage', 'high')
            ],
            r'curl.*-d|wget.*--post': [
                ('exfiltration', 'T1048.003', 'Exfiltration Over Alternative Protocol: HTTP/S', 'medium')
            ],
            r'(?:compress|encrypt).*before.*(?:send|transfer)': [
                ('exfiltration', 'T1560', 'Archive Collected Data', 'medium')
            ],
            r'dns.*(?:query|request).*data': [
                ('exfiltration', 'T1048.004', 'Exfiltration Over Alternative Protocol: DNS', 'high')
            ]
        })

        # ===== IMPACT (TA0040) =====
        patterns.update({
            r'(?:ransomware|crypto.*locker|wannacry)': [
                ('impact', 'T1486', 'Data Encrypted for Impact', 'critical')
            ],
            r'(?:wipe|shred|secure.*delete)': [
                ('impact', 'T1485', 'Data Destruction', 'critical')
            ],
            r'(?:defac|alter|modify).*(?:website|webpage)': [
                ('impact', 'T1491.001', 'Defacement: Internal Defacement', 'high')
            ],
            r'(?:ddos|dos|flood)': [
                ('impact', 'T1498', 'Network Denial of Service', 'critical')
            ],
            r'(?:shutdown|reboot|restart).*system': [
                ('impact', 'T1529', 'System Shutdown/Reboot', 'high')
            ],
            r'(?:corrupt|damage).*(?:data|file|disk)': [
                ('impact', 'T1565', 'Data Manipulation', 'critical')
            ],
            r'(?:fork.*bomb|resource.*exhaust)': [
                ('impact', 'T1499', 'Endpoint Denial of Service', 'high')
            ]
        })

        # ===== WEB APPLICATION ATTACKS =====
        patterns.update({
            r"(?:union.*select|'.*or.*'?1'?='?1)": [
                ('initial_access', 'T1190', 'Exploit Public-Facing Application: SQL Injection', 'critical')
            ],
            r'(?:<script|javascript:|onerror=|onload=)': [
                ('initial_access', 'T1190', 'Exploit Public-Facing Application: XSS', 'high')
            ],
            r'(?:\.\./|\.\.\\\|directory.*traversal|path.*traversal)': [
                ('initial_access', 'T1190', 'Exploit Public-Facing Application: Path Traversal', 'high')
            ],
            r'(?:xxe|xml.*external.*entity)': [
                ('initial_access', 'T1190', 'Exploit Public-Facing Application: XXE', 'high')
            ],
            r'(?:csrf|cross.*site.*request)': [
                ('initial_access', 'T1190', 'Exploit Public-Facing Application: CSRF', 'medium')
            ],
            r'(?:ssrf|server.*side.*request)': [
                ('initial_access', 'T1190', 'Exploit Public-Facing Application: SSRF', 'high')
            ],
            r'(?:rce|remote.*code.*execution)': [
                ('initial_access', 'T1190', 'Exploit Public-Facing Application: RCE', 'critical')
            ],
            r'(?:lfi|local.*file.*inclusion)': [
                ('initial_access', 'T1190', 'Exploit Public-Facing Application: LFI', 'high')
            ],
            r'(?:rfi|remote.*file.*inclusion)': [
                ('initial_access', 'T1190', 'Exploit Public-Facing Application: RFI', 'critical')
            ]
        })

        return patterns

    def map_to_attack(self, log_entry):
        """
        Map a log entry to MITRE ATT&CK techniques

        Args:
            log_entry: Dictionary containing log entry data

        Returns:
            List of matched ATT&CK techniques with metadata
        """
        matches = []
        raw_text = log_entry.get('raw', '').lower()

        for pattern, techniques in self.attack_patterns.items():
            if re.search(pattern, raw_text, re.IGNORECASE):
                for tactic, technique_id, technique_name, severity in techniques:
                    matches.append({
                        'tactic': tactic,
                        'tactic_id': self.tactics[tactic]['id'],
                        'tactic_name': self.tactics[tactic]['name'],
                        'technique_id': technique_id,
                        'technique_name': technique_name,
                        'severity': severity,
                        'timestamp': log_entry.get('timestamp'),
                        'matched_pattern': pattern,
                        'log_excerpt': raw_text[:200]
                    })

        return matches

    def analyze_attack_chain(self, entries):
        """
        Analyze log entries to identify potential attack chains

        Args:
            entries: List of log entries

        Returns:
            Dictionary with ATT&CK analysis results
        """
        all_matches = []
        tactic_counts = defaultdict(int)
        technique_counts = defaultdict(int)

        for entry in entries:
            matches = self.map_to_attack(entry)
            all_matches.extend(matches)

            for match in matches:
                tactic_counts[match['tactic']] += 1
                technique_counts[match['technique_id']] += 1

        # Identify attack chain (ordered tactics)
        attack_chain = self._identify_attack_chain(tactic_counts)

        # Get top techniques
        top_techniques = sorted(
            technique_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]

        return {
            'total_matches': len(all_matches),
            'matches': all_matches,
            'tactic_summary': dict(tactic_counts),
            'technique_summary': dict(technique_counts),
            'top_techniques': [
                {'technique_id': tid, 'count': count}
                for tid, count in top_techniques
            ],
            'attack_chain': attack_chain,
            'attack_chain_detected': len(attack_chain) >= 3,
            'severity_distribution': self._calculate_severity_distribution(all_matches)
        }

    def _identify_attack_chain(self, tactic_counts):
        """
        Identify which tactics were used to determine attack progression

        Args:
            tactic_counts: Dictionary of tactic counts

        Returns:
            List of tactics in typical attack chain order
        """
        # Typical attack chain order
        chain_order = [
            'reconnaissance',
            'resource_development',
            'initial_access',
            'execution',
            'persistence',
            'privilege_escalation',
            'defense_evasion',
            'credential_access',
            'discovery',
            'lateral_movement',
            'collection',
            'command_and_control',
            'exfiltration',
            'impact'
        ]

        detected_chain = [
            tactic for tactic in chain_order
            if tactic in tactic_counts and tactic_counts[tactic] > 0
        ]

        return detected_chain

    def _calculate_severity_distribution(self, matches):
        """Calculate distribution of severity levels"""
        severity_counts = defaultdict(int)
        for match in matches:
            severity_counts[match['severity']] += 1
        return dict(severity_counts)

    def get_mitre_url(self, technique_id):
        """Generate MITRE ATT&CK URL for a technique"""
        return f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"

    def generate_attack_report(self, analysis):
        """
        Generate a human-readable ATT&CK report

        Args:
            analysis: ATT&CK analysis results from analyze_attack_chain()

        Returns:
            Formatted report string
        """
        report = []
        report.append("=" * 60)
        report.append("MITRE ATT&CK ANALYSIS REPORT")
        report.append("=" * 60)
        report.append("")

        report.append(f"Total ATT&CK Technique Matches: {analysis['total_matches']}")
        report.append("")

        if analysis['attack_chain_detected']:
            report.append("WARNING: Multi-stage attack chain detected!")
            report.append("")

        report.append("Attack Chain Progression:")
        for i, tactic in enumerate(analysis['attack_chain'], 1):
            tactic_info = self.tactics[tactic]
            count = analysis['tactic_summary'][tactic]
            report.append(f"  {i}. {tactic_info['name']} ({tactic_info['id']}) - {count} occurrences")
        report.append("")

        report.append("Top Techniques Detected:")
        for tech in analysis['top_techniques'][:5]:
            report.append(f"  - {tech['technique_id']}: {tech['count']} occurrences")
            report.append(f"    {self.get_mitre_url(tech['technique_id'])}")
        report.append("")

        report.append("Severity Distribution:")
        for severity, count in analysis['severity_distribution'].items():
            report.append(f"  {severity.upper()}: {count}")

        return "\n".join(report)
