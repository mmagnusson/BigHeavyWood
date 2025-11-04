import re
from collections import Counter, defaultdict
from datetime import datetime
from dateutil import parser as date_parser

class ForensicAnalyzer:
    """Forensic analysis engine for log data"""

    def __init__(self, custom_patterns=None):
        # IOC patterns
        self.ioc_patterns = {
            'ipv4': re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
            'ipv6': re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'),
            'domain': re.compile(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b', re.IGNORECASE),
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
            'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
            'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
            'url': re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+'),
            'filepath': re.compile(r'(?:[a-zA-Z]:\\|/)[^\s<>"\'|*?]+'),
        }

        # Suspicious patterns
        self.suspicious_patterns = {
            'failed_login': r'(?:failed|invalid|unauthorized|denied).*(?:login|auth|access|password)',
            'privilege_escalation': r'(?:sudo|su|admin|root|privilege|elevation)',
            'lateral_movement': r'(?:psexec|wmic|schtasks|net use|rdp|ssh)',
            'command_execution': r'(?:cmd\.exe|powershell|bash|sh|execute)',
            'data_exfiltration': r'(?:download|export|copy|transfer|ftp|scp)',
            'sql_injection': r'(?:union.*select|sleep\(|benchmark\(|\'.*or.*1=1)',
            'xss': r'(?:<script|javascript:|onerror=|onload=)',
            'path_traversal': r'(?:\.\./|\.\.\\|etc/passwd|windows/system)',
            'reconnaissance': r'(?:scan|probe|enumerate|discover)',
        }

        # Add custom patterns if provided
        if custom_patterns:
            for name, pattern in custom_patterns.items():
                self.suspicious_patterns[f"custom_{name}"] = pattern

    def analyze(self, parsed_data):
        """Perform comprehensive forensic analysis"""
        entries = parsed_data['entries']

        # Extract IOCs
        iocs = self._extract_iocs(entries)

        # Detect anomalies
        anomalies = self._detect_anomalies(entries)

        # Find suspicious patterns
        suspicious = self._find_suspicious_patterns(entries)

        # Build timeline
        timeline = self._build_timeline(entries)

        # Calculate statistics
        stats = self._calculate_statistics(entries, iocs, anomalies, suspicious)

        return {
            'iocs': iocs,
            'anomalies': anomalies,
            'suspicious_activity': suspicious,
            'timeline': timeline,
            'statistics': stats
        }

    def _extract_iocs(self, entries):
        """Extract Indicators of Compromise"""
        iocs = defaultdict(set)

        for entry in entries:
            raw_text = entry.get('raw', '')

            # Extract each IOC type
            for ioc_type, pattern in self.ioc_patterns.items():
                matches = pattern.findall(raw_text)
                for match in matches:
                    # Filter out common false positives
                    if ioc_type in ['ipv4', 'ipv6']:
                        # Skip private/local IPs for external threat focus
                        if not self._is_private_ip(match):
                            iocs[ioc_type].add(match)
                    elif ioc_type == 'domain':
                        # Skip common non-threat domains
                        if not self._is_common_domain(match):
                            iocs[ioc_type].add(match)
                    else:
                        iocs[ioc_type].add(match)

        # Convert sets to sorted lists
        return {k: sorted(list(v)) for k, v in iocs.items()}

    def _detect_anomalies(self, entries):
        """Detect anomalies in log data"""
        anomalies = []

        # Time-based anomalies
        time_anomalies = self._detect_time_anomalies(entries)
        anomalies.extend(time_anomalies)

        # Frequency anomalies
        frequency_anomalies = self._detect_frequency_anomalies(entries)
        anomalies.extend(frequency_anomalies)

        # Volume anomalies
        volume_anomalies = self._detect_volume_anomalies(entries)
        anomalies.extend(volume_anomalies)

        # Gap detection (possible log tampering)
        gap_anomalies = self._detect_gaps(entries)
        anomalies.extend(gap_anomalies)

        return anomalies

    def _find_suspicious_patterns(self, entries):
        """Find suspicious patterns in logs"""
        suspicious = []

        for entry in entries:
            raw_text = entry.get('raw', '').lower()

            for pattern_name, pattern in self.suspicious_patterns.items():
                if re.search(pattern, raw_text, re.IGNORECASE):
                    suspicious.append({
                        'type': pattern_name,
                        'timestamp': entry.get('timestamp'),
                        'entry': entry.get('raw', '')[:200],  # First 200 chars
                        'severity': self._calculate_severity(pattern_name)
                    })

        return suspicious

    def _build_timeline(self, entries):
        """Build chronological timeline"""
        timeline = []

        for entry in entries:
            if entry.get('timestamp'):
                timeline.append({
                    'timestamp': entry['timestamp'],
                    'summary': self._create_summary(entry),
                    'full_entry': entry.get('raw', '')
                })

        # Sort by timestamp
        timeline.sort(key=lambda x: x['timestamp'] if x['timestamp'] else '')

        return timeline[:1000]  # Limit to 1000 most recent entries

    def _calculate_statistics(self, entries, iocs, anomalies, suspicious):
        """Calculate summary statistics"""
        timestamps = [e['timestamp'] for e in entries if e.get('timestamp')]

        stats = {
            'total_entries': len(entries),
            'date_range': {
                'start': min(timestamps) if timestamps else None,
                'end': max(timestamps) if timestamps else None
            },
            'ioc_counts': {k: len(v) for k, v in iocs.items()},
            'anomaly_count': len(anomalies),
            'suspicious_count': len(suspicious),
            'severity_breakdown': self._calculate_severity_breakdown(suspicious)
        }

        return stats

    def _detect_time_anomalies(self, entries):
        """Detect unusual timing patterns"""
        anomalies = []
        timestamps = []

        for entry in entries:
            if entry.get('timestamp'):
                try:
                    dt = date_parser.parse(entry['timestamp'])
                    timestamps.append((dt, entry))
                except:
                    continue

        # Check for off-hours activity (2 AM - 5 AM)
        for dt, entry in timestamps:
            if 2 <= dt.hour <= 5:
                anomalies.append({
                    'type': 'off_hours_activity',
                    'severity': 'medium',
                    'timestamp': entry['timestamp'],
                    'description': f'Activity detected during unusual hours ({dt.hour}:00)',
                    'entry': entry.get('raw', '')[:200]
                })

        return anomalies

    def _detect_frequency_anomalies(self, entries):
        """Detect unusual frequency patterns"""
        anomalies = []

        # Count events by source IP or user
        sources = []
        for entry in entries:
            parsed = entry.get('parsed', {})
            source = parsed.get('ip') or parsed.get('source_ip') or parsed.get('client_ip')
            if source:
                sources.append(source)

        if sources:
            source_counts = Counter(sources)
            avg_count = sum(source_counts.values()) / len(source_counts)

            # Flag sources with unusually high frequency (5x average)
            for source, count in source_counts.items():
                if count > avg_count * 5:
                    anomalies.append({
                        'type': 'high_frequency',
                        'severity': 'high',
                        'description': f'Unusually high activity from {source}: {count} events',
                        'details': {'source': source, 'count': count, 'average': round(avg_count, 2)}
                    })

        return anomalies

    def _detect_volume_anomalies(self, entries):
        """Detect volume spikes"""
        anomalies = []

        # Group entries by hour
        hourly_counts = defaultdict(int)
        for entry in entries:
            if entry.get('timestamp'):
                try:
                    dt = date_parser.parse(entry['timestamp'])
                    hour_key = dt.strftime('%Y-%m-%d %H:00')
                    hourly_counts[hour_key] += 1
                except:
                    continue

        if hourly_counts:
            counts = list(hourly_counts.values())
            avg_count = sum(counts) / len(counts)

            # Flag hours with 3x average volume
            for hour, count in hourly_counts.items():
                if count > avg_count * 3:
                    anomalies.append({
                        'type': 'volume_spike',
                        'severity': 'medium',
                        'description': f'Volume spike detected at {hour}: {count} events',
                        'details': {'hour': hour, 'count': count, 'average': round(avg_count, 2)}
                    })

        return anomalies

    def _detect_gaps(self, entries):
        """Detect gaps in logging (possible tampering)"""
        anomalies = []
        timestamps = []

        for entry in entries:
            if entry.get('timestamp'):
                try:
                    dt = date_parser.parse(entry['timestamp'])
                    timestamps.append(dt)
                except:
                    continue

        if len(timestamps) > 1:
            timestamps.sort()

            # Check for gaps larger than 1 hour
            for i in range(len(timestamps) - 1):
                gap = (timestamps[i + 1] - timestamps[i]).total_seconds()
                if gap > 3600:  # 1 hour
                    anomalies.append({
                        'type': 'logging_gap',
                        'severity': 'high',
                        'description': f'Logging gap detected: {gap / 3600:.1f} hours',
                        'details': {
                            'gap_start': timestamps[i].isoformat(),
                            'gap_end': timestamps[i + 1].isoformat(),
                            'duration_hours': round(gap / 3600, 2)
                        }
                    })

        return anomalies

    def _calculate_severity(self, pattern_name):
        """Calculate severity level for suspicious patterns"""
        high_severity = ['sql_injection', 'privilege_escalation', 'lateral_movement', 'data_exfiltration']
        medium_severity = ['failed_login', 'command_execution', 'path_traversal']

        if pattern_name in high_severity:
            return 'high'
        elif pattern_name in medium_severity:
            return 'medium'
        else:
            return 'low'

    def _calculate_severity_breakdown(self, suspicious):
        """Calculate breakdown of suspicious activity by severity"""
        breakdown = Counter([s['severity'] for s in suspicious])
        return dict(breakdown)

    def _create_summary(self, entry):
        """Create a brief summary of a log entry"""
        parsed = entry.get('parsed', {})

        # Try to create meaningful summary based on available fields
        if 'request' in parsed:
            return f"Request: {parsed['request'][:100]}"
        elif 'message' in parsed:
            return parsed['message'][:100]
        elif 'event_type' in parsed:
            return f"Event: {parsed['event_type']}"
        else:
            return entry.get('raw', '')[:100]

    def _is_private_ip(self, ip):
        """Check if IP is private/local"""
        private_patterns = [
            r'^10\.',
            r'^172\.(1[6-9]|2[0-9]|3[0-1])\.',
            r'^192\.168\.',
            r'^127\.',
            r'^0\.',
        ]
        return any(re.match(pattern, ip) for pattern in private_patterns)

    def _is_common_domain(self, domain):
        """Filter out common non-threat domains"""
        common = ['localhost', 'example.com', 'test.com', 'local']
        return any(c in domain.lower() for c in common)
