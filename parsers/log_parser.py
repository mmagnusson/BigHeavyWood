import re
import json
from datetime import datetime
from dateutil import parser as date_parser

class LogParser:
    """Multi-format log parser with automatic format detection"""

    def __init__(self):
        self.format_patterns = {
            'apache': re.compile(r'^(\S+) (\S+) (\S+) \[([^\]]+)\] "([^"]*)" (\d+) (\d+)'),
            'nginx': re.compile(r'^(\S+) - (\S+) \[([^\]]+)\] "([^"]*)" (\d+) (\d+) "([^"]*)" "([^"]*)"'),
            'syslog': re.compile(r'^(\w+\s+\d+\s+\d+:\d+:\d+) (\S+) ([^:]+):\s*(.*)'),
            'iis': None,  # Special handling for W3C Extended Log Format
            'json': None,  # Special handling
            'csv': None,   # Special handling
        }
        self.iis_fields = None  # Will store IIS field names from #Fields: line

    def parse_file(self, filepath):
        """Parse a log file and return structured data"""
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        # Detect format
        log_format = self._detect_format(content)

        # Parse based on detected format
        if log_format == 'json':
            entries = self._parse_json(content)
        elif log_format == 'csv':
            entries = self._parse_csv(content)
        elif log_format == 'iis':
            entries = self._parse_iis(content)
        elif log_format in self.format_patterns:
            entries = self._parse_text_log(content, log_format)
        else:
            entries = self._parse_generic(content)

        return {
            'format': log_format,
            'entry_count': len(entries),
            'entries': entries,
            'raw_sample': content[:1000]  # First 1000 chars for reference
        }

    def _detect_format(self, content):
        """Automatically detect log format"""
        lines = content.strip().split('\n')
        first_line = lines[0] if lines else ''

        # Check for IIS W3C Extended Log Format (must be checked early)
        if first_line.startswith('#Software:') or first_line.startswith('#Version:') or first_line.startswith('#Fields:'):
            return 'iis'

        # Look for #Fields: in first few lines (IIS header)
        for line in lines[:10]:
            if line.startswith('#Fields:'):
                return 'iis'

        # Check for JSON
        if first_line.startswith('{'):
            try:
                json.loads(first_line)
                return 'json'
            except:
                pass

        # Check for CSV
        if ',' in first_line and not re.search(r'\[|\]|\{|\}', first_line):
            return 'csv'

        # Check for Apache/Nginx
        if self.format_patterns['apache'].match(first_line):
            return 'apache'
        if self.format_patterns['nginx'].match(first_line):
            return 'nginx'

        # Check for Syslog
        if self.format_patterns['syslog'].match(first_line):
            return 'syslog'

        return 'generic'

    def _parse_json(self, content):
        """Parse JSON format logs"""
        entries = []
        for line in content.strip().split('\n'):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
                # Normalize timestamp field
                timestamp = self._extract_timestamp(entry)
                entries.append({
                    'timestamp': timestamp,
                    'raw': line,
                    'parsed': entry
                })
            except json.JSONDecodeError:
                continue
        return entries

    def _parse_csv(self, content):
        """Parse CSV format logs"""
        entries = []
        lines = content.strip().split('\n')
        if not lines:
            return entries

        # Assume first line is header
        headers = [h.strip() for h in lines[0].split(',')]

        for line in lines[1:]:
            if not line.strip():
                continue
            values = [v.strip() for v in line.split(',')]
            if len(values) != len(headers):
                continue

            entry = dict(zip(headers, values))
            timestamp = self._extract_timestamp(entry)

            entries.append({
                'timestamp': timestamp,
                'raw': line,
                'parsed': entry
            })

        return entries

    def _parse_iis(self, content):
        """Parse IIS W3C Extended Log Format"""
        entries = []
        lines = content.strip().split('\n')
        fields = None
        metadata = {}

        for line in lines:
            # Skip empty lines
            if not line.strip():
                continue

            # Parse header metadata
            if line.startswith('#'):
                if line.startswith('#Fields:'):
                    # Extract field names
                    fields = line[8:].strip().split()
                elif line.startswith('#Software:'):
                    metadata['software'] = line[10:].strip()
                elif line.startswith('#Version:'):
                    metadata['version'] = line[9:].strip()
                elif line.startswith('#Date:'):
                    metadata['log_date'] = line[6:].strip()
                continue

            # Parse data lines (only if we have field definitions)
            if fields:
                values = line.split()

                # Ensure we have the right number of values
                if len(values) != len(fields):
                    continue

                # Create entry dictionary
                entry = dict(zip(fields, values))

                # Extract timestamp
                timestamp = self._extract_timestamp(entry)

                entries.append({
                    'timestamp': timestamp,
                    'raw': line,
                    'parsed': entry,
                    'metadata': metadata
                })

        return entries

    def _parse_text_log(self, content, log_format):
        """Parse text-based logs (Apache, Nginx, Syslog, IIS)"""
        entries = []
        pattern = self.format_patterns[log_format]

        for line in content.strip().split('\n'):
            if not line.strip() or line.startswith('#'):
                continue

            match = pattern.match(line)
            if match:
                if log_format == 'apache':
                    entry = {
                        'ip': match.group(1),
                        'ident': match.group(2),
                        'user': match.group(3),
                        'timestamp': match.group(4),
                        'request': match.group(5),
                        'status': match.group(6),
                        'size': match.group(7)
                    }
                elif log_format == 'nginx':
                    entry = {
                        'ip': match.group(1),
                        'user': match.group(2),
                        'timestamp': match.group(3),
                        'request': match.group(4),
                        'status': match.group(5),
                        'size': match.group(6),
                        'referrer': match.group(7),
                        'user_agent': match.group(8)
                    }
                elif log_format == 'syslog':
                    entry = {
                        'timestamp': match.group(1),
                        'host': match.group(2),
                        'process': match.group(3),
                        'message': match.group(4)
                    }

                timestamp = self._extract_timestamp(entry)
                entries.append({
                    'timestamp': timestamp,
                    'raw': line,
                    'parsed': entry
                })

        return entries

    def _parse_generic(self, content):
        """Parse generic text logs"""
        entries = []
        for line in content.strip().split('\n'):
            if not line.strip():
                continue

            timestamp = self._extract_timestamp_from_text(line)
            entries.append({
                'timestamp': timestamp,
                'raw': line,
                'parsed': {'message': line}
            })

        return entries

    def _extract_timestamp(self, entry):
        """Extract and normalize timestamp from parsed entry"""
        timestamp_fields = ['timestamp', 'time', 'datetime', '@timestamp', 'date']

        for field in timestamp_fields:
            if field in entry:
                try:
                    dt = date_parser.parse(str(entry[field]))
                    return dt.isoformat()
                except:
                    continue

        # Try combining date and time fields
        if 'date' in entry and 'time' in entry:
            try:
                dt = date_parser.parse(f"{entry['date']} {entry['time']}")
                return dt.isoformat()
            except:
                pass

        return None

    def _extract_timestamp_from_text(self, text):
        """Extract timestamp from raw text line"""
        # Common timestamp patterns
        patterns = [
            r'\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}',
            r'\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}',
            r'\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}',
        ]

        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                try:
                    dt = date_parser.parse(match.group(0))
                    return dt.isoformat()
                except:
                    continue

        return None
