import requests
import time
from collections import defaultdict

class ThreatIntelligence:
    """Threat intelligence integration for IOC enrichment"""

    def __init__(self, abuseipdb_api_key=None):
        self.abuseipdb_api_key = abuseipdb_api_key
        self.cache = {}  # Simple in-memory cache
        self.rate_limit_delay = 1  # seconds between API calls

    def enrich_ips(self, ip_list):
        """Enrich IP addresses with threat intelligence"""
        enriched = {}

        for ip in ip_list[:50]:  # Limit to first 50 IPs to avoid rate limits
            if ip in self.cache:
                enriched[ip] = self.cache[ip]
                continue

            result = {
                'ip': ip,
                'is_private': self._is_private_ip(ip),
                'threat_score': 0,
                'abuse_reports': 0,
                'country': 'Unknown',
                'isp': 'Unknown',
                'threat_categories': [],
                'last_seen': None
            }

            # Only check public IPs
            if not result['is_private']:
                # Check AbuseIPDB if API key provided
                if self.abuseipdb_api_key:
                    abuse_data = self._check_abuseipdb(ip)
                    if abuse_data:
                        result['threat_score'] = abuse_data.get('abuseConfidenceScore', 0)
                        result['abuse_reports'] = abuse_data.get('totalReports', 0)
                        result['country'] = abuse_data.get('countryCode', 'Unknown')
                        result['isp'] = abuse_data.get('isp', 'Unknown')
                        result['last_seen'] = abuse_data.get('lastReportedAt')

                # Estimate threat level based on available data
                result['threat_level'] = self._calculate_threat_level(result)

            self.cache[ip] = result
            enriched[ip] = result

        return enriched

    def _check_abuseipdb(self, ip):
        """Check IP against AbuseIPDB"""
        if not self.abuseipdb_api_key:
            return None

        url = 'https://api.abuseipdb.com/api/v2/check'
        headers = {
            'Accept': 'application/json',
            'Key': self.abuseipdb_api_key
        }
        params = {
            'ipAddress': ip,
            'maxAgeInDays': '90',
            'verbose': ''
        }

        try:
            response = requests.get(url, headers=headers, params=params, timeout=5)
            time.sleep(self.rate_limit_delay)  # Rate limiting

            if response.status_code == 200:
                data = response.json()
                return data.get('data', {})
            else:
                return None
        except Exception as e:
            print(f"Error checking AbuseIPDB for {ip}: {e}")
            return None

    def _is_private_ip(self, ip):
        """Check if IP is private/local"""
        import re
        private_patterns = [
            r'^10\.',
            r'^172\.(1[6-9]|2[0-9]|3[0-1])\.',
            r'^192\.168\.',
            r'^127\.',
            r'^0\.',
            r'^169\.254\.',
            r'^::1$',
            r'^fe80:',
        ]
        return any(re.match(pattern, ip) for pattern in private_patterns)

    def _calculate_threat_level(self, result):
        """Calculate threat level based on available data"""
        score = result.get('threat_score', 0)

        if score >= 75:
            return 'Critical'
        elif score >= 50:
            return 'High'
        elif score >= 25:
            return 'Medium'
        elif score > 0:
            return 'Low'
        else:
            return 'Clean'

    def get_ip_reputation_summary(self, enriched_ips):
        """Generate summary of IP reputations"""
        summary = {
            'total_ips': len(enriched_ips),
            'private_ips': 0,
            'public_ips': 0,
            'threat_levels': defaultdict(int),
            'high_risk_ips': []
        }

        for ip, data in enriched_ips.items():
            if data['is_private']:
                summary['private_ips'] += 1
            else:
                summary['public_ips'] += 1

            threat_level = data.get('threat_level', 'Unknown')
            summary['threat_levels'][threat_level] += 1

            # Flag high-risk IPs
            if threat_level in ['Critical', 'High']:
                summary['high_risk_ips'].append({
                    'ip': ip,
                    'threat_score': data.get('threat_score', 0),
                    'country': data.get('country', 'Unknown'),
                    'abuse_reports': data.get('abuse_reports', 0)
                })

        return summary


# Simple GeoIP lookup using ip-api.com (free, no API key required)
class SimpleGeoIP:
    """Simple GeoIP lookup using free API"""

    def __init__(self):
        self.cache = {}
        self.api_url = "http://ip-api.com/json/{}"
        self.rate_limit_delay = 0.5  # 2 requests per second limit

    def lookup(self, ip):
        """Lookup IP geolocation"""
        if ip in self.cache:
            return self.cache[ip]

        # Skip private IPs
        if self._is_private_ip(ip):
            return {'ip': ip, 'country': 'Private', 'city': 'N/A', 'isp': 'N/A'}

        try:
            response = requests.get(self.api_url.format(ip), timeout=5)
            time.sleep(self.rate_limit_delay)

            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    result = {
                        'ip': ip,
                        'country': data.get('country', 'Unknown'),
                        'countryCode': data.get('countryCode', 'Unknown'),
                        'city': data.get('city', 'Unknown'),
                        'lat': data.get('lat'),
                        'lon': data.get('lon'),
                        'isp': data.get('isp', 'Unknown'),
                        'org': data.get('org', 'Unknown')
                    }
                    self.cache[ip] = result
                    return result
        except Exception as e:
            print(f"Error looking up {ip}: {e}")

        return {'ip': ip, 'country': 'Unknown', 'city': 'Unknown', 'isp': 'Unknown'}

    def lookup_batch(self, ip_list):
        """Lookup multiple IPs"""
        results = {}
        for ip in ip_list[:20]:  # Limit to 20 to respect rate limits
            results[ip] = self.lookup(ip)
        return results

    def _is_private_ip(self, ip):
        """Check if IP is private/local"""
        import re
        private_patterns = [
            r'^10\.',
            r'^172\.(1[6-9]|2[0-9]|3[0-1])\.',
            r'^192\.168\.',
            r'^127\.',
            r'^0\.',
        ]
        return any(re.match(pattern, ip) for pattern in private_patterns)
