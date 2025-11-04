# Forensic Log Analyzer

A professional, easy-to-use web-based platform for forensic log analysis and threat detection. Built specifically for cybersecurity analysts who need quick, flexible log analysis without complex setup.

## 🎯 Features

### Automatic Log Parsing
- **Multiple Format Support**: Automatically detects and parses:
  - Apache/Nginx access logs
  - IIS web server logs
  - Linux Syslog
  - Windows Event Logs (XML)
  - JSON logs
  - CSV logs
  - Generic text logs

### Forensic Analysis
- **IOC Extraction**: Automatically extracts:
  - IPv4 and IPv6 addresses
  - Domain names and URLs
  - Email addresses
  - File hashes (MD5, SHA1, SHA256)
  - Usernames
  - File paths

- **Anomaly Detection**:
  - Unusual activity timing (off-hours access)
  - Logging gaps (potential tampering)
  - Frequency anomalies (repeated events)
  - Volume spikes (DDoS, data exfiltration)

- **Pattern Recognition**:
  - Failed login attempts
  - Privilege escalation attempts
  - Lateral movement indicators
  - Command execution
  - Data exfiltration patterns

### Analysis Features
- **Timeline View**: Chronological visualization of all events
- **Search**: Full-text search across all log entries
- **Export**: Export results as JSON or IOC lists
- **Real-time Analysis**: Instant results after upload

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- Modern web browser (Chrome, Firefox, Safari, Edge)

### Installation

#### Option 1: Automatic Setup (Recommended)
```bash
cd log-analyzer
chmod +x setup.sh
./setup.sh
```

#### Option 2: Manual Setup
```bash
cd log-analyzer

# Create virtual environment (optional but recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt --break-system-packages
```

### Running the Application

```bash
# If using virtual environment
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Start the server
python3 app.py
```

Open your browser to: **http://localhost:5000**

## 📖 Usage Guide

### 1. Upload Logs
- Drag and drop log files onto the upload area, or
- Click to browse and select files
- Supported formats are automatically detected

### 2. View Analysis
After upload, you'll immediately see:
- **Overview Tab**: File info, statistics, and suspicious activity summary
- **Timeline Tab**: Chronological event timeline
- **IOCs Tab**: All extracted indicators of compromise
- **Anomalies Tab**: Detected anomalies with severity levels
- **Search Tab**: Search through all log entries

### 3. Export Results
- **Export Full Report**: Complete analysis in JSON format
- **Export IOCs**: Text file with all IOCs for import into SIEM/IDS

## 🎨 Interface Overview

### Dashboard Tabs

#### Overview
- File metadata and format detection
- Entry count and date range
- Suspicious activity alerts
- Quick statistics

#### Timeline
- Chronological event listing
- Timestamp correlation
- Event summaries

#### IOCs
- Categorized indicators
- IP addresses, domains, hashes
- Usernames and file paths

#### Anomalies
- Severity-coded alerts (High/Medium/Low)
- Timing anomalies
- Frequency spikes
- Logging gaps

#### Search
- Full-text search
- Field-specific filtering
- Result previews

## 📁 Supported Log Formats

### Apache/Nginx Access Logs
```
192.168.1.100 - - [01/Jan/2024:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234
```

### Syslog
```
Jan 1 12:00:00 server sshd[1234]: Failed password for admin from 10.0.0.1
```

### JSON Logs
```json
{"timestamp": "2024-01-01T12:00:00Z", "level": "ERROR", "message": "Authentication failed"}
```

### CSV Logs
```csv
timestamp,source_ip,event_type,status
2024-01-01 12:00:00,192.168.1.100,login,failed
```

### Windows Event Logs (XML)
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4625</EventID>
  </System>
</Event>
```

## 🔧 Configuration

### Port Configuration
Edit `app.py` to change the port:
```python
app.run(debug=True, host='0.0.0.0', port=5000)
```

### File Size Limit
Edit `app.py` to change maximum upload size:
```python
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB
```

## 🛡️ Security Best Practices

1. **Network Access**: By default, the app binds to `0.0.0.0` for easy access. For production:
   - Use a reverse proxy (nginx, Apache)
   - Enable HTTPS/TLS
   - Restrict to localhost or specific IPs

2. **Authentication**: This prototype doesn't include authentication. For production:
   - Add user authentication
   - Implement role-based access control
   - Use session management

3. **Data Storage**: Currently stores data in memory. For production:
   - Use a database (PostgreSQL, MongoDB)
   - Implement data retention policies
   - Add encryption for sensitive logs

## 📊 Example Use Cases

### Incident Response
1. Upload server logs from compromised system
2. Review Timeline for attack progression
3. Check Anomalies for unusual patterns
4. Export IOCs for blocking/monitoring

### Threat Hunting
1. Upload logs from multiple sources
2. Search for specific IOCs or patterns
3. Identify lateral movement indicators
4. Generate reports for documentation

### Compliance & Audit
1. Upload audit logs
2. Review access patterns
3. Identify policy violations
4. Export reports for compliance

## 🐛 Troubleshooting

### "Module not found" errors
```bash
pip install -r requirements.txt --break-system-packages
```

### Port already in use
Change the port in `app.py` or kill the process using port 5000:
```bash
# Find process
lsof -i :5000

# Kill process
kill -9 <PID>
```

### File upload fails
- Check file size (default limit: 100MB)
- Ensure file is readable
- Check file encoding (UTF-8 preferred)

## 🔄 Future Enhancements

Potential additions for production use:
- Database integration for persistent storage
- User authentication and authorization
- Multi-file analysis and correlation
- Real-time log streaming
- Machine learning-based anomaly detection
- Integration with SIEM platforms
- Custom rule creation
- Report scheduling and automation
- API endpoints for automation

## 📝 Technical Details

### Architecture
- **Backend**: Python Flask
- **Frontend**: HTML5, CSS3, JavaScript (Vanilla)
- **Parsing**: Custom multi-format parser
- **Analysis**: Pattern matching and statistical analysis

### Dependencies
- Flask 3.0.0: Web framework
- python-dateutil: Timestamp parsing
- pandas: Data analysis
- python-evtx: Windows Event Log parsing (optional)

### File Structure
```
log-analyzer/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── setup.sh              # Setup script
├── parsers/
│   ├── log_parser.py     # Multi-format log parser
│   └── forensic_analyzer.py  # Analysis engine
├── templates/
│   └── index.html        # Web interface
├── static/
│   ├── css/
│   │   └── style.css     # Styling
│   └── js/
│       └── app.js        # Frontend logic
└── uploads/              # Temporary file storage
```

## 🤝 Contributing

This is a prototype application. Suggestions for improvements:
- Additional log format support
- Enhanced anomaly detection algorithms
- Performance optimizations for large files
- Additional export formats

## ⚠️ Disclaimer

This tool is designed for cybersecurity professionals conducting authorized log analysis. Always ensure you have proper authorization before analyzing logs, and handle all log data according to your organization's data handling and privacy policies.

## 📄 License

This is a prototype tool created for professional cybersecurity analysis purposes.

---

**Need Help?** 
- Check the troubleshooting section above
- Review the example log formats
- Ensure all dependencies are installed correctly

**Ready to analyze logs?** Run `python3 app.py` and visit http://localhost:5000
