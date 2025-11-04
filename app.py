from flask import Flask, render_template, request, jsonify, send_file
import os
import json
import gzip
import zipfile
import tarfile
import tempfile
from datetime import datetime
from werkzeug.utils import secure_filename
from parsers.log_parser import LogParser
from parsers.forensic_analyzer import ForensicAnalyzer
from parsers.threat_intelligence import SimpleGeoIP, ThreatIntelligence
from parsers.database import AnalysisDatabase

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB max file size
app.config['SECRET_KEY'] = 'forensic-log-analyzer-secret-key-change-in-production'

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize database
db = AnalysisDatabase()

# In-memory storage for analysis results (for quick access)
analyses = {}

def extract_compressed_file(filepath):
    """Extract compressed files and return path to extracted content"""
    filename = os.path.basename(filepath)

    # Handle .gz files
    if filename.endswith('.gz'):
        if filename.endswith('.tar.gz'):
            # Handle tar.gz
            with tarfile.open(filepath, 'r:gz') as tar:
                # Extract first text file found
                for member in tar.getmembers():
                    if member.isfile() and not member.name.startswith('.'):
                        extracted = tar.extractfile(member)
                        temp_file = tempfile.NamedTemporaryFile(delete=False, mode='wb')
                        temp_file.write(extracted.read())
                        temp_file.close()
                        return temp_file.name
        else:
            # Handle gzip
            temp_file = tempfile.NamedTemporaryFile(delete=False, mode='wb')
            with gzip.open(filepath, 'rb') as gz:
                temp_file.write(gz.read())
            temp_file.close()
            return temp_file.name

    # Handle .zip files
    elif filename.endswith('.zip'):
        with zipfile.ZipFile(filepath, 'r') as zip_ref:
            # Extract first text file found
            for name in zip_ref.namelist():
                if not name.startswith('.') and not name.endswith('/'):
                    temp_file = tempfile.NamedTemporaryFile(delete=False, mode='wb')
                    temp_file.write(zip_ref.read(name))
                    temp_file.close()
                    return temp_file.name

    # Handle .tar files
    elif filename.endswith('.tar'):
        with tarfile.open(filepath, 'r') as tar:
            for member in tar.getmembers():
                if member.isfile() and not member.name.startswith('.'):
                    extracted = tar.extractfile(member)
                    temp_file = tempfile.NamedTemporaryFile(delete=False, mode='wb')
                    temp_file.write(extracted.read())
                    temp_file.close()
                    return temp_file.name

    # Return original if not compressed
    return filepath

@app.route('/')
def index():
    """Render the main application page"""
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload and initiate analysis"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if file:
        # Save the uploaded file
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        extracted_path = None
        try:
            # Extract if compressed
            extracted_path = extract_compressed_file(filepath)

            # Parse the log file
            parser = LogParser()
            parsed_data = parser.parse_file(extracted_path)

            # Get custom patterns if provided
            custom_patterns = request.form.get('custom_patterns')
            if custom_patterns:
                try:
                    custom_patterns = json.loads(custom_patterns)
                except:
                    custom_patterns = None

            # Perform forensic analysis
            analyzer = ForensicAnalyzer(custom_patterns=custom_patterns)
            analysis_results = analyzer.analyze(parsed_data)

            # Generate unique analysis ID
            analysis_id = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}"

            # Store results in memory
            analyses[analysis_id] = {
                'filename': filename,
                'upload_time': datetime.now().isoformat(),
                'parsed_data': parsed_data,
                'analysis': analysis_results
            }

            # Save to database for persistence
            db.save_analysis(analysis_id, analyses[analysis_id])

            # Clean up uploaded files
            if os.path.exists(filepath):
                os.remove(filepath)
            if extracted_path and extracted_path != filepath and os.path.exists(extracted_path):
                os.remove(extracted_path)

            return jsonify({
                'success': True,
                'analysis_id': analysis_id,
                'message': 'File analyzed successfully'
            })

        except Exception as e:
            # Clean up on error
            if os.path.exists(filepath):
                os.remove(filepath)
            if extracted_path and extracted_path != filepath and os.path.exists(extracted_path):
                os.remove(extracted_path)
            return jsonify({'error': f'Analysis failed: {str(e)}'}), 500

@app.route('/analyze/<analysis_id>')
def get_analysis(analysis_id):
    """Retrieve analysis results"""
    # Check memory first
    if analysis_id in analyses:
        return jsonify(analyses[analysis_id])

    # Try loading from database
    data = db.load_analysis(analysis_id)
    if data:
        # Cache in memory
        analyses[analysis_id] = data
        return jsonify(data)

    return jsonify({'error': 'Analysis not found'}), 404

@app.route('/export/<analysis_id>')
def export_analysis(analysis_id):
    """Export analysis results"""
    if analysis_id not in analyses:
        return jsonify({'error': 'Analysis not found'}), 404

    export_format = request.args.get('format', 'json')
    data = analyses[analysis_id]

    if export_format == 'json':
        # Export full analysis as JSON
        output_file = f"exports/{analysis_id}_report.json"
        os.makedirs('exports', exist_ok=True)

        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2, default=str)

        return send_file(output_file, as_attachment=True, download_name=f"{analysis_id}_report.json")

    elif export_format == 'iocs':
        # Export IOCs only
        iocs = data['analysis']['iocs']
        output_file = f"exports/{analysis_id}_iocs.txt"
        os.makedirs('exports', exist_ok=True)

        with open(output_file, 'w') as f:
            f.write("# Indicators of Compromise\n")
            f.write(f"# Generated: {datetime.now().isoformat()}\n")
            f.write(f"# Source: {data['filename']}\n\n")

            for ioc_type, values in iocs.items():
                if values:
                    f.write(f"\n## {ioc_type.upper()}\n")
                    for value in values:
                        f.write(f"{value}\n")

        return send_file(output_file, as_attachment=True, download_name=f"{analysis_id}_iocs.txt")

    else:
        return jsonify({'error': 'Invalid export format'}), 400

@app.route('/enrich/<analysis_id>')
def enrich_analysis(analysis_id):
    """Enrich analysis with threat intelligence and GeoIP data"""
    if analysis_id not in analyses:
        return jsonify({'error': 'Analysis not found'}), 404

    data = analyses[analysis_id]
    iocs = data['analysis']['iocs']

    # Get IP addresses
    ipv4_list = iocs.get('ipv4', [])
    ipv6_list = iocs.get('ipv6', [])
    all_ips = ipv4_list + ipv6_list

    if not all_ips:
        return jsonify({'error': 'No IPs found to enrich'}), 400

    # GeoIP lookup
    geoip = SimpleGeoIP()
    geoip_data = geoip.lookup_batch(all_ips)

    # Threat intelligence (if API key provided in config)
    api_key = os.environ.get('ABUSEIPDB_API_KEY')
    threat_data = None
    threat_summary = None

    if api_key:
        threat_intel = ThreatIntelligence(abuseipdb_api_key=api_key)
        threat_data = threat_intel.enrich_ips(all_ips)
        threat_summary = threat_intel.get_ip_reputation_summary(threat_data)

    # Store enrichment data
    if 'enrichment' not in data:
        data['enrichment'] = {}

    data['enrichment']['geoip'] = geoip_data
    data['enrichment']['threat_intel'] = threat_data
    data['enrichment']['threat_summary'] = threat_summary
    data['enrichment']['enriched_at'] = datetime.now().isoformat()

    return jsonify({
        'success': True,
        'geoip': geoip_data,
        'threat_intel': threat_data,
        'threat_summary': threat_summary
    })

@app.route('/history')
def list_history():
    """List all saved analyses"""
    limit = request.args.get('limit', 50, type=int)
    analyses_list = db.list_analyses(limit=limit)
    return jsonify({'analyses': analyses_list})

@app.route('/search')
def search_ioc():
    """Search for IOC across all analyses"""
    query = request.args.get('q', '')
    if not query:
        return jsonify({'error': 'Query parameter required'}), 400

    results = db.search_iocs(query)
    return jsonify({'results': results})

@app.route('/stats')
def get_stats():
    """Get database statistics"""
    stats = db.get_statistics()
    return jsonify(stats)

@app.route('/delete/<analysis_id>', methods=['DELETE'])
def delete_analysis(analysis_id):
    """Delete an analysis"""
    success = db.delete_analysis(analysis_id)
    if success:
        # Remove from memory cache if present
        if analysis_id in analyses:
            del analyses[analysis_id]
        return jsonify({'success': True})
    return jsonify({'error': 'Failed to delete analysis'}), 500

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'version': '2.0.0'})

if __name__ == '__main__':
    print("=" * 60)
    print("Forensic Log Analyzer")
    print("=" * 60)
    print(f"Starting server on http://localhost:5000")
    print("Press CTRL+C to stop")
    print("=" * 60)
    app.run(debug=True, host='0.0.0.0', port=5000)
