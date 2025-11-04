import sqlite3
import json
from datetime import datetime
import os

class AnalysisDatabase:
    """SQLite database for persistent analysis storage"""

    def __init__(self, db_path='analysis_data.db'):
        self.db_path = db_path
        self.init_database()

    def init_database(self):
        """Initialize database tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Create analyses table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS analyses (
                id TEXT PRIMARY KEY,
                filename TEXT NOT NULL,
                upload_time TEXT NOT NULL,
                format TEXT,
                entry_count INTEGER,
                parsed_data TEXT,
                analysis_results TEXT,
                enrichment_data TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Create IOCs table for quick searching
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id TEXT NOT NULL,
                ioc_type TEXT NOT NULL,
                ioc_value TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (analysis_id) REFERENCES analyses(id)
            )
        ''')

        # Create index for faster searches
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_iocs_value
            ON iocs(ioc_value)
        ''')

        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_iocs_type
            ON iocs(ioc_type)
        ''')

        conn.commit()
        conn.close()

    def save_analysis(self, analysis_id, analysis_data):
        """Save analysis to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            # Extract key fields
            filename = analysis_data.get('filename', 'unknown')
            upload_time = analysis_data.get('upload_time', datetime.now().isoformat())
            parsed_data = analysis_data.get('parsed_data', {})
            analysis_results = analysis_data.get('analysis', {})
            enrichment_data = analysis_data.get('enrichment', {})

            log_format = parsed_data.get('format', 'unknown')
            entry_count = parsed_data.get('entry_count', 0)

            # Insert or replace analysis
            cursor.execute('''
                INSERT OR REPLACE INTO analyses
                (id, filename, upload_time, format, entry_count, parsed_data, analysis_results, enrichment_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                analysis_id,
                filename,
                upload_time,
                log_format,
                entry_count,
                json.dumps(parsed_data, default=str),
                json.dumps(analysis_results, default=str),
                json.dumps(enrichment_data, default=str)
            ))

            # Save IOCs for quick searching
            iocs = analysis_results.get('iocs', {})
            for ioc_type, values in iocs.items():
                for value in values:
                    cursor.execute('''
                        INSERT INTO iocs (analysis_id, ioc_type, ioc_value)
                        VALUES (?, ?, ?)
                    ''', (analysis_id, ioc_type, value))

            conn.commit()
            return True
        except Exception as e:
            conn.rollback()
            print(f"Error saving analysis: {e}")
            return False
        finally:
            conn.close()

    def load_analysis(self, analysis_id):
        """Load analysis from database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute('''
                SELECT filename, upload_time, format, entry_count,
                       parsed_data, analysis_results, enrichment_data
                FROM analyses
                WHERE id = ?
            ''', (analysis_id,))

            row = cursor.fetchone()
            if row:
                return {
                    'filename': row[0],
                    'upload_time': row[1],
                    'parsed_data': json.loads(row[4]),
                    'analysis': json.loads(row[5]),
                    'enrichment': json.loads(row[6]) if row[6] else {}
                }
            return None
        finally:
            conn.close()

    def list_analyses(self, limit=50):
        """List all saved analyses"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute('''
                SELECT id, filename, upload_time, format, entry_count, created_at
                FROM analyses
                ORDER BY created_at DESC
                LIMIT ?
            ''', (limit,))

            rows = cursor.fetchall()
            return [{
                'id': row[0],
                'filename': row[1],
                'upload_time': row[2],
                'format': row[3],
                'entry_count': row[4],
                'created_at': row[5]
            } for row in rows]
        finally:
            conn.close()

    def search_iocs(self, ioc_value):
        """Search for analyses containing a specific IOC"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute('''
                SELECT DISTINCT a.id, a.filename, a.upload_time, i.ioc_type
                FROM analyses a
                JOIN iocs i ON a.id = i.analysis_id
                WHERE i.ioc_value LIKE ?
                ORDER BY a.created_at DESC
            ''', (f'%{ioc_value}%',))

            rows = cursor.fetchall()
            return [{
                'analysis_id': row[0],
                'filename': row[1],
                'upload_time': row[2],
                'ioc_type': row[3]
            } for row in rows]
        finally:
            conn.close()

    def delete_analysis(self, analysis_id):
        """Delete an analysis"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute('DELETE FROM iocs WHERE analysis_id = ?', (analysis_id,))
            cursor.execute('DELETE FROM analyses WHERE id = ?', (analysis_id,))
            conn.commit()
            return True
        except Exception as e:
            conn.rollback()
            print(f"Error deleting analysis: {e}")
            return False
        finally:
            conn.close()

    def get_statistics(self):
        """Get database statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute('SELECT COUNT(*) FROM analyses')
            total_analyses = cursor.fetchone()[0]

            cursor.execute('SELECT COUNT(*) FROM iocs')
            total_iocs = cursor.fetchone()[0]

            cursor.execute('SELECT COUNT(DISTINCT ioc_value) FROM iocs')
            unique_iocs = cursor.fetchone()[0]

            return {
                'total_analyses': total_analyses,
                'total_iocs': total_iocs,
                'unique_iocs': unique_iocs
            }
        finally:
            conn.close()
