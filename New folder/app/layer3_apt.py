"""
Layer 3: APT Correlation Engine
Long-term threat tracking with SQLite event store and threat intelligence.
"""
import sqlite3
import time
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
import logging

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    logging.warning("requests not available. Install with: pip install requests")

from .security_io import validate_and_resolve_path, safe_write_file

logger = logging.getLogger(__name__)


class Layer3APT:
    """
    Layer 3: APT (Advanced Persistent Threat) Correlation Engine.
    Tracks long-term patterns and correlates with threat intelligence.
    """
    
    def __init__(self, db_path: str, virustotal_api_key: Optional[str] = None):
        """
        Initialize Layer 3 APT engine.
        
        Args:
            db_path: Path to SQLite database
            virustotal_api_key: VirusTotal API key (optional)
        """
        self.db_path = db_path
        self.virustotal_api_key = virustotal_api_key
        self.conn = None
        self._init_database()
    
    def _init_database(self):
        """Initialize SQLite database with required tables."""
        try:
            # Ensure parent directory exists
            db_file = Path(self.db_path)
            db_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Connect to database
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self.conn.row_factory = sqlite3.Row
            cursor = self.conn.cursor()
            
            # Create events table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    file_path TEXT NOT NULL,
                    file_hash TEXT,
                    event_type TEXT NOT NULL,
                    layer INTEGER,
                    score REAL,
                    details TEXT,
                    UNIQUE(file_hash, event_type, timestamp)
                )
            ''')
            
            # Create findings table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    file_path TEXT NOT NULL,
                    file_hash TEXT,
                    threat_type TEXT,
                    confidence REAL,
                    apt_score REAL,
                    indicators TEXT,
                    remediation_status TEXT,
                    UNIQUE(file_hash, threat_type)
                )
            ''')
            
            # Create indicators table (for tracking behavioral patterns)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS indicators (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    indicator_type TEXT NOT NULL,
                    indicator_value TEXT NOT NULL,
                    file_hash TEXT,
                    severity INTEGER,
                    description TEXT
                )
            ''')
            
            # Create threat_intel cache table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threat_intel (
                    file_hash TEXT PRIMARY KEY,
                    timestamp REAL NOT NULL,
                    source TEXT,
                    positives INTEGER,
                    total INTEGER,
                    scan_data TEXT
                )
            ''')
            
            # Create indexes for performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_hash ON events(file_hash)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_findings_hash ON findings(file_hash)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_indicators_type ON indicators(indicator_type)')
            
            self.conn.commit()
            logger.info(f"Database initialized: {self.db_path}")
        
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
            raise
    
    def log_event(self, file_path: str, file_hash: str, event_type: str, 
                  layer: int, score: float, details: Dict) -> bool:
        """
        Log a security event to the database.
        
        Args:
            file_path: Path to the file
            file_hash: Hash of the file
            event_type: Type of event (e.g., 'scan', 'detection', 'quarantine')
            layer: Detection layer (1, 2, or 3)
            score: Threat score
            details: Additional details as dictionary
        
        Returns:
            True if successful
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT OR IGNORE INTO events 
                (timestamp, file_path, file_hash, event_type, layer, score, details)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                time.time(),
                file_path,
                file_hash,
                event_type,
                layer,
                score,
                json.dumps(details)
            ))
            self.conn.commit()
            return True
        
        except Exception as e:
            logger.error(f"Failed to log event: {e}")
            return False
    
    def log_indicator(self, indicator_type: str, indicator_value: str,
                     file_hash: str, severity: int, description: str = "") -> bool:
        """
        Log a behavioral indicator.
        
        Args:
            indicator_type: Type of indicator (e.g., 'high_cpu', 'network_connection')
            indicator_value: Value of the indicator
            file_hash: Associated file hash
            severity: Severity level (1-5)
            description: Optional description
        
        Returns:
            True if successful
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT INTO indicators 
                (timestamp, indicator_type, indicator_value, file_hash, severity, description)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                time.time(),
                indicator_type,
                indicator_value,
                file_hash,
                severity,
                description
            ))
            self.conn.commit()
            return True
        
        except Exception as e:
            logger.error(f"Failed to log indicator: {e}")
            return False
    
    def calculate_apt_score(self, file_hash: str, window_hours: int = 24) -> Tuple[float, Dict]:
        """
        Calculate APT correlation score based on historical data.
        
        Args:
            file_hash: Hash of the file to analyze
            window_hours: Time window to consider (hours)
        
        Returns:
            Tuple of (apt_score: 0.0-1.0, analysis: dict)
        """
        try:
            cutoff_time = time.time() - (window_hours * 3600)
            cursor = self.conn.cursor()
            
            analysis = {
                'event_count': 0,
                'avg_score': 0.0,
                'max_score': 0.0,
                'layer_distribution': {1: 0, 2: 0, 3: 0},
                'indicators': [],
                'temporal_pattern': None
            }
            
            # Get recent events for this file
            cursor.execute('''
                SELECT * FROM events 
                WHERE file_hash = ? AND timestamp > ?
                ORDER BY timestamp DESC
            ''', (file_hash, cutoff_time))
            
            events = cursor.fetchall()
            analysis['event_count'] = len(events)
            
            if not events:
                return 0.0, analysis
            
            # Calculate statistics
            scores = []
            timestamps = []
            for event in events:
                if event['score']:
                    scores.append(event['score'])
                timestamps.append(event['timestamp'])
                layer = event['layer']
                if layer in analysis['layer_distribution']:
                    analysis['layer_distribution'][layer] += 1
            
            if scores:
                analysis['avg_score'] = sum(scores) / len(scores)
                analysis['max_score'] = max(scores)
            
            # Get associated indicators
            cursor.execute('''
                SELECT * FROM indicators 
                WHERE file_hash = ? AND timestamp > ?
                ORDER BY severity DESC
            ''', (file_hash, cutoff_time))
            
            indicators = cursor.fetchall()
            analysis['indicators'] = [
                {
                    'type': ind['indicator_type'],
                    'value': ind['indicator_value'],
                    'severity': ind['severity']
                }
                for ind in indicators
            ]
            
            # Calculate temporal pattern score
            if len(timestamps) > 1:
                time_deltas = [timestamps[i] - timestamps[i+1] for i in range(len(timestamps)-1)]
                avg_delta = sum(time_deltas) / len(time_deltas)
                
                # Regular periodic activity is more suspicious
                if avg_delta < 3600:  # Less than 1 hour between events
                    analysis['temporal_pattern'] = 'periodic_high_frequency'
                    temporal_score = 0.3
                elif avg_delta < 86400:  # Less than 1 day
                    analysis['temporal_pattern'] = 'periodic_medium_frequency'
                    temporal_score = 0.2
                else:
                    analysis['temporal_pattern'] = 'sporadic'
                    temporal_score = 0.1
            else:
                temporal_score = 0.0
            
            # Calculate APT score
            apt_score = 0.0
            
            # Component 1: Maximum detection score (40% weight)
            apt_score += analysis['max_score'] * 0.4
            
            # Component 2: Frequency of detections (30% weight)
            frequency_score = min(1.0, analysis['event_count'] / 10.0)
            apt_score += frequency_score * 0.3
            
            # Component 3: Temporal patterns (20% weight)
            apt_score += temporal_score
            
            # Component 4: Indicator severity (10% weight)
            if analysis['indicators']:
                avg_severity = sum(ind['severity'] for ind in analysis['indicators']) / len(analysis['indicators'])
                indicator_score = avg_severity / 5.0  # Normalize to 0-1
                apt_score += indicator_score * 0.1
            
            apt_score = min(1.0, apt_score)
            
            logger.info(f"APT score for {file_hash}: {apt_score:.4f}")
            return apt_score, analysis
        
        except Exception as e:
            logger.error(f"APT score calculation failed: {e}")
            return 0.0, analysis
    
    def query_virustotal(self, file_hash: str, cache_hours: int = 24) -> Optional[Dict]:
        """
        Query VirusTotal API for threat intelligence.
        
        Args:
            file_hash: SHA256 hash of the file
            cache_hours: Hours to cache results
        
        Returns:
            Dictionary with scan results, or None
        """
        if not REQUESTS_AVAILABLE or not self.virustotal_api_key:
            logger.warning("VirusTotal query not available")
            return None
        
        try:
            # Check cache first
            cursor = self.conn.cursor()
            cutoff_time = time.time() - (cache_hours * 3600)
            
            cursor.execute('''
                SELECT * FROM threat_intel 
                WHERE file_hash = ? AND timestamp > ?
            ''', (file_hash, cutoff_time))
            
            cached = cursor.fetchone()
            if cached:
                logger.info(f"Using cached VirusTotal data for {file_hash}")
                return json.loads(cached['scan_data'])
            
            # Query VirusTotal API
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            headers = {
                'x-apikey': self.virustotal_api_key
            }
            
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                
                result = {
                    'positives': stats.get('malicious', 0),
                    'total': sum(stats.values()),
                    'scan_date': data.get('data', {}).get('attributes', {}).get('last_analysis_date'),
                    'permalink': f"https://www.virustotal.com/gui/file/{file_hash}"
                }
                
                # Cache result
                cursor.execute('''
                    INSERT OR REPLACE INTO threat_intel 
                    (file_hash, timestamp, source, positives, total, scan_data)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    file_hash,
                    time.time(),
                    'virustotal',
                    result['positives'],
                    result['total'],
                    json.dumps(result)
                ))
                self.conn.commit()
                
                logger.info(f"VirusTotal: {file_hash} - {result['positives']}/{result['total']} detections")
                return result
            
            elif response.status_code == 404:
                logger.info(f"File not found in VirusTotal: {file_hash}")
                return {'positives': 0, 'total': 0, 'scan_date': None}
            
            else:
                logger.error(f"VirusTotal API error: {response.status_code}")
                return None
        
        except Exception as e:
            logger.error(f"VirusTotal query failed: {e}")
            return None
    
    def correlate_threat(self, file_path: str, file_hash: str, 
                        layer1_result: Dict, layer2_result: Dict) -> Tuple[float, Dict]:
        """
        Correlate threat data from all layers and generate final APT score.
        
        Args:
            file_path: Path to the file
            file_hash: Hash of the file
            layer1_result: Results from Layer 1
            layer2_result: Results from Layer 2
        
        Returns:
            Tuple of (final_apt_score: 0.0-1.0, correlation_details: dict)
        """
        start_time = time.time()
        
        try:
            # Log events from previous layers
            if layer1_result:
                self.log_event(
                    file_path, file_hash, 'layer1_scan', 1,
                    layer1_result.get('confidence', 0.0),
                    layer1_result
                )
            
            if layer2_result:
                self.log_event(
                    file_path, file_hash, 'layer2_analysis', 2,
                    layer2_result.get('anomaly_score', 0.0),
                    layer2_result
                )
            
            # Calculate historical APT score
            apt_score, apt_analysis = self.calculate_apt_score(file_hash)
            
            # Query threat intelligence
            threat_intel = self.query_virustotal(file_hash)
            
            # Calculate combined threat likelihood
            scores = {
                'layer1': layer1_result.get('confidence', 0.0) if layer1_result else 0.0,
                'layer2': layer2_result.get('anomaly_score', 0.0) if layer2_result else 0.0,
                'layer3_apt': apt_score,
                'threat_intel': 0.0
            }
            
            if threat_intel and threat_intel.get('total', 0) > 0:
                scores['threat_intel'] = threat_intel['positives'] / threat_intel['total']
            
            # Weighted combination of all scores
            # Layer 1: 30%, Layer 2: 35%, Layer 3: 20%, Threat Intel: 15%
            final_score = (
                scores['layer1'] * 0.30 +
                scores['layer2'] * 0.35 +
                scores['layer3_apt'] * 0.20 +
                scores['threat_intel'] * 0.15
            )
            
            correlation_details = {
                'layer': 3,
                'scores': scores,
                'final_threat_score': final_score,
                'apt_analysis': apt_analysis,
                'threat_intel': threat_intel,
                'scan_time': time.time() - start_time
            }
            
            # Log final finding
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO findings 
                (timestamp, file_path, file_hash, threat_type, confidence, apt_score, indicators, remediation_status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                time.time(),
                file_path,
                file_hash,
                'multi_layer_detection',
                final_score,
                apt_score,
                json.dumps(correlation_details),
                'pending'
            ))
            self.conn.commit()
            
            logger.info(f"Layer 3 correlation for {file_path}: final_score={final_score:.4f}, apt_score={apt_score:.4f}")
            
            return final_score, correlation_details
        
        except Exception as e:
            logger.error(f"Threat correlation failed: {e}")
            return 0.5, {'error': str(e)}
    
    def get_threat_history(self, file_hash: str, limit: int = 50) -> List[Dict]:
        """
        Get threat history for a file.
        
        Args:
            file_hash: Hash of the file
            limit: Maximum number of events to return
        
        Returns:
            List of historical events
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                SELECT * FROM events 
                WHERE file_hash = ?
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (file_hash, limit))
            
            events = cursor.fetchall()
            return [dict(event) for event in events]
        
        except Exception as e:
            logger.error(f"Failed to get threat history: {e}")
            return []
    
    def get_recent_threats(self, hours: int = 24, min_score: float = 0.5) -> List[Dict]:
        """
        Get recent high-confidence threats.
        
        Args:
            hours: Time window in hours
            min_score: Minimum threat score
        
        Returns:
            List of recent threats
        """
        try:
            cutoff_time = time.time() - (hours * 3600)
            cursor = self.conn.cursor()
            
            cursor.execute('''
                SELECT * FROM findings 
                WHERE timestamp > ? AND confidence >= ?
                ORDER BY confidence DESC
            ''', (cutoff_time, min_score))
            
            threats = cursor.fetchall()
            return [dict(threat) for threat in threats]
        
        except Exception as e:
            logger.error(f"Failed to get recent threats: {e}")
            return []
    
    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()
            logger.info("Database connection closed")
