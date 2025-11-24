"""
Enhanced Threat Intelligence Module
Integrates multiple threat intelligence sources including VirusTotal and Hybrid Analysis.
Provides comprehensive threat lookups with caching and rate limiting.
"""
import os
import time
import json
import logging
import hashlib
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime, timedelta
import sqlite3

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

logger = logging.getLogger(__name__)


class ThreatIntelligence:
    """
    Comprehensive threat intelligence integration with multiple sources.
    """
    
    def __init__(self, db_path: str = 'data/threat_intel.db', 
                 vt_api_key: Optional[str] = None,
                 ha_api_key: Optional[str] = None):
        """
        Initialize threat intelligence module.
        
        Args:
            db_path: Path to cache database
            vt_api_key: VirusTotal API key
            ha_api_key: Hybrid Analysis API key
        """
        self.db_path = db_path
        self.vt_api_key = vt_api_key
        self.ha_api_key = ha_api_key
        self.cache_duration = 24 * 3600  # 24 hours
        self.rate_limit_delay = 15  # seconds between requests
        self.last_request_time = {}
        
        self._init_database()
    
    def _init_database(self):
        """Initialize threat intelligence cache database."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vt_cache (
                file_hash TEXT PRIMARY KEY,
                result TEXT NOT NULL,
                timestamp REAL NOT NULL,
                positives INTEGER,
                total INTEGER
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ha_cache (
                file_hash TEXT PRIMARY KEY,
                result TEXT NOT NULL,
                timestamp REAL NOT NULL,
                threat_score INTEGER,
                verdict TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_feeds (
                indicator TEXT PRIMARY KEY,
                type TEXT NOT NULL,
                source TEXT NOT NULL,
                threat_level TEXT NOT NULL,
                description TEXT,
                timestamp REAL NOT NULL
            )
        ''')
        
        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_vt_timestamp ON vt_cache(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ha_timestamp ON ha_cache(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_feed_type ON threat_feeds(type)')
        
        conn.commit()
        conn.close()
        logger.info(f"Threat intelligence database initialized at {self.db_path}")
    
    def _check_rate_limit(self, source: str):
        """Enforce rate limiting for API requests."""
        if source in self.last_request_time:
            elapsed = time.time() - self.last_request_time[source]
            if elapsed < self.rate_limit_delay:
                wait_time = self.rate_limit_delay - elapsed
                logger.info(f"Rate limiting {source}: waiting {wait_time:.1f}s")
                time.sleep(wait_time)
        
        self.last_request_time[source] = time.time()
    
    def query_virustotal(self, file_hash: str) -> Dict:
        """
        Query VirusTotal API v3 for file reputation.
        
        Args:
            file_hash: SHA256 hash of file
        
        Returns:
            VirusTotal analysis results
        """
        if not REQUESTS_AVAILABLE:
            return {'error': 'requests library not available'}
        
        if not self.vt_api_key:
            logger.warning("No VirusTotal API key configured")
            return {'error': 'No API key', 'scanned': False}
        
        # Check cache
        cached = self._get_cached_result('vt', file_hash)
        if cached:
            logger.info(f"VirusTotal cache hit for {file_hash}")
            return cached
        
        # Rate limiting
        self._check_rate_limit('virustotal')
        
        try:
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            headers = {
                'x-apikey': self.vt_api_key,
                'Accept': 'application/json'
            }
            
            response = requests.get(url, headers=headers, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                stats = attributes.get('last_analysis_stats', {})
                results = attributes.get('last_analysis_results', {})
                
                result = {
                    'hash': file_hash,
                    'scanned': True,
                    'source': 'virustotal',
                    'positives': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'undetected': stats.get('undetected', 0),
                    'total': sum(stats.values()),
                    'scan_date': attributes.get('last_analysis_date', 0),
                    'first_seen': attributes.get('first_submission_date', 0),
                    'file_type': attributes.get('type_description', ''),
                    'size': attributes.get('size', 0),
                    'tags': attributes.get('tags', []),
                    'reputation': attributes.get('reputation', 0),
                    'threat_label': self._determine_threat_label(stats),
                    'detection_names': [],
                    'timestamp': time.time()
                }
                
                # Extract detection names from top vendors
                detections = []
                for vendor, verdict in results.items():
                    if verdict.get('category') == 'malicious':
                        detections.append({
                            'vendor': vendor,
                            'result': verdict.get('result', 'Unknown')
                        })
                
                result['detection_names'] = detections[:15]  # Top 15
                
                # Cache result
                self._cache_result('vt', file_hash, result)
                
                logger.info(f"VirusTotal: {result['positives']}/{result['total']} for {file_hash}")
                return result
            
            elif response.status_code == 404:
                result = {
                    'hash': file_hash,
                    'scanned': False,
                    'source': 'virustotal',
                    'message': 'File not found in VirusTotal database',
                    'timestamp': time.time()
                }
                return result
            
            elif response.status_code == 429:
                logger.warning("VirusTotal rate limit exceeded")
                return {
                    'error': 'Rate limit exceeded',
                    'retry_after': response.headers.get('Retry-After', 60),
                    'scanned': False
                }
            
            else:
                logger.error(f"VirusTotal error: {response.status_code}")
                return {'error': f'API error {response.status_code}', 'scanned': False}
        
        except requests.exceptions.Timeout:
            return {'error': 'Request timeout', 'scanned': False}
        except Exception as e:
            logger.error(f"VirusTotal query failed: {e}")
            return {'error': str(e), 'scanned': False}
    
    def query_hybrid_analysis(self, file_hash: str) -> Dict:
        """
        Query Hybrid Analysis API for sandbox results.
        
        Args:
            file_hash: SHA256 hash
        
        Returns:
            Hybrid Analysis results
        """
        if not REQUESTS_AVAILABLE or not self.ha_api_key:
            return {'error': 'Not available', 'scanned': False}
        
        # Check cache
        cached = self._get_cached_result('ha', file_hash)
        if cached:
            return cached
        
        # Rate limiting
        self._check_rate_limit('hybrid_analysis')
        
        try:
            url = f"https://www.hybrid-analysis.com/api/v2/search/hash"
            headers = {
                'api-key': self.ha_api_key,
                'User-Agent': 'EDR Scanner',
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            data = {'hash': file_hash}
            
            response = requests.post(url, headers=headers, data=data, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                
                if not data:
                    return {
                        'hash': file_hash,
                        'scanned': False,
                        'source': 'hybrid_analysis',
                        'message': 'No results found'
                    }
                
                # Get first result
                first_result = data[0] if isinstance(data, list) else data
                
                result = {
                    'hash': file_hash,
                    'scanned': True,
                    'source': 'hybrid_analysis',
                    'threat_score': first_result.get('threat_score', 0),
                    'verdict': first_result.get('verdict', 'unknown'),
                    'av_detect': first_result.get('av_detect', 0),
                    'vx_family': first_result.get('vx_family', ''),
                    'type': first_result.get('type', ''),
                    'environment': first_result.get('environment_description', ''),
                    'analysis_start_time': first_result.get('analysis_start_time', ''),
                    'timestamp': time.time()
                }
                
                self._cache_result('ha', file_hash, result)
                
                logger.info(f"Hybrid Analysis: threat_score={result['threat_score']} for {file_hash}")
                return result
            
            else:
                return {'error': f'API error {response.status_code}', 'scanned': False}
        
        except Exception as e:
            logger.error(f"Hybrid Analysis query failed: {e}")
            return {'error': str(e), 'scanned': False}
    
    def query_all_sources(self, file_hash: str) -> Dict:
        """
        Query all available threat intelligence sources.
        
        Args:
            file_hash: SHA256 hash
        
        Returns:
            Aggregated results from all sources
        """
        results = {
            'hash': file_hash,
            'sources': {},
            'aggregated': {
                'is_malicious': False,
                'confidence': 0.0,
                'threat_level': 'unknown',
                'sources_agreeing': 0
            }
        }
        
        # Query VirusTotal
        if self.vt_api_key:
            vt_result = self.query_virustotal(file_hash)
            results['sources']['virustotal'] = vt_result
        
        # Query Hybrid Analysis
        if self.ha_api_key:
            ha_result = self.query_hybrid_analysis(file_hash)
            results['sources']['hybrid_analysis'] = ha_result
        
        # Aggregate results
        results['aggregated'] = self._aggregate_results(results['sources'])
        
        return results
    
    def _aggregate_results(self, sources: Dict) -> Dict:
        """Aggregate results from multiple threat intelligence sources."""
        aggregated = {
            'is_malicious': False,
            'confidence': 0.0,
            'threat_level': 'unknown',
            'sources_agreeing': 0,
            'details': []
        }
        
        votes_malicious = 0
        total_sources = 0
        confidence_scores = []
        
        # VirusTotal
        if 'virustotal' in sources:
            vt = sources['virustotal']
            if vt.get('scanned'):
                total_sources += 1
                if vt.get('total', 0) > 0:
                    detection_rate = vt.get('positives', 0) / vt.get('total', 1)
                    if detection_rate > 0.3:
                        votes_malicious += 1
                        confidence_scores.append(detection_rate)
                        aggregated['details'].append(f"VT: {vt['positives']}/{vt['total']} detections")
        
        # Hybrid Analysis
        if 'hybrid_analysis' in sources:
            ha = sources['hybrid_analysis']
            if ha.get('scanned'):
                total_sources += 1
                threat_score = ha.get('threat_score', 0)
                if threat_score >= 50:
                    votes_malicious += 1
                    confidence_scores.append(threat_score / 100)
                    aggregated['details'].append(f"HA: threat score {threat_score}")
        
        # Determine final verdict
        if total_sources > 0:
            aggregated['sources_agreeing'] = votes_malicious
            aggregated['is_malicious'] = votes_malicious > 0
            
            if confidence_scores:
                aggregated['confidence'] = sum(confidence_scores) / len(confidence_scores)
            
            # Threat level
            if votes_malicious >= total_sources:
                aggregated['threat_level'] = 'high'
            elif votes_malicious > 0:
                aggregated['threat_level'] = 'medium'
            else:
                aggregated['threat_level'] = 'low'
        
        return aggregated
    
    def _determine_threat_label(self, stats: Dict) -> str:
        """Determine threat label from VirusTotal stats."""
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        total = sum(stats.values())
        
        if total == 0:
            return 'unknown'
        
        detection_rate = (malicious + suspicious) / total
        
        if malicious > total * 0.5:
            return 'high_confidence_malicious'
        elif malicious > total * 0.2:
            return 'likely_malicious'
        elif suspicious > total * 0.3:
            return 'suspicious'
        elif detection_rate < 0.1:
            return 'likely_benign'
        else:
            return 'uncertain'
    
    def _get_cached_result(self, source: str, file_hash: str) -> Optional[Dict]:
        """Get cached result if still valid."""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            table = f"{source}_cache"
            cursor.execute(f"SELECT * FROM {table} WHERE file_hash = ?", (file_hash,))
            row = cursor.fetchone()
            conn.close()
            
            if row:
                # Check if cache is still valid
                age = time.time() - row['timestamp']
                if age < self.cache_duration:
                    result = json.loads(row['result'])
                    result['from_cache'] = True
                    return result
        
        except Exception as e:
            logger.error(f"Cache read error: {e}")
        
        return None
    
    def _cache_result(self, source: str, file_hash: str, result: Dict):
        """Cache threat intelligence result."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            result_json = json.dumps(result)
            timestamp = time.time()
            
            if source == 'vt':
                cursor.execute('''
                    INSERT OR REPLACE INTO vt_cache 
                    (file_hash, result, timestamp, positives, total)
                    VALUES (?, ?, ?, ?, ?)
                ''', (file_hash, result_json, timestamp, 
                      result.get('positives', 0), result.get('total', 0)))
            
            elif source == 'ha':
                cursor.execute('''
                    INSERT OR REPLACE INTO ha_cache 
                    (file_hash, result, timestamp, threat_score, verdict)
                    VALUES (?, ?, ?, ?, ?)
                ''', (file_hash, result_json, timestamp,
                      result.get('threat_score', 0), result.get('verdict', '')))
            
            conn.commit()
            conn.close()
        
        except Exception as e:
            logger.error(f"Cache write error: {e}")
    
    def add_threat_indicator(self, indicator: str, indicator_type: str,
                            source: str, threat_level: str, 
                            description: str = ''):
        """Add custom threat indicator to database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO threat_feeds 
                (indicator, type, source, threat_level, description, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (indicator, indicator_type, source, threat_level, 
                  description, time.time()))
            
            conn.commit()
            conn.close()
            logger.info(f"Added threat indicator: {indicator}")
        
        except Exception as e:
            logger.error(f"Failed to add threat indicator: {e}")
    
    def check_threat_feeds(self, indicator: str, indicator_type: str) -> Optional[Dict]:
        """Check if indicator exists in threat feeds."""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM threat_feeds 
                WHERE indicator = ? AND type = ?
            ''', (indicator, indicator_type))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return dict(row)
        
        except Exception as e:
            logger.error(f"Threat feed check error: {e}")
        
        return None
    
    def cleanup_old_cache(self, days: int = 7):
        """Remove old cached results."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cutoff = time.time() - (days * 86400)
            
            cursor.execute('DELETE FROM vt_cache WHERE timestamp < ?', (cutoff,))
            cursor.execute('DELETE FROM ha_cache WHERE timestamp < ?', (cutoff,))
            cursor.execute('DELETE FROM threat_feeds WHERE timestamp < ?', (cutoff,))
            
            conn.commit()
            deleted = cursor.rowcount
            conn.close()
            
            logger.info(f"Cleaned up {deleted} old cache entries")
        
        except Exception as e:
            logger.error(f"Cache cleanup error: {e}")
