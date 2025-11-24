"""
Layer 2: Adaptive Pattern Scoring & Analysis (APSA)
Behavioral anomaly detection with dynamic signature generation.
"""
import time
from pathlib import Path
from typing import Tuple, Dict, List, Optional
import logging

from ml_core import MLCore
from layer1_scanner import Layer1Scanner
from security_io import validate_and_resolve_path

logger = logging.getLogger(__name__)


class Layer2APSA:
    """
    Layer 2: Adaptive Pattern Scoring & Analysis.
    Uses ML-based behavioral analysis and dynamic signature generation.
    """
    
    def __init__(self, ml_model_path: Optional[str] = None, 
                 yara_rules_dir: Optional[str] = None,
                 anomaly_threshold: float = 0.6):
        """
        Initialize Layer 2 APSA.
        
        Args:
            ml_model_path: Path to trained ML model
            yara_rules_dir: Directory for YARA rules (for dynamic rule generation)
            anomaly_threshold: Threshold for anomaly detection (0.0-1.0)
        """
        self.ml_core = MLCore(model_path=ml_model_path)
        self.layer1_scanner = Layer1Scanner(yara_rules_dir=yara_rules_dir) if yara_rules_dir else None
        self.anomaly_threshold = anomaly_threshold
        self.detected_anomalies = []  # Store for clustering
        self.max_anomaly_cache = 100  # Maximum anomalies to cache for clustering
    
    def analyze_file(self, file_path: str) -> Tuple[float, Dict[str, any]]:
        """
        Perform behavioral analysis on a file using ML model.
        
        Args:
            file_path: Path to file to analyze
        
        Returns:
            Tuple of (anomaly_score: 0.0-1.0, details: dict)
        """
        start_time = time.time()
        
        details = {
            'layer': 2,
            'anomaly_score': 0.0,
            'features': {},
            'is_anomaly': False,
            'scan_time': 0.0
        }
        
        try:
            path = validate_and_resolve_path(file_path, must_exist=True)
            
            # Check file size (skip very large files)
            file_size = path.stat().st_size
            if file_size > 1024 * 1024 * 1024:  # 1GB
                logger.warning(f"File too large for Layer 2 analysis: {file_path}")
                details['error'] = 'File too large'
                return 0.5, details
            
            # Extract features and predict anomaly score
            if not self.ml_core.is_trained:
                logger.warning("ML model not trained, using heuristic scoring")
                # Fallback to basic heuristic analysis
                anomaly_score = self._heuristic_analysis(file_path)
                details['method'] = 'heuristic'
            else:
                anomaly_score, features = self.ml_core.predict_anomaly_score(file_path)
                details['features'] = features
                details['method'] = 'ml_model'
            
            details['anomaly_score'] = anomaly_score
            details['is_anomaly'] = anomaly_score >= self.anomaly_threshold
            
            # Cache high-score anomalies for clustering
            if anomaly_score >= self.anomaly_threshold:
                self._cache_anomaly(file_path, anomaly_score, details)
            
            scan_time = time.time() - start_time
            details['scan_time'] = scan_time
            
            logger.info(f"Layer 2 analysis for {file_path}: score={anomaly_score:.4f}, anomaly={details['is_anomaly']}, time={scan_time:.3f}s")
            
            return anomaly_score, details
        
        except Exception as e:
            logger.error(f"Layer 2 analysis failed for {file_path}: {e}")
            details['error'] = str(e)
            return 0.5, details
    
    def _heuristic_analysis(self, file_path: str) -> float:
        """
        Fallback heuristic analysis when ML model is not available.
        
        Args:
            file_path: Path to file
        
        Returns:
            Heuristic anomaly score (0.0-1.0)
        """
        try:
            # Extract basic features
            features = self.ml_core.extract_features(file_path)
            
            score = 0.0
            
            # High entropy is suspicious
            if features.get('entropy', 0) > 7.5:
                score += 0.3
            elif features.get('entropy', 0) > 7.0:
                score += 0.15
            
            # Low printable ratio is suspicious
            if features.get('printable_ratio', 0) < 0.1:
                score += 0.2
            
            # Executable files are inherently riskier
            if features.get('is_executable', 0) == 1.0:
                score += 0.15
            
            # Scripts are risky
            if features.get('is_script', 0) == 1.0:
                score += 0.2
            
            # High null byte ratio can indicate padding/obfuscation
            if features.get('null_byte_ratio', 0) > 0.5:
                score += 0.15
            
            return min(1.0, score)
        
        except Exception as e:
            logger.error(f"Heuristic analysis failed: {e}")
            return 0.5
    
    def _cache_anomaly(self, file_path: str, score: float, details: dict):
        """
        Cache anomaly for later clustering and dynamic signature generation.
        
        Args:
            file_path: Path to anomalous file
            score: Anomaly score
            details: Analysis details
        """
        self.detected_anomalies.append({
            'file': file_path,
            'score': score,
            'details': details,
            'timestamp': time.time()
        })
        
        # Keep cache size manageable
        if len(self.detected_anomalies) > self.max_anomaly_cache:
            # Remove oldest entries
            self.detected_anomalies = sorted(
                self.detected_anomalies,
                key=lambda x: x['score'],
                reverse=True
            )[:self.max_anomaly_cache]
    
    def generate_dynamic_signatures(self, min_cluster_size: int = 3) -> List[Dict]:
        """
        Generate dynamic YARA signatures from clustered anomalies.
        This is the core APSA feature.
        
        Args:
            min_cluster_size: Minimum number of samples to form a cluster
        
        Returns:
            List of generated signatures
        """
        if len(self.detected_anomalies) < min_cluster_size:
            logger.info(f"Not enough anomalies for clustering ({len(self.detected_anomalies)} < {min_cluster_size})")
            return []
        
        try:
            logger.info(f"Generating dynamic signatures from {len(self.detected_anomalies)} anomalies")
            
            # Extract file paths
            file_paths = [a['file'] for a in self.detected_anomalies]
            
            # Cluster anomalies by behavioral similarity
            clusters = self.ml_core.cluster_anomalies(file_paths, min_samples=min_cluster_size)
            
            generated_signatures = []
            
            # Generate signatures for each cluster
            for cluster_id, cluster_files in clusters.items():
                if cluster_id == -1:  # Noise cluster in DBSCAN
                    continue
                
                if len(cluster_files) < min_cluster_size:
                    continue
                
                # Generate YARA rule for this cluster
                signature = self._generate_yara_rule(cluster_id, cluster_files)
                
                if signature:
                    generated_signatures.append({
                        'cluster_id': cluster_id,
                        'file_count': len(cluster_files),
                        'rule_name': signature['rule_name'],
                        'rule_content': signature['rule_content']
                    })
                    
                    # Add rule to Layer 1 scanner if available
                    if self.layer1_scanner:
                        success = self.layer1_scanner.add_yara_rule(
                            signature['rule_content'],
                            signature['rule_name']
                        )
                        logger.info(f"Added dynamic YARA rule: {signature['rule_name']} (success={success})")
            
            logger.info(f"Generated {len(generated_signatures)} dynamic signatures")
            return generated_signatures
        
        except Exception as e:
            logger.error(f"Dynamic signature generation failed: {e}")
            return []
    
    def _generate_yara_rule(self, cluster_id: int, file_paths: List[str]) -> Optional[Dict]:
        """
        Generate a YARA rule from a cluster of similar files.
        
        Args:
            cluster_id: Cluster identifier
            file_paths: List of file paths in the cluster
        
        Returns:
            Dictionary with rule_name and rule_content, or None
        """
        try:
            from datetime import datetime
            import hashlib
            
            # Extract common features from cluster files
            all_features = []
            for file_path in file_paths[:10]:  # Sample up to 10 files
                features = self.ml_core.extract_features(file_path)
                if features:
                    all_features.append(features)
            
            if not all_features:
                return None
            
            # Calculate average features
            avg_entropy = sum(f.get('entropy', 0) for f in all_features) / len(all_features)
            avg_file_size = sum(f.get('file_size', 0) for f in all_features) / len(all_features)
            
            # Determine file type
            file_types = [f.get('is_executable', 0) for f in all_features]
            is_executable = sum(file_types) / len(file_types) > 0.5
            
            # Generate rule name
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            rule_name = f"apsa_dynamic_cluster_{cluster_id}_{timestamp}"
            
            # Build YARA rule
            rule_content = f'''rule {rule_name} {{
    meta:
        description = "APSA dynamically generated rule for cluster {cluster_id}"
        author = "EDR-APSA-Layer2"
        date = "{datetime.now().isoformat()}"
        cluster_size = "{len(file_paths)}"
        avg_entropy = "{avg_entropy:.2f}"
        avg_size = "{int(avg_file_size)}"
    
    strings:
        // Pattern-based detection would go here
        // This is a simplified example
    
    condition:
        // High entropy files within size range
        filesize > {int(avg_file_size * 0.5)} and 
        filesize < {int(avg_file_size * 2.0)} and
        math.entropy(0, filesize) > {max(6.0, avg_entropy - 0.5)}
}}
'''
            
            return {
                'rule_name': rule_name,
                'rule_content': rule_content
            }
        
        except Exception as e:
            logger.error(f"YARA rule generation failed for cluster {cluster_id}: {e}")
            return None
    
    def train_model(self, benign_files: List[str]) -> bool:
        """
        Train the ML model on benign baseline files.
        
        Args:
            benign_files: List of paths to known benign files
        
        Returns:
            True if training successful
        """
        return self.ml_core.train(benign_files)
    
    def save_model(self, model_path: str) -> bool:
        """
        Save trained ML model.
        
        Args:
            model_path: Path to save the model
        
        Returns:
            True if successful
        """
        return self.ml_core.save_model(model_path)
    
    def get_anomaly_statistics(self) -> Dict:
        """
        Get statistics about detected anomalies.
        
        Returns:
            Dictionary with statistics
        """
        if not self.detected_anomalies:
            return {
                'total': 0,
                'avg_score': 0.0,
                'max_score': 0.0,
                'min_score': 0.0
            }
        
        scores = [a['score'] for a in self.detected_anomalies]
        
        return {
            'total': len(self.detected_anomalies),
            'avg_score': sum(scores) / len(scores),
            'max_score': max(scores),
            'min_score': min(scores),
            'cache_size': len(self.detected_anomalies)
        }
    
    def clear_anomaly_cache(self):
        """Clear the anomaly cache."""
        self.detected_anomalies.clear()
        logger.info("Anomaly cache cleared")
