"""
APSA ML Core - Machine Learning for Behavioral Anomaly Detection
Uses IsolationForest for unsupervised anomaly detection with feature extraction.
"""
import os
import math
import numpy as np
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import pickle
import logging
from collections import Counter

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN, KMeans

from .security_io import read_in_chunks, validate_and_resolve_path, safe_write_file

logger = logging.getLogger(__name__)


class MLCore:
    """
    Machine Learning Core for behavioral anomaly detection.
    Uses IsolationForest for unsupervised learning.
    """
    
    def __init__(self, model_path: Optional[str] = None, contamination: float = 0.1):
        """
        Initialize ML Core with IsolationForest model.
        
        Args:
            model_path: Path to saved model (if exists)
            contamination: Expected proportion of outliers (default: 0.1)
        """
        self.contamination = contamination
        self.model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100,
            max_samples='auto',
            n_jobs=-1  # Use all CPU cores
        )
        self.scaler = StandardScaler()
        self.is_trained = False
        self.feature_names = []
        
        if model_path and os.path.exists(model_path):
            self.load_model(model_path)
    
    def calculate_entropy(self, file_path: str) -> float:
        """
        Calculate Shannon entropy of a file.
        Higher entropy indicates more randomness (possible encryption/packing).
        
        Args:
            file_path: Path to the file
        
        Returns:
            Entropy value (0.0 to 8.0 for byte data)
        """
        try:
            byte_counts = Counter()
            total_bytes = 0
            
            # Read file in chunks to calculate entropy
            for chunk in read_in_chunks(file_path):
                byte_counts.update(chunk)
                total_bytes += len(chunk)
            
            if total_bytes == 0:
                return 0.0
            
            # Calculate Shannon entropy
            entropy = 0.0
            for count in byte_counts.values():
                probability = count / total_bytes
                if probability > 0:
                    entropy -= probability * math.log2(probability)
            
            return entropy
        
        except Exception as e:
            logger.error(f"Entropy calculation failed for {file_path}: {e}")
            return 0.0
    
    def calculate_fuzzy_hash(self, file_path: str) -> str:
        """
        Calculate fuzzy hash (ssdeep) for similarity detection.
        Falls back to simple hash if ssdeep not available.
        
        Args:
            file_path: Path to the file
        
        Returns:
            Fuzzy hash string
        """
        try:
            import ssdeep
            return ssdeep.hash_from_file(file_path)
        except ImportError:
            logger.warning("ssdeep not available, using fallback hashing")
            # Fallback: use chunk-based hashing
            import hashlib
            hasher = hashlib.sha256()
            for chunk in read_in_chunks(file_path):
                hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            logger.error(f"Fuzzy hash calculation failed for {file_path}: {e}")
            return ""
    
    def extract_features(self, file_path: str) -> Dict[str, float]:
        """
        Extract behavioral features from a file.
        
        Args:
            file_path: Path to the file
        
        Returns:
            Dictionary of feature values
        """
        return self.extract_features_optimized(file_path, sample_large_files=False)
    
    def extract_features_optimized(self, file_path: str, sample_large_files: bool = True, 
                                   sample_size_mb: int = 10) -> Dict[str, float]:
        """
        Extract behavioral features with optional sampling for large files (Phase 3 optimization).
        
        For files larger than threshold, sample first/middle/last chunks instead of
        reading entire file. This dramatically speeds up feature extraction.
        
        Args:
            file_path: Path to the file
            sample_large_files: If True, sample large files instead of full read
            sample_size_mb: Size of each sample chunk in MB (default: 10)
        
        Returns:
            Dictionary of feature values
        """
        try:
            path = validate_and_resolve_path(file_path, must_exist=True)
            
            features = {}
            
            # Basic file attributes
            stat = path.stat()
            file_size = stat.st_size
            features['file_size'] = file_size
            features['file_size_log'] = math.log10(file_size + 1)
            
            # Determine if we should sample
            sample_threshold = 100 * 1024 * 1024  # 100MB
            should_sample = sample_large_files and file_size > sample_threshold
            
            if should_sample:
                logger.debug(f"Sampling large file {file_path} ({file_size / (1024*1024):.1f} MB)")
                features.update(self._extract_features_sampled(path, sample_size_mb * 1024 * 1024))
            else:
                features.update(self._extract_features_full(path))
            
            # File extension analysis
            ext = path.suffix.lower()
            features['is_executable'] = 1.0 if ext in ['.exe', '.dll', '.sys', '.scr'] else 0.0
            features['is_script'] = 1.0 if ext in ['.bat', '.cmd', '.ps1', '.vbs', '.js'] else 0.0
            features['is_office'] = 1.0 if ext in ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'] else 0.0
            features['is_archive'] = 1.0 if ext in ['.zip', '.rar', '.7z', '.tar', '.gz'] else 0.0
            
            return features
        
        except Exception as e:
            logger.error(f"Feature extraction failed for {file_path}: {e}")
            return {}
            
            # Entropy (key indicator of encryption/packing)
            features['entropy'] = self.calculate_entropy(file_path)
            
            # Calculate byte frequency features
            byte_counts = Counter()
            null_bytes = 0
            printable_bytes = 0
            high_bytes = 0
            total_bytes = 0
            
            for chunk in read_in_chunks(file_path, chunk_size=1024 * 1024):
                byte_counts.update(chunk)
                null_bytes += chunk.count(b'\x00')
                printable_bytes += sum(1 for b in chunk if 32 <= b <= 126)
                high_bytes += sum(1 for b in chunk if b >= 128)
                total_bytes += len(chunk)
            
            if total_bytes > 0:
                features['null_byte_ratio'] = null_bytes / total_bytes
                features['printable_ratio'] = printable_bytes / total_bytes
                features['high_byte_ratio'] = high_bytes / total_bytes
            else:
                features['null_byte_ratio'] = 0.0
                features['printable_ratio'] = 0.0
                features['high_byte_ratio'] = 0.0
            
            # Unique byte count (another indicator of entropy)
            features['unique_bytes'] = len(byte_counts)
            features['unique_byte_ratio'] = len(byte_counts) / 256.0
            
            # File extension analysis
            ext = path.suffix.lower()
            features['is_executable'] = 1.0 if ext in ['.exe', '.dll', '.sys', '.scr'] else 0.0
            features['is_script'] = 1.0 if ext in ['.bat', '.cmd', '.ps1', '.vbs', '.js'] else 0.0
            features['is_office'] = 1.0 if ext in ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'] else 0.0
            features['is_archive'] = 1.0 if ext in ['.zip', '.rar', '.7z', '.tar', '.gz'] else 0.0
            
            # Calculate longest sequence of same byte (indicator of padding)
            max_sequence = 0
            current_sequence = 1
            prev_byte = None
            
            for chunk in read_in_chunks(file_path, chunk_size=65536):
                for byte in chunk:
                    if byte == prev_byte:
                        current_sequence += 1
                        max_sequence = max(max_sequence, current_sequence)
                    else:
                        current_sequence = 1
                    prev_byte = byte
            
            features['max_byte_sequence'] = max_sequence
            features['max_sequence_ratio'] = max_sequence / (total_bytes + 1)
            
            logger.debug(f"Extracted features for {file_path}: {features}")
            return features
        
        except Exception as e:
            logger.error(f"Feature extraction failed for {file_path}: {e}")
            return {}
    
    def _extract_features_full(self, path: Path) -> Dict[str, float]:
        """Extract features from entire file (original method)."""
        features = {}
        
        # Entropy (key indicator of encryption/packing)
        features['entropy'] = self.calculate_entropy(str(path))
        
        # Calculate byte frequency features
        byte_counts = Counter()
        null_bytes = 0
        printable_bytes = 0
        high_bytes = 0
        total_bytes = 0
        
        for chunk in read_in_chunks(str(path), chunk_size=1024 * 1024):
            byte_counts.update(chunk)
            null_bytes += chunk.count(b'\x00')
            printable_bytes += sum(1 for b in chunk if 32 <= b <= 126)
            high_bytes += sum(1 for b in chunk if b >= 128)
            total_bytes += len(chunk)
        
        if total_bytes > 0:
            features['null_byte_ratio'] = null_bytes / total_bytes
            features['printable_ratio'] = printable_bytes / total_bytes
            features['high_byte_ratio'] = high_bytes / total_bytes
        else:
            features['null_byte_ratio'] = 0.0
            features['printable_ratio'] = 0.0
            features['high_byte_ratio'] = 0.0
        
        # Unique byte count
        features['unique_bytes'] = len(byte_counts)
        features['unique_byte_ratio'] = len(byte_counts) / 256.0
        
        return features
    
    def _extract_features_sampled(self, path: Path, sample_size: int) -> Dict[str, float]:
        """Extract features from sampled chunks (Phase 3 optimization)."""
        features = {}
        file_size = path.stat().st_size
        
        # Sample from beginning, middle, and end
        samples = []
        positions = [0, max(0, file_size // 2 - sample_size // 2), max(0, file_size - sample_size)]
        
        with open(path, 'rb') as f:
            for pos in positions:
                f.seek(pos)
                chunk = f.read(sample_size)
                if chunk:
                    samples.append(chunk)
        
        # Combine samples
        combined = b''.join(samples)
        total_bytes = len(combined)
        
        if total_bytes == 0:
            return {'entropy': 0.0, 'null_byte_ratio': 0.0, 'printable_ratio': 0.0,
                   'high_byte_ratio': 0.0, 'unique_bytes': 0, 'unique_byte_ratio': 0.0}
        
        # Calculate entropy from samples
        byte_counts = Counter(combined)
        entropy = 0.0
        for count in byte_counts.values():
            probability = count / total_bytes
            if probability > 0:
                entropy -= probability * math.log2(probability)
        features['entropy'] = entropy
        
        # Byte statistics
        null_bytes = combined.count(b'\x00')
        printable_bytes = sum(1 for b in combined if 32 <= b <= 126)
        high_bytes = sum(1 for b in combined if b >= 128)
        
        features['null_byte_ratio'] = null_bytes / total_bytes
        features['printable_ratio'] = printable_bytes / total_bytes
        features['high_byte_ratio'] = high_bytes / total_bytes
        features['unique_bytes'] = len(byte_counts)
        features['unique_byte_ratio'] = len(byte_counts) / 256.0
        
        return features
    
    def predict_batch(self, feature_matrix: List[Dict[str, float]]) -> List[float]:
        """Predict anomaly scores for a batch of feature vectors (Phase 3 optimization).
        
        Args:
            feature_matrix: List of feature dictionaries
        
        Returns:
            List of anomaly scores (0.0-1.0)
        """
        if not self.is_trained:
            logger.warning("Model not trained, returning neutral scores")
            return [0.5] * len(feature_matrix)
        
        try:
            # Convert all features to vectors
            vectors = []
            for features in feature_matrix:
                vec = self.features_to_vector(features)
                vectors.append(vec[0])  # Remove the extra dimension
            
            # Stack into single matrix
            X = np.vstack(vectors)
            
            # Batch prediction
            predictions = self.model.predict(X)  # -1 for outliers, 1 for inliers
            decision_scores = self.model.decision_function(X)
            
            # Normalize scores to [0, 1] range
            anomaly_scores = []
            for pred, score in zip(predictions, decision_scores):
                if pred == -1:  # Outlier
                    # Map decision score to 0.5-1.0 range
                    normalized_score = 0.5 + (1.0 - min(1.0, abs(score) / 2.0)) * 0.5
                else:  # Inlier
                    # Map decision score to 0.0-0.5 range
                    normalized_score = max(0.0, 0.5 - score / 2.0)
                anomaly_scores.append(normalized_score)
            
            logger.debug(f"Batch predicted {len(anomaly_scores)} scores")
            return anomaly_scores
        
        except Exception as e:
            logger.error(f"Batch prediction failed: {e}")
            return [0.5] * len(feature_matrix)
    
    def features_to_vector(self, features: Dict[str, float]) -> np.ndarray:
        """
        Convert feature dictionary to numpy array vector.
        
        Args:
            features: Dictionary of features
        
        Returns:
            Numpy array of feature values
        """
        if not self.feature_names:
            self.feature_names = sorted(features.keys())
        
        vector = np.array([features.get(name, 0.0) for name in self.feature_names])
        return vector.reshape(1, -1)
    
    def train(self, benign_files: List[str]) -> bool:
        """
        Train the IsolationForest model on benign baseline files.
        
        Args:
            benign_files: List of paths to known benign files
        
        Returns:
            True if training successful
        """
        try:
            logger.info(f"Training model on {len(benign_files)} benign files...")
            
            # Extract features from all benign files
            feature_vectors = []
            for file_path in benign_files:
                try:
                    features = self.extract_features(file_path)
                    if features:
                        vector = self.features_to_vector(features)
                        feature_vectors.append(vector[0])
                except Exception as e:
                    logger.warning(f"Skipping file {file_path}: {e}")
            
            if not feature_vectors:
                logger.error("No features extracted from training files")
                return False
            
            # Convert to numpy array
            X = np.array(feature_vectors)
            
            # Normalize features
            X_scaled = self.scaler.fit_transform(X)
            
            # Train IsolationForest
            self.model.fit(X_scaled)
            self.is_trained = True
            
            logger.info("Model training completed successfully")
            return True
        
        except Exception as e:
            logger.error(f"Model training failed: {e}")
            return False
    
    def predict_anomaly_score(self, file_path: str) -> Tuple[float, Dict[str, float]]:
        """
        Predict anomaly score for a file.
        
        Args:
            file_path: Path to the file to analyze
        
        Returns:
            Tuple of (anomaly_score: 0.0-1.0, features: dict)
        """
        try:
            if not self.is_trained:
                logger.warning("Model not trained, returning default score")
                return 0.5, {}
            
            # Extract features
            features = self.extract_features(file_path)
            if not features:
                return 0.5, {}
            
            # Convert to vector and scale
            vector = self.features_to_vector(features)
            vector_scaled = self.scaler.transform(vector)
            
            # Predict anomaly score
            # IsolationForest returns -1 for anomalies, 1 for inliers
            # decision_function returns the anomaly score (lower = more anomalous)
            raw_score = self.model.decision_function(vector_scaled)[0]
            
            # Normalize to 0.0-1.0 (0 = benign, 1 = highly anomalous)
            # Using sigmoid-like transformation
            anomaly_score = 1.0 / (1.0 + math.exp(raw_score))
            
            logger.info(f"Anomaly score for {file_path}: {anomaly_score:.4f}")
            return anomaly_score, features
        
        except Exception as e:
            logger.error(f"Prediction failed for {file_path}: {e}")
            return 0.5, {}
    
    def save_model(self, model_path: str) -> bool:
        """
        Save trained model to disk.
        
        Args:
            model_path: Path to save the model
        
        Returns:
            True if successful
        """
        try:
            model_data = {
                'model': self.model,
                'scaler': self.scaler,
                'feature_names': self.feature_names,
                'is_trained': self.is_trained,
                'contamination': self.contamination
            }
            
            with open(model_path, 'wb') as f:
                pickle.dump(model_data, f)
            
            logger.info(f"Model saved to {model_path}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to save model: {e}")
            return False
    
    def load_model(self, model_path: str) -> bool:
        """
        Load trained model from disk.
        
        Args:
            model_path: Path to the saved model
        
        Returns:
            True if successful
        """
        try:
            with open(model_path, 'rb') as f:
                model_data = pickle.load(f)
            
            self.model = model_data['model']
            self.scaler = model_data['scaler']
            self.feature_names = model_data['feature_names']
            self.is_trained = model_data['is_trained']
            self.contamination = model_data.get('contamination', 0.1)
            
            logger.info(f"Model loaded from {model_path}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            return False
    
    def cluster_anomalies(self, file_paths: List[str], min_samples: int = 3) -> Dict[int, List[str]]:
        """
        Cluster anomalous files using DBSCAN for pattern detection.
        Used for dynamic signature generation.
        
        Args:
            file_paths: List of anomalous file paths
            min_samples: Minimum cluster size
        
        Returns:
            Dictionary mapping cluster_id to list of file paths
        """
        try:
            # Extract features from all files
            feature_vectors = []
            valid_files = []
            
            for file_path in file_paths:
                features = self.extract_features(file_path)
                if features:
                    vector = self.features_to_vector(features)
                    feature_vectors.append(vector[0])
                    valid_files.append(file_path)
            
            if len(feature_vectors) < min_samples:
                logger.warning("Not enough samples for clustering")
                return {0: valid_files}
            
            # Normalize features
            X = np.array(feature_vectors)
            X_scaled = self.scaler.transform(X)
            
            # Cluster using DBSCAN
            clustering = DBSCAN(eps=0.5, min_samples=min_samples).fit(X_scaled)
            labels = clustering.labels_
            
            # Group files by cluster
            clusters = {}
            for label, file_path in zip(labels, valid_files):
                if label not in clusters:
                    clusters[label] = []
                clusters[label].append(file_path)
            
            logger.info(f"Clustered {len(valid_files)} files into {len(clusters)} groups")
            return clusters
        
        except Exception as e:
            logger.error(f"Clustering failed: {e}")
            return {0: file_paths}
