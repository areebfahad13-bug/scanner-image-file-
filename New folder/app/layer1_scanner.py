"""
Layer 1: Signature Filter
High-speed detection using ClamAV and compiled YARA rules.
"""
import os
import time
from pathlib import Path
from typing import Tuple, List, Optional, Dict
import logging

from .security_io import validate_and_resolve_path

logger = logging.getLogger(__name__)

# Try to import YARA
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    logger.warning("YARA not available. Install with: pip install yara-python")

# Try to import ClamAV
try:
    import pyclamd
    CLAMAV_AVAILABLE = True
except ImportError:
    CLAMAV_AVAILABLE = False
    logger.warning("ClamAV not available. Install with: pip install pyclamd")


class Layer1Scanner:
    """
    Layer 1: High-speed signature-based malware detection.
    Uses ClamAV and compiled YARA rules for known threat detection.
    """
    
    def __init__(self, yara_rules_dir: Optional[str] = None):
        """
        Initialize Layer 1 scanner.
        
        Args:
            yara_rules_dir: Directory containing YARA rules
        """
        self.yara_rules = None
        self.clamav = None
        self.yara_rules_dir = yara_rules_dir
        
        # Initialize YARA
        if YARA_AVAILABLE and yara_rules_dir:
            self._load_yara_rules(yara_rules_dir)
        
        # Initialize ClamAV
        if CLAMAV_AVAILABLE:
            self._init_clamav()
    
    def _load_yara_rules(self, rules_dir: str) -> bool:
        """
        Load and compile YARA rules from directory.
        
        Args:
            rules_dir: Directory containing .yar or .yara files
        
        Returns:
            True if successful
        """
        try:
            rules_path = Path(rules_dir)
            if not rules_path.exists():
                logger.warning(f"YARA rules directory not found: {rules_dir}")
                return False
            
            # Find all YARA rule files
            rule_files = {}
            for ext in ['*.yar', '*.yara']:
                for rule_file in rules_path.glob(ext):
                    namespace = rule_file.stem
                    rule_files[namespace] = str(rule_file)
            
            if not rule_files:
                logger.warning(f"No YARA rules found in {rules_dir}")
                return False
            
            # Compile rules
            self.yara_rules = yara.compile(filepaths=rule_files)
            logger.info(f"Loaded {len(rule_files)} YARA rule files")
            return True
        
        except Exception as e:
            logger.error(f"Failed to load YARA rules: {e}")
            return False
    
    def _init_clamav(self) -> bool:
        """
        Initialize ClamAV connection.
        
        Returns:
            True if successful
        """
        try:
            # Try to connect to ClamAV daemon
            cd = pyclamd.ClamdUnixSocket()
            if cd.ping():
                self.clamav = cd
                logger.info("Connected to ClamAV daemon")
                return True
            
            # Try network socket
            cd = pyclamd.ClamdNetworkSocket()
            if cd.ping():
                self.clamav = cd
                logger.info("Connected to ClamAV via network socket")
                return True
            
            logger.warning("ClamAV daemon not running")
            return False
        
        except Exception as e:
            logger.error(f"Failed to initialize ClamAV: {e}")
            return False
    
    def scan_with_yara(self, file_path: str) -> Tuple[bool, float, List[str]]:
        """
        Scan file with YARA rules.
        
        Args:
            file_path: Path to file to scan
        
        Returns:
            Tuple of (is_threat: bool, confidence: float, matches: List[str])
        """
        if not YARA_AVAILABLE or not self.yara_rules:
            return False, 0.0, []
        
        try:
            path = validate_and_resolve_path(file_path, must_exist=True)
            
            # Match against all rules
            matches = self.yara_rules.match(str(path))
            
            if matches:
                match_names = [match.rule for match in matches]
                confidence = min(1.0, len(matches) * 0.3 + 0.4)  # Higher confidence with more matches
                logger.info(f"YARA matches for {file_path}: {match_names}")
                return True, confidence, match_names
            
            return False, 0.0, []
        
        except Exception as e:
            logger.error(f"YARA scan failed for {file_path}: {e}")
            return False, 0.0, []
    
    def scan_with_clamav(self, file_path: str) -> Tuple[bool, float, Optional[str]]:
        """
        Scan file with ClamAV.
        
        Args:
            file_path: Path to file to scan
        
        Returns:
            Tuple of (is_threat: bool, confidence: float, virus_name: Optional[str])
        """
        if not CLAMAV_AVAILABLE or not self.clamav:
            return False, 0.0, None
        
        try:
            path = validate_and_resolve_path(file_path, must_exist=True)
            
            # Scan file
            result = self.clamav.scan_file(str(path))
            
            if result:
                # result format: {filepath: ('FOUND', 'virusname')}
                for file_result in result.values():
                    if file_result[0] == 'FOUND':
                        virus_name = file_result[1]
                        logger.info(f"ClamAV detection for {file_path}: {virus_name}")
                        return True, 0.95, virus_name  # High confidence for ClamAV
            
            return False, 0.0, None
        
        except Exception as e:
            logger.error(f"ClamAV scan failed for {file_path}: {e}")
            return False, 0.0, None
    
    def scan_file(self, file_path: str) -> Tuple[bool, float, Dict[str, any]]:
        """
        Scan file using both YARA and ClamAV.
        Returns immediately if known threat is detected.
        
        Args:
            file_path: Path to file to scan
        
        Returns:
            Tuple of (is_known_threat: bool, confidence_score: float, details: dict)
        """
        start_time = time.time()
        
        details = {
            'layer': 1,
            'clamav': {'detected': False, 'virus_name': None},
            'yara': {'detected': False, 'matches': []},
            'scan_time': 0.0
        }
        
        try:
            # Validate file
            path = validate_and_resolve_path(file_path, must_exist=True)
            
            # Quick file size check (skip very large files for speed)
            file_size = path.stat().st_size
            if file_size > 500 * 1024 * 1024:  # 500MB
                logger.warning(f"File too large for Layer 1 scan: {file_path}")
                return False, 0.0, details
            
            max_confidence = 0.0
            is_threat = False
            
            # Scan with ClamAV (fastest, most reliable)
            if CLAMAV_AVAILABLE and self.clamav:
                clamav_threat, clamav_conf, virus_name = self.scan_with_clamav(file_path)
                details['clamav']['detected'] = clamav_threat
                details['clamav']['virus_name'] = virus_name
                
                if clamav_threat:
                    is_threat = True
                    max_confidence = max(max_confidence, clamav_conf)
            
            # Scan with YARA (custom rules, fast)
            if YARA_AVAILABLE and self.yara_rules:
                yara_threat, yara_conf, matches = self.scan_with_yara(file_path)
                details['yara']['detected'] = yara_threat
                details['yara']['matches'] = matches
                
                if yara_threat:
                    is_threat = True
                    max_confidence = max(max_confidence, yara_conf)
            
            # Calculate final confidence (boost if both detect)
            if details['clamav']['detected'] and details['yara']['detected']:
                max_confidence = min(0.98, max_confidence + 0.15)
            
            scan_time = time.time() - start_time
            details['scan_time'] = scan_time
            
            logger.info(f"Layer 1 scan completed for {file_path}: threat={is_threat}, confidence={max_confidence:.2f}, time={scan_time:.3f}s")
            
            return is_threat, max_confidence, details
        
        except Exception as e:
            logger.error(f"Layer 1 scan error for {file_path}: {e}")
            details['error'] = str(e)
            return False, 0.0, details
    
    def scan_directory(self, directory: str, recursive: bool = True) -> List[Dict]:
        """
        Scan all files in a directory.
        
        Args:
            directory: Directory to scan
            recursive: Whether to scan recursively
        
        Returns:
            List of scan results
        """
        results = []
        dir_path = Path(directory)
        
        try:
            if recursive:
                file_iterator = dir_path.rglob('*')
            else:
                file_iterator = dir_path.glob('*')
            
            for file_path in file_iterator:
                if file_path.is_file():
                    is_threat, confidence, details = self.scan_file(str(file_path))
                    
                    results.append({
                        'file': str(file_path),
                        'is_threat': is_threat,
                        'confidence': confidence,
                        'details': details
                    })
            
            return results
        
        except Exception as e:
            logger.error(f"Directory scan failed for {directory}: {e}")
            return []
    
    def reload_rules(self) -> bool:
        """
        Reload YARA rules (useful for dynamic rule updates).
        
        Returns:
            True if successful
        """
        if not YARA_AVAILABLE or not self.yara_rules_dir:
            return False
        
        return self._load_yara_rules(self.yara_rules_dir)
    
    def add_yara_rule(self, rule_content: str, rule_name: str) -> bool:
        """
        Add a new YARA rule dynamically.
        Used for Layer 2 dynamic signature generation.
        
        Args:
            rule_content: YARA rule as string
            rule_name: Name for the rule
        
        Returns:
            True if successful
        """
        if not YARA_AVAILABLE or not self.yara_rules_dir:
            return False
        
        try:
            rules_path = Path(self.yara_rules_dir)
            rules_path.mkdir(parents=True, exist_ok=True)
            
            # Save rule to file
            rule_file = rules_path / f"{rule_name}.yar"
            with open(rule_file, 'w') as f:
                f.write(rule_content)
            
            # Reload all rules
            return self.reload_rules()
        
        except Exception as e:
            logger.error(f"Failed to add YARA rule: {e}")
            return False
    
    def get_statistics(self) -> Dict[str, any]:
        """
        Get scanner statistics and status.
        
        Returns:
            Dictionary with scanner status
        """
        return {
            'yara_available': YARA_AVAILABLE,
            'yara_loaded': self.yara_rules is not None,
            'clamav_available': CLAMAV_AVAILABLE,
            'clamav_connected': self.clamav is not None
        }
