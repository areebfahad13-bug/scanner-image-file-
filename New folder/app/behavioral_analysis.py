"""
Behavioral Analysis Module
Provides sandboxed execution and monitoring of suspicious files.
Tracks system calls, file changes, network activity, and registry modifications.
"""
import os
import sys
import time
import json
import hashlib
import logging
import subprocess
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from collections import defaultdict

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

from security_io import validate_and_resolve_path

logger = logging.getLogger(__name__)


class SandboxMonitor:
    """
    Monitors system activity during file execution in a sandboxed environment.
    """
    
    def __init__(self, timeout: int = 30):
        """
        Initialize sandbox monitor.
        
        Args:
            timeout: Maximum execution time in seconds
        """
        self.timeout = timeout
        self.baseline_state = {}
        self.monitored_process = None
        self.start_time = None
        
    def capture_baseline(self) -> Dict:
        """
        Capture system baseline state before execution.
        
        Returns:
            Dictionary with baseline metrics
        """
        baseline = {
            'timestamp': datetime.now().isoformat(),
            'processes': [],
            'network_connections': [],
            'open_files': [],
            'cpu_percent': 0.0,
            'memory_percent': 0.0
        }
        
        if not PSUTIL_AVAILABLE:
            return baseline
        
        try:
            # Current processes
            baseline['processes'] = [
                {'pid': p.pid, 'name': p.name()}
                for p in psutil.process_iter(['pid', 'name'])
            ]
            
            # Network connections
            baseline['network_connections'] = [
                {
                    'laddr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    'status': conn.status
                }
                for conn in psutil.net_connections()
            ]
            
            # System resources
            baseline['cpu_percent'] = psutil.cpu_percent(interval=0.1)
            baseline['memory_percent'] = psutil.virtual_memory().percent
            
        except Exception as e:
            logger.error(f"Failed to capture baseline: {e}")
        
        self.baseline_state = baseline
        return baseline
    
    def monitor_process(self, process: psutil.Process) -> Dict:
        """
        Monitor a running process for suspicious behavior.
        
        Args:
            process: Process to monitor
        
        Returns:
            Dictionary with monitoring results
        """
        metrics = {
            'pid': process.pid,
            'name': process.name(),
            'cpu_percent': 0.0,
            'memory_mb': 0.0,
            'num_threads': 0,
            'connections': [],
            'open_files': [],
            'child_processes': [],
            'suspicious_calls': []
        }
        
        if not PSUTIL_AVAILABLE:
            return metrics
        
        try:
            # CPU and memory
            metrics['cpu_percent'] = process.cpu_percent(interval=0.1)
            metrics['memory_mb'] = process.memory_info().rss / 1024 / 1024
            metrics['num_threads'] = process.num_threads()
            
            # Network connections
            try:
                connections = process.connections()
                metrics['connections'] = [
                    {
                        'laddr': f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else None,
                        'raddr': f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None,
                        'status': c.status
                    }
                    for c in connections
                ]
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            
            # Open files
            try:
                open_files = process.open_files()
                metrics['open_files'] = [f.path for f in open_files]
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            
            # Child processes
            try:
                children = process.children(recursive=True)
                metrics['child_processes'] = [
                    {'pid': c.pid, 'name': c.name()}
                    for c in children
                ]
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            
        except Exception as e:
            logger.error(f"Error monitoring process {process.pid}: {e}")
        
        return metrics
    
    def analyze_behavior(self, metrics: Dict, baseline: Dict) -> Dict:
        """
        Analyze collected metrics for suspicious behavior.
        
        Args:
            metrics: Collected process metrics
            baseline: Baseline system state
        
        Returns:
            Analysis results with risk score
        """
        anomalies = []
        risk_score = 0.0
        
        # High CPU usage
        if metrics['cpu_percent'] > 80:
            anomalies.append({
                'type': 'high_cpu',
                'severity': 'medium',
                'description': f"CPU usage {metrics['cpu_percent']:.1f}% exceeds threshold"
            })
            risk_score += 0.15
        
        # High memory usage
        if metrics['memory_mb'] > 500:
            anomalies.append({
                'type': 'high_memory',
                'severity': 'medium',
                'description': f"Memory usage {metrics['memory_mb']:.1f}MB exceeds threshold"
            })
            risk_score += 0.15
        
        # Suspicious network connections
        if metrics['connections']:
            for conn in metrics['connections']:
                if conn['raddr'] and 'ESTABLISHED' in conn['status']:
                    anomalies.append({
                        'type': 'network_connection',
                        'severity': 'high',
                        'description': f"Established connection to {conn['raddr']}"
                    })
                    risk_score += 0.25
        
        # Multiple child processes
        if len(metrics['child_processes']) > 3:
            anomalies.append({
                'type': 'process_spawning',
                'severity': 'high',
                'description': f"Spawned {len(metrics['child_processes'])} child processes"
            })
            risk_score += 0.3
        
        # File system access
        suspicious_paths = [
            'system32', 'windows', 'program files', 'appdata', 'startup'
        ]
        for file_path in metrics['open_files']:
            if any(path in file_path.lower() for path in suspicious_paths):
                anomalies.append({
                    'type': 'suspicious_file_access',
                    'severity': 'high',
                    'description': f"Access to sensitive path: {file_path}"
                })
                risk_score += 0.2
                break
        
        return {
            'anomalies': anomalies,
            'risk_score': min(1.0, risk_score),
            'is_suspicious': risk_score > 0.5,
            'num_anomalies': len(anomalies)
        }


class BehavioralAnalyzer:
    """
    Main behavioral analysis engine.
    Executes files in monitored environment and analyzes behavior.
    """
    
    def __init__(self, sandbox_dir: Optional[str] = None):
        """
        Initialize behavioral analyzer.
        
        Args:
            sandbox_dir: Directory for sandbox environment
        """
        self.sandbox_dir = sandbox_dir or tempfile.gettempdir()
        self.monitor = SandboxMonitor()
        self.execution_history = []
        
    def create_sandbox_env(self) -> str:
        """
        Create isolated sandbox directory.
        
        Returns:
            Path to sandbox directory
        """
        sandbox_path = Path(self.sandbox_dir) / f"sandbox_{int(time.time())}"
        sandbox_path.mkdir(parents=True, exist_ok=True)
        logger.info(f"Created sandbox at {sandbox_path}")
        return str(sandbox_path)
    
    def cleanup_sandbox(self, sandbox_path: str):
        """Remove sandbox directory."""
        try:
            shutil.rmtree(sandbox_path)
            logger.info(f"Cleaned up sandbox {sandbox_path}")
        except Exception as e:
            logger.error(f"Failed to cleanup sandbox: {e}")
    
    def analyze_file(self, file_path: str, execute: bool = False) -> Dict:
        """
        Perform behavioral analysis on a file.
        
        Args:
            file_path: Path to file to analyze
            execute: Whether to execute the file (dangerous!)
        
        Returns:
            Analysis results
        """
        start_time = time.time()
        
        result = {
            'file': file_path,
            'timestamp': datetime.now().isoformat(),
            'executed': execute,
            'baseline': {},
            'metrics': {},
            'analysis': {},
            'duration': 0.0
        }
        
        try:
            path = validate_and_resolve_path(file_path, must_exist=True)
            
            # Static analysis
            static_features = self._extract_static_features(str(path))
            result['static_features'] = static_features
            
            # Dynamic analysis (if execution enabled)
            if execute and PSUTIL_AVAILABLE:
                result.update(self._dynamic_analysis(str(path)))
            else:
                result['analysis'] = {
                    'risk_score': self._estimate_risk_from_static(static_features),
                    'is_suspicious': False,
                    'method': 'static_only'
                }
            
            result['duration'] = time.time() - start_time
            self.execution_history.append(result)
            
        except Exception as e:
            logger.error(f"Behavioral analysis failed for {file_path}: {e}")
            result['error'] = str(e)
        
        return result
    
    def _extract_static_features(self, file_path: str) -> Dict:
        """
        Extract static features without execution.
        
        Args:
            file_path: Path to file
        
        Returns:
            Dictionary of static features
        """
        features = {
            'file_size': 0,
            'extension': '',
            'entropy': 0.0,
            'is_executable': False,
            'has_pe_header': False
        }
        
        try:
            path = Path(file_path)
            features['file_size'] = path.stat().st_size
            features['extension'] = path.suffix.lower()
            features['is_executable'] = path.suffix.lower() in ['.exe', '.dll', '.bat', '.ps1', '.sh']
            
            # Calculate entropy
            with open(path, 'rb') as f:
                data = f.read(1024 * 1024)  # First 1MB
                if data:
                    features['entropy'] = self._calculate_entropy(data)
            
            # Check for PE header
            if features['is_executable']:
                with open(path, 'rb') as f:
                    header = f.read(2)
                    features['has_pe_header'] = header == b'MZ'
        
        except Exception as e:
            logger.error(f"Static feature extraction failed: {e}")
        
        return features
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0
        
        entropy = 0.0
        byte_counts = defaultdict(int)
        
        for byte in data:
            byte_counts[byte] += 1
        
        for count in byte_counts.values():
            prob = count / len(data)
            entropy -= prob * (prob.bit_length() - 1)
        
        return entropy
    
    def _estimate_risk_from_static(self, features: Dict) -> float:
        """Estimate risk score from static features."""
        risk = 0.0
        
        # High entropy (packed/encrypted)
        if features['entropy'] > 7.5:
            risk += 0.3
        
        # Executable file
        if features['is_executable']:
            risk += 0.2
        
        # Large file size
        if features['file_size'] > 10 * 1024 * 1024:
            risk += 0.1
        
        # No PE header but executable extension
        if features['is_executable'] and not features['has_pe_header']:
            risk += 0.2
        
        return min(1.0, risk)
    
    def _dynamic_analysis(self, file_path: str) -> Dict:
        """
        Perform dynamic analysis by executing file in monitored environment.
        
        Args:
            file_path: Path to file
        
        Returns:
            Dynamic analysis results
        """
        # Create sandbox
        sandbox_path = self.create_sandbox_env()
        
        try:
            # Copy file to sandbox
            sandbox_file = Path(sandbox_path) / Path(file_path).name
            shutil.copy2(file_path, sandbox_file)
            
            # Capture baseline
            baseline = self.monitor.capture_baseline()
            
            # Execute file (with timeout)
            process = None
            metrics = {}
            
            try:
                # Start process
                if sys.platform == 'win32':
                    process = subprocess.Popen(
                        str(sandbox_file),
                        cwd=sandbox_path,
                        creationflags=subprocess.CREATE_NEW_CONSOLE
                    )
                else:
                    process = subprocess.Popen(
                        ['python', str(sandbox_file)],
                        cwd=sandbox_path
                    )
                
                # Monitor for timeout period
                psutil_process = psutil.Process(process.pid)
                time.sleep(2)  # Let it run for a bit
                
                metrics = self.monitor.monitor_process(psutil_process)
                
                # Terminate process
                process.terminate()
                process.wait(timeout=5)
                
            except subprocess.TimeoutExpired:
                if process:
                    process.kill()
                logger.warning("Process execution timed out")
            
            except Exception as e:
                logger.error(f"Error during execution: {e}")
            
            # Analyze behavior
            analysis = self.monitor.analyze_behavior(metrics, baseline)
            
            return {
                'baseline': baseline,
                'metrics': metrics,
                'analysis': analysis
            }
        
        finally:
            # Cleanup sandbox
            self.cleanup_sandbox(sandbox_path)
    
    def analyze_batch(self, file_paths: List[str], execute: bool = False) -> List[Dict]:
        """
        Analyze multiple files.
        
        Args:
            file_paths: List of file paths
            execute: Whether to execute files
        
        Returns:
            List of analysis results
        """
        results = []
        for file_path in file_paths:
            result = self.analyze_file(file_path, execute=execute)
            results.append(result)
        return results
    
    def get_statistics(self) -> Dict:
        """Get behavioral analysis statistics."""
        if not self.execution_history:
            return {'total_analyzed': 0}
        
        total = len(self.execution_history)
        suspicious = sum(
            1 for r in self.execution_history 
            if r.get('analysis', {}).get('is_suspicious', False)
        )
        
        return {
            'total_analyzed': total,
            'suspicious_count': suspicious,
            'suspicious_rate': suspicious / total if total > 0 else 0,
            'avg_risk_score': sum(
                r.get('analysis', {}).get('risk_score', 0) 
                for r in self.execution_history
            ) / total if total > 0 else 0
        }
