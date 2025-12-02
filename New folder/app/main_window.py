"""
Main Window - EDR System with Three-Layered Triage Architecture
PyQt5 GUI with Bento Grid Layout and comprehensive dashboard.
"""
import sys
import os
import hashlib
from pathlib import Path
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QPushButton, QLabel, QFileDialog, QTextEdit, QProgressBar, QMessageBox,
    QGroupBox, QTabWidget, QTableWidget, QTableWidgetItem, QHeaderView
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QColor, QPalette
import time
import logging

# Import our EDR layers
from .layer1_scanner import Layer1Scanner
from .layer2_apsa import Layer2APSA
from .layer3_apt import Layer3APT
from .remediation_helper import execute_privileged_action
from .pipeline_controller import PipelineController

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PipelineWorker(QThread):
    """
    Worker thread for parallel pipeline scanning with real-time updates.
    Uses multiprocessing pipeline for better performance.
    """
    progress = pyqtSignal(dict)  # Statistics updates
    log_message = pyqtSignal(str)  # Log messages
    finished = pyqtSignal()
    
    def __init__(self, directory, yara_rules_dir, db_path, ml_model_path=None, vt_api_key=None):
        super().__init__()
        self.directory = directory
        self.yara_rules_dir = yara_rules_dir
        self.db_path = db_path
        self.ml_model_path = ml_model_path
        self.vt_api_key = vt_api_key
        self.pipeline = None
    
    def progress_callback(self, stats):
        """Callback for pipeline progress updates."""
        self.progress.emit(stats)
    
    def run(self):
        """Execute pipeline scan."""
        try:
            self.log_message.emit("Initializing parallel pipeline scanner...")
            
            # Create pipeline controller with progress callback
            self.pipeline = PipelineController(
                num_workers=None,  # Auto-detect CPU cores
                yara_rules_dir=self.yara_rules_dir,
                ml_model_path=self.ml_model_path,
                db_path=self.db_path,
                vt_api_key=self.vt_api_key,
                progress_callback=self.progress_callback
            )
            
            self.log_message.emit(f"Starting scan of: {self.directory}")
            self.log_message.emit(f"Workers: {self.pipeline.num_workers}")
            
            # Start the scan
            self.pipeline.start_scan([self.directory])
            
            # Wait for completion (monitor the aggregator thread)
            while self.pipeline.aggregator_thread and self.pipeline.aggregator_thread.is_alive():
                time.sleep(1)
            
            self.log_message.emit("Pipeline scan complete")
            self.finished.emit()
            
        except Exception as e:
            logger.error(f"Pipeline worker error: {e}")
            self.log_message.emit(f"Error: {str(e)}")
            self.finished.emit()
    
    def stop(self):
        """Stop the pipeline scan."""
        if self.pipeline:
            self.pipeline.stop_scan()


class ScanWorker(QThread):
    """
    Worker thread for orchestrating three-layered scanning.
    Prevents GUI freeze during resource-intensive analysis.
    """
    progress = pyqtSignal(str, dict)  # message, details
    finished = pyqtSignal(list)  # results
    
    def __init__(self, directory, layer1, layer2, layer3, quarantine_dir):
        super().__init__()
        self.directory = directory
        self.layer1 = layer1
        self.layer2 = layer2
        self.layer3 = layer3
        self.quarantine_dir = quarantine_dir
        self.is_running = True
    
    def calculate_file_hash(self, file_path):
        """Calculate SHA256 hash of a file."""
        try:
            hasher = hashlib.sha256()
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except:
            return None
    
    def run(self):
        """Execute three-layered scan on directory."""
        results = []
        
        try:
            # Collect all files
            dir_path = Path(self.directory)
            all_files = [f for f in dir_path.rglob('*') if f.is_file()]
            
            total_files = len(all_files)
            self.progress.emit(f"Found {total_files} files to scan", {})
            
            for idx, file_path in enumerate(all_files):
                if not self.is_running:
                    break
                
                file_str = str(file_path)
                file_hash = self.calculate_file_hash(file_str)
                
                self.progress.emit(
                    f"Scanning [{idx+1}/{total_files}]: {file_path.name}",
                    {'progress': (idx+1) / total_files * 100}
                )
                
                scan_start = time.time()
                
                # Layer 1: Signature Filter
                is_known_threat, l1_confidence, l1_details = self.layer1.scan_file(file_str)
                
                layer2_score = 0.0
                l2_details = None
                final_score = 0.0
                l3_details = None
                
                # Layer 2: Only if Layer 1 doesn't detect known threat
                if not is_known_threat:
                    layer2_score, l2_details = self.layer2.analyze_file(file_str)
                    
                    # Layer 3: APT Correlation
                    final_score, l3_details = self.layer3.correlate_threat(
                        file_str, file_hash, l1_details, l2_details
                    )
                else:
                    # Known threat - still correlate for tracking
                    final_score, l3_details = self.layer3.correlate_threat(
                        file_str, file_hash, l1_details, None
                    )
                
                scan_time = time.time() - scan_start
                
                # Determine overall threat status
                is_threat = is_known_threat or layer2_score >= 0.6 or final_score >= 0.6
                
                result = {
                    'file': file_str,
                    'file_name': file_path.name,
                    'file_hash': file_hash,
                    'is_threat': is_threat,
                    'is_known_threat': is_known_threat,
                    'layer1_confidence': l1_confidence,
                    'layer2_score': layer2_score,
                    'final_score': final_score,
                    'scan_time': scan_time,
                    'layer1_details': l1_details,
                    'layer2_details': l2_details,
                    'layer3_details': l3_details
                }
                
                results.append(result)
            
            self.finished.emit(results)
        
        except Exception as e:
            logger.error(f"Scan worker error: {e}")
            self.progress.emit(f"Error: {str(e)}", {})
    
    def stop(self):
        """Stop the scanning process."""
        self.is_running = False


class RiskScoreWidget(QWidget):
    """Large central risk score display widget."""
    
    def __init__(self):
        super().__init__()
        self.score = 0.0
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignCenter)
        
        self.title_label = QLabel("Threat Likelihood Score")
        self.title_label.setAlignment(Qt.AlignCenter)
        title_font = QFont()
        title_font.setPointSize(12)
        title_font.setBold(True)
        self.title_label.setFont(title_font)
        
        self.score_label = QLabel("0.0%")
        self.score_label.setAlignment(Qt.AlignCenter)
        score_font = QFont()
        score_font.setPointSize(48)
        score_font.setBold(True)
        self.score_label.setFont(score_font)
        
        self.status_label = QLabel("CLEAN")
        self.status_label.setAlignment(Qt.AlignCenter)
        status_font = QFont()
        status_font.setPointSize(16)
        self.status_label.setFont(status_font)
        
        layout.addWidget(self.title_label)
        layout.addWidget(self.score_label)
        layout.addWidget(self.status_label)
        
        self.setLayout(layout)
        self.update_score(0.0)
    
    def update_score(self, score):
        """Update the displayed score and color."""
        self.score = score
        percentage = score * 100
        self.score_label.setText(f"{percentage:.1f}%")
        
        # Color coding
        if score < 0.3:
            color = "green"
            status = "CLEAN"
        elif score < 0.6:
            color = "orange"
            status = "SUSPICIOUS"
        else:
            color = "red"
            status = "THREAT"
        
        self.score_label.setStyleSheet(f"color: {color};")
        self.status_label.setText(status)
        self.status_label.setStyleSheet(f"color: {color};")


class LayerBreakdownWidget(QWidget):
    """Widget showing score breakdown by layer."""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        title = QLabel("Layered Detection Breakdown")
        title_font = QFont()
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)
        
        self.layer1_bar = QProgressBar()
        self.layer2_bar = QProgressBar()
        self.layer3_bar = QProgressBar()
        
        layout.addWidget(QLabel("Layer 1 (Signature):"))
        layout.addWidget(self.layer1_bar)
        layout.addWidget(QLabel("Layer 2 (Behavioral):"))
        layout.addWidget(self.layer2_bar)
        layout.addWidget(QLabel("Layer 3 (APT Correlation):"))
        layout.addWidget(self.layer3_bar)
        
        layout.addStretch()
        self.setLayout(layout)
    
    def update_scores(self, l1_score, l2_score, l3_score):
        """Update the progress bars."""
        self.layer1_bar.setValue(int(l1_score * 100))
        self.layer2_bar.setValue(int(l2_score * 100))
        self.layer3_bar.setValue(int(l3_score * 100))
        
        # Color code bars
        for bar, score in [(self.layer1_bar, l1_score), 
                          (self.layer2_bar, l2_score),
                          (self.layer3_bar, l3_score)]:
            if score < 0.3:
                bar.setStyleSheet("QProgressBar::chunk { background-color: green; }")
            elif score < 0.6:
                bar.setStyleSheet("QProgressBar::chunk { background-color: orange; }")
            else:
                bar.setStyleSheet("QProgressBar::chunk { background-color: red; }")


class PerformanceWidget(QWidget):
    """Widget displaying scan performance metrics."""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        title = QLabel("Performance Metrics")
        title_font = QFont()
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)
        
        self.latency_label = QLabel("Scan Latency: N/A")
        self.throughput_label = QLabel("Throughput: N/A")
        self.files_scanned_label = QLabel("Files Scanned: 0")
        
        layout.addWidget(self.latency_label)
        layout.addWidget(self.throughput_label)
        layout.addWidget(self.files_scanned_label)
        layout.addStretch()
        
        self.setLayout(layout)
    
    def update_metrics(self, latency, throughput, files_scanned):
        """Update performance metrics."""
        self.latency_label.setText(f"Scan Latency: {latency:.2f}s")
        self.throughput_label.setText(f"Throughput: {throughput:.2f} MB/s")
        self.files_scanned_label.setText(f"Files Scanned: {files_scanned}")


class MainWindow(QMainWindow):
    """Main EDR application window with Bento Grid layout."""
    
    def __init__(self):
        super().__init__()
        
        # Initialize paths
        self.base_dir = Path(__file__).parent.parent
        self.data_dir = self.base_dir / 'data'
        self.yara_rules_dir = self.data_dir / 'yara_rules'
        self.quarantine_dir = self.data_dir / 'quarantine'
        self.db_path = self.data_dir / 'events_db.sqlite'
        
        # Ensure directories exist
        self.yara_rules_dir.mkdir(parents=True, exist_ok=True)
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize EDR layers
        self.layer1 = Layer1Scanner(yara_rules_dir=str(self.yara_rules_dir))
        self.layer2 = Layer2APSA(
            ml_model_path=None,
            yara_rules_dir=str(self.yara_rules_dir),
            anomaly_threshold=0.6
        )
        self.layer3 = Layer3APT(db_path=str(self.db_path))
        
        self.scan_worker = None
        self.pipeline_worker = None
        self.scan_results = []
        self.use_pipeline = True  # Toggle for pipeline vs. sequential mode
        
        self.init_ui()
        
        logger.info("EDR System initialized")
    
    def init_ui(self):
        """Initialize the user interface."""
        self.setWindowTitle('EDR System - Three-Layered Triage Architecture')
        self.setGeometry(100, 100, 1400, 900)
        
        # Create central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Create tabs
        tabs = QTabWidget()
        
        # Dashboard tab
        dashboard_tab = self.create_dashboard_tab()
        tabs.addTab(dashboard_tab, "Dashboard")
        
        # Quarantine tab
        quarantine_tab = self.create_quarantine_tab()
        tabs.addTab(quarantine_tab, "Quarantine Management")
        
        main_layout.addWidget(tabs)
        
        # Status bar
        self.statusBar().showMessage('Ready')
    
    def create_dashboard_tab(self):
        """Create the main dashboard with Bento Grid layout."""
        dashboard = QWidget()
        layout = QGridLayout(dashboard)
        
        # Top: Scan controls
        controls_group = QGroupBox("Scan Controls")
        controls_layout = QHBoxLayout()
        
        self.scan_btn = QPushButton('Select Directory to Scan')
        self.scan_btn.setMinimumHeight(40)
        self.scan_btn.clicked.connect(self.select_directory)
        
        self.stop_btn = QPushButton('Stop Scan')
        self.stop_btn.setMinimumHeight(40)
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_scan)
        
        controls_layout.addWidget(self.scan_btn)
        controls_layout.addWidget(self.stop_btn)
        
        # Add mode toggle
        self.mode_label = QLabel("Mode: Parallel Pipeline")
        mode_font = QFont()
        mode_font.setBold(True)
        self.mode_label.setFont(mode_font)
        controls_layout.addWidget(self.mode_label)
        
        controls_group.setLayout(controls_layout)
        
        layout.addWidget(controls_group, 0, 0, 1, 3)
        
        # Row 1: Central Risk Score (large tile)
        self.risk_score_widget = RiskScoreWidget()
        self.risk_score_widget.setMinimumHeight(200)
        layout.addWidget(self.risk_score_widget, 1, 0, 2, 1)
        
        # Row 1-2: Layer Breakdown
        self.layer_breakdown_widget = LayerBreakdownWidget()
        layout.addWidget(self.layer_breakdown_widget, 1, 1, 2, 1)
        
        # Row 1-2: Performance Metrics
        self.performance_widget = PerformanceWidget()
        layout.addWidget(self.performance_widget, 1, 2, 2, 1)
        
        # Row 3: System Activity Log (full width)
        log_group = QGroupBox("System Activity Log")
        log_layout = QVBoxLayout()
        
        self.progress_bar = QProgressBar()
        self.progress_bar.hide()
        
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setMaximumHeight(300)
        
        log_layout.addWidget(self.progress_bar)
        log_layout.addWidget(self.log_text)
        log_group.setLayout(log_layout)
        
        layout.addWidget(log_group, 3, 0, 1, 3)
        
        return dashboard
    
    def create_quarantine_tab(self):
        """Create quarantine management tab."""
        quarantine_widget = QWidget()
        layout = QVBoxLayout(quarantine_widget)
        
        # Controls
        controls_layout = QHBoxLayout()
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh_quarantine)
        restore_btn = QPushButton("Restore Selected")
        restore_btn.clicked.connect(self.restore_selected)
        delete_btn = QPushButton("Delete Selected")
        delete_btn.clicked.connect(self.delete_selected)
        
        controls_layout.addWidget(refresh_btn)
        controls_layout.addWidget(restore_btn)
        controls_layout.addWidget(delete_btn)
        controls_layout.addStretch()
        
        layout.addLayout(controls_layout)
        
        # Quarantine table
        self.quarantine_table = QTableWidget()
        self.quarantine_table.setColumnCount(4)
        self.quarantine_table.setHorizontalHeaderLabels(['File', 'Quarantine Date', 'Threat Score', 'Actions'])
        self.quarantine_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        
        layout.addWidget(self.quarantine_table)
        
        return quarantine_widget
    
    def select_directory(self):
        """Select directory and start scan."""
        directory = QFileDialog.getExistingDirectory(self, "Select Directory to Scan")
        if directory:
            self.start_scan(directory)
    
    def start_scan(self, directory):
        """Start the three-layered scan."""
        self.scan_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.show()
        self.progress_bar.setValue(0)
        self.log_text.clear()
        self.log_text.append(f"<b>Starting scan of:</b> {directory}\n")
        
        if self.use_pipeline:
            # Use parallel pipeline mode
            self.log_text.append("<b>Mode:</b> Parallel Pipeline (Multiprocessing)")
            self.pipeline_worker = PipelineWorker(
                directory,
                str(self.yara_rules_dir),
                str(self.db_path),
                ml_model_path=None,
                vt_api_key=os.environ.get('VT_API_KEY')
            )
            self.pipeline_worker.progress.connect(self.update_pipeline_progress)
            self.pipeline_worker.log_message.connect(self.append_log)
            self.pipeline_worker.finished.connect(self.pipeline_scan_finished)
            self.pipeline_worker.start()
        else:
            # Use sequential mode (original)
            self.log_text.append("<b>Mode:</b> Sequential (Single-threaded)")
            self.scan_worker = ScanWorker(
                directory,
                self.layer1,
                self.layer2,
                self.layer3,
                str(self.quarantine_dir)
            )
            self.scan_worker.progress.connect(self.update_progress)
            self.scan_worker.finished.connect(self.scan_finished)
            self.scan_worker.start()
    
    def append_log(self, message):
        """Append a log message."""
        self.log_text.append(message)
    
    def update_pipeline_progress(self, stats):
        """Update UI with pipeline statistics."""
        files_scanned = stats.get('files_scanned', 0)
        threats_found = stats.get('threats_found', 0)
        avg_score = stats.get('avg_score', 0.0)
        
        # Update risk score widget
        self.risk_score_widget.update_score(avg_score)
        
        # Update performance widget (approximate throughput)
        self.performance_widget.update_metrics(
            latency=0.0,  # Not calculated in pipeline mode
            throughput=0.0,
            files_scanned=files_scanned
        )
        
        # Log progress
        if files_scanned % 10 == 0 or threats_found > 0:
            self.log_text.append(
                f"Progress: {files_scanned} files | "
                f"{threats_found} threats | "
                f"Avg score: {avg_score:.1%}"
            )
        
        # Update progress bar (indeterminate since we don't know total)
        if files_scanned > 0:
            self.progress_bar.setMaximum(0)  # Indeterminate mode
    
    def pipeline_scan_finished(self):
        """Handle pipeline scan completion."""
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.hide()
        
        self.log_text.append("\n<b>===== Pipeline Scan Complete =====</b>")
        self.log_text.append("Results saved to database")
        self.log_text.append(f"Database: {self.db_path}")
        
        # Load results from database
        self.load_results_from_db()
    
    def load_results_from_db(self):
        """Load scan results from the database."""
        try:
            import sqlite3
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            cursor.execute('SELECT path, payload FROM scan_results ORDER BY last_seen DESC LIMIT 100')
            results = cursor.fetchall()
            
            conn.close()
            
            if results:
                self.log_text.append(f"\n<b>Loaded {len(results)} results from database</b>")
                
                # Parse and display summary
                threat_count = 0
                for path, payload_str in results:
                    try:
                        payload = eval(payload_str)  # Convert string back to dict
                        score = payload.get('final_score', 0)
                        if score >= 0.6:
                            threat_count += 1
                    except:
                        pass
                
                if threat_count > 0:
                    self.log_text.append(f"<span style='color: red;'>⚠️ Found {threat_count} threats</span>")
                else:
                    self.log_text.append("<span style='color: green;'>✅ No threats detected</span>")
            else:
                self.log_text.append("No results found in database")
                
        except Exception as e:
            logger.error(f"Failed to load results from DB: {e}")
            self.log_text.append(f"<span style='color: orange;'>Warning: Could not load results - {e}</span>")
    
    def start_scan_original(self, directory):
        """Original start scan method - kept for reference."""
        self.scan_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.show()
        self.progress_bar.setValue(0)
        self.log_text.clear()
        self.log_text.append(f"<b>Starting three-layered scan of:</b> {directory}\n")
        
        # Create and start worker
        self.scan_worker = ScanWorker(
            directory,
            self.layer1,
            self.layer2,
            self.layer3,
            str(self.quarantine_dir)
        )
        self.scan_worker.progress.connect(self.update_progress)
        self.scan_worker.finished.connect(self.scan_finished)
        self.scan_worker.start()
    
    def stop_scan(self):
        """Stop the current scan."""
        if self.pipeline_worker:
            self.pipeline_worker.stop()
            self.log_text.append("<span style='color: orange;'>Pipeline scan stopped by user</span>")
        elif self.scan_worker:
            self.scan_worker.stop()
            self.log_text.append("<span style='color: orange;'>Scan stopped by user</span>")
    
    def update_progress(self, message, details):
        """Update progress during scan."""
        self.log_text.append(message)
        
        if 'progress' in details:
            self.progress_bar.setValue(int(details['progress']))
    
    def scan_finished(self, results):
        """Handle scan completion."""
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.hide()
        
        self.scan_results = results
        
        # Calculate statistics
        total_files = len(results)
        threats_found = sum(1 for r in results if r['is_threat'])
        total_time = sum(r['scan_time'] for r in results)
        
        # Calculate average scores
        avg_l1 = sum(r['layer1_confidence'] for r in results) / total_files if total_files > 0 else 0
        avg_l2 = sum(r['layer2_score'] for r in results) / total_files if total_files > 0 else 0
        avg_final = sum(r['final_score'] for r in results) / total_files if total_files > 0 else 0
        
        # Update widgets
        max_score = max((r['final_score'] for r in results), default=0)
        self.risk_score_widget.update_score(max_score)
        self.layer_breakdown_widget.update_scores(avg_l1, avg_l2, avg_final)
        
        # Calculate throughput (rough estimate)
        total_size_mb = sum(Path(r['file']).stat().st_size for r in results if Path(r['file']).exists()) / (1024 * 1024)
        throughput = total_size_mb / total_time if total_time > 0 else 0
        avg_latency = total_time / total_files if total_files > 0 else 0
        
        self.performance_widget.update_metrics(avg_latency, throughput, total_files)
        
        # Log summary
        self.log_text.append(f"\n<b>===== Scan Complete =====</b>")
        self.log_text.append(f"<b>Files Scanned:</b> {total_files}")
        self.log_text.append(f"<b>Threats Found:</b> {threats_found}")
        self.log_text.append(f"<b>Total Time:</b> {total_time:.2f}s")
        self.log_text.append(f"<b>Average Latency:</b> {avg_latency:.3f}s")
        
        # Display threats
        if threats_found > 0:
            self.log_text.append(f"\n<b style='color: red;'>Threats Detected:</b>")
            for result in results:
                if result['is_threat']:
                    self.log_text.append(
                        f"<span style='color: red;'>🔴 THREAT:</span> {result['file_name']} "
                        f"(Score: {result['final_score']:.2%})"
                    )
            
            # Show alert dialog
            self.show_threat_alert(threats_found, results)
        else:
            self.log_text.append(f"\n<span style='color: green;'>✅ No threats detected</span>")
    
    def show_threat_alert(self, threat_count, results):
        """Show alert for detected threats."""
        msg = QMessageBox(self)
        msg.setIcon(QMessageBox.Warning)
        msg.setWindowTitle("Threats Detected")
        msg.setText(f"<b>Found {threat_count} potential threat(s)!</b>")
        
        threat_details = []
        for r in results:
            if r['is_threat']:
                threat_details.append(f"• {r['file_name']} (Confidence: {r['final_score']:.1%})")
        
        msg.setInformativeText("\n".join(threat_details[:10]))  # Show up to 10
        msg.setDetailedText("Would you like to quarantine these threats?")
        
        quarantine_btn = msg.addButton("Quarantine All", QMessageBox.AcceptRole)
        msg.addButton("Review Manually", QMessageBox.RejectRole)
        
        msg.exec_()
        
        if msg.clickedButton() == quarantine_btn:
            self.quarantine_threats(results)
    
    def quarantine_threats(self, results):
        """Quarantine all detected threats."""
        threats = [r for r in results if r['is_threat']]
        
        for threat in threats:
            success, message = execute_privileged_action(
                'quarantine',
                threat['file'],
                quarantine_dir=str(self.quarantine_dir),
                metadata=threat
            )
            
            if success:
                self.log_text.append(f"<span style='color: green;'>✅ Quarantined:</span> {threat['file_name']}")
            else:
                self.log_text.append(f"<span style='color: red;'>❌ Quarantine failed:</span> {threat['file_name']} - {message}")
        
        self.refresh_quarantine()
    
    def refresh_quarantine(self):
        """Refresh quarantine table."""
        # TODO: Implement quarantine listing
        pass
    
    def restore_selected(self):
        """Restore selected quarantined file."""
        # TODO: Implement restore
        pass
    
    def delete_selected(self):
        """Delete selected quarantined file."""
        # TODO: Implement delete
        pass
    
    def closeEvent(self, event):
        """Clean up when closing."""
        if self.layer3:
            self.layer3.close()
        event.accept()


def main():
    """Main application entry point."""
    app = QApplication(sys.argv)
    
    # Set application style
    app.setStyle('Fusion')
    
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
